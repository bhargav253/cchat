import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { RelayDatabase } from "./database.ts";
import { WebSocket, WebSocketServer } from "ws";

const HOST = process.env.CCHAT_RELAY_HOST ?? "127.0.0.1";
const PORT = Number(process.env.CCHAT_RELAY_PORT ?? 8787);
const PUBLIC_ORIGIN = process.env.CCHAT_PUBLIC_ORIGIN ?? "https://mycchat.win";
const DATABASE_PATH = process.env.CCHAT_RELAY_DB ?? "./data/relay.sqlite";
const publicDir = fileURLToPath(new URL("../../relay-public", import.meta.url));

if (!PUBLIC_ORIGIN.startsWith("https://")) throw new Error("CCHAT_PUBLIC_ORIGIN must use HTTPS");
if (HOST !== "127.0.0.1" && HOST !== "::1") throw new Error("Relay must remain loopback-only behind the TLS reverse proxy");
if (!Number.isInteger(PORT) || PORT < 1024 || PORT > 65535) throw new Error("Invalid relay port");

const database = new RelayDatabase(DATABASE_PATH);
database.purgeExpired();
const cleanup = setInterval(() => database.purgeExpired(), 60 * 60_000);
cleanup.unref();

const mimeTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

const server = createServer((request, response) => {
  response.setHeader("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'");
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");

  if (request.method === "GET" && request.url === "/healthz") {
    response.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }).end("ok\n");
    return;
  }
  if (request.method === "GET" && request.url === "/readyz") {
    response.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }).end("ready\n");
    return;
  }
  if (request.method === "POST" && request.url === "/api/v1/installations/claim") {
    void readJson(request).then((body) => {
      database.claimInstallation({
        rawBootstrapToken: requiredString(body, "bootstrapToken"),
        installationId: requiredString(body, "installationId"),
        bridgeDeviceId: requiredString(body, "bridgeDeviceId"),
        bridgeIdentityPublicKey: requiredString(body, "bridgeIdentityPublicKey"),
        bridgeAccessToken: requiredString(body, "bridgeAccessToken"),
      });
      json(response, 201, { ok: true });
    }).catch((error) => jsonError(response, error));
    return;
  }
  if (request.method === "POST" && request.url === "/api/v1/pairing/invitations") {
    void readJson(request).then((body) => {
      const installationId = requiredString(body, "installationId");
      authenticateBridgeRequest(request.headers.authorization, installationId, requiredString(body, "bridgeDeviceId"));
      database.createPairingInvitation({
        id: requiredString(body, "invitationId"),
        installationId,
        tokenHash: requiredString(body, "tokenHash"),
        expiresAt: Date.now() + 5 * 60_000,
      });
      json(response, 201, { expiresAt: Date.now() + 5 * 60_000 });
    }).catch((error) => jsonError(response, error));
    return;
  }
  const invitationMatch = request.method === "GET" && request.url?.match(/^\/api\/v1\/pairing\/invitations\/([A-Za-z0-9_-]{8,128})$/);
  if (invitationMatch) {
    const invitation = database.getPairingInvitation(invitationMatch[1]!);
    if (!invitation || invitation.usedAt !== null || invitation.expiresAt < Date.now()) {
      json(response, 404, { error: "Invitation is invalid, expired, or already used" });
    } else {
      json(response, 200, invitation);
    }
    return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" }).end();
    return;
  }
  serveStatic(request.url ?? "/", response, request.method === "HEAD");
});

const bridgeSockets = new Map<string, { socket: WebSocket; deviceId: string }>();
const phoneSockets = new Map<string, WebSocket>();
const wsServer = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });

server.on("upgrade", (request, socket, head) => {
  const url = new URL(request.url ?? "/", PUBLIC_ORIGIN);
  if (url.pathname !== "/api/v1/connect" || request.headers.origin !== PUBLIC_ORIGIN) {
    socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }
  wsServer.handleUpgrade(request, socket, head, (websocket) => wsServer.emit("connection", websocket));
});

wsServer.on("connection", (socket) => {
  let bridgeInstallationId: string | null = null;
  const connectionIds = new Set<string>();
  const authTimer = setTimeout(() => socket.close(1008, "Authentication timeout"), 10_000);
  socket.once("message", (raw) => {
    let first: Record<string, unknown>;
    try { first = JSON.parse(raw.toString()) as Record<string, unknown>; }
    catch { socket.close(1008, "Invalid message"); return; }
    if (first.type === "bridge.authenticate") {
      const installationId = requiredString(first, "installationId");
      const deviceId = requiredString(first, "bridgeDeviceId");
      const accessToken = requiredString(first, "accessToken");
      if (!database.authenticateBridge(installationId, deviceId, accessToken)) {
        socket.close(1008, "Authentication failed"); return;
      }
      clearTimeout(authTimer);
      bridgeInstallationId = installationId;
      bridgeSockets.get(installationId)?.socket.close(1012, "Bridge reconnected");
      bridgeSockets.set(installationId, { socket, deviceId });
      database.touchDevice(deviceId);
      send(socket, { type: "bridge.authenticated" });
      socket.on("message", (message) => handleBridgeMessage(installationId, deviceId, message.toString()));
      return;
    }
    if (first.type === "phone.pair") {
      const invitationId = requiredString(first, "invitationId");
      const invitation = database.getPairingInvitation(invitationId);
      const request = objectValue(first, "request");
      if (!invitation || invitation.usedAt !== null || invitation.expiresAt < Date.now() ||
          request.installationId !== invitation.installationId ||
          request.bridgeIdentityPublicKey !== invitation.bridgeIdentityPublicKey) {
        socket.close(1008, "Invalid invitation"); return;
      }
      const bridge = bridgeSockets.get(invitation.installationId);
      if (!bridge || bridge.socket.readyState !== WebSocket.OPEN) {
        socket.close(1013, "Bridge is offline"); return;
      }
      clearTimeout(authTimer);
      const connectionId = randomUUID();
      connectionIds.add(connectionId);
      phoneSockets.set(connectionId, socket);
      send(bridge.socket, { type: "pairing.request", connectionId, invitationId, name: requiredString(first, "name"), request });
      return;
    }
    socket.close(1008, "Authentication required");
  });
  socket.on("close", () => {
    clearTimeout(authTimer);
    if (bridgeInstallationId && bridgeSockets.get(bridgeInstallationId)?.socket === socket) bridgeSockets.delete(bridgeInstallationId);
    for (const id of connectionIds) phoneSockets.delete(id);
  });
});

function handleBridgeMessage(installationId: string, bridgeDeviceId: string, raw: string): void {
  try {
    const message = JSON.parse(raw) as Record<string, unknown>;
    if (message.type !== "pairing.approve" && message.type !== "pairing.reject") return;
    const connectionId = requiredString(message, "connectionId");
    const phone = phoneSockets.get(connectionId);
    if (!phone) return;
    phoneSockets.delete(connectionId);
    if (message.type === "pairing.reject") {
      send(phone, { type: "pairing.rejected", error: String(message.error ?? "Pairing rejected") });
      phone.close(1008, "Pairing rejected");
      return;
    }
    database.completePairing({
      invitationId: requiredString(message, "invitationId"),
      installationId,
      phoneDeviceId: requiredString(message, "phoneDeviceId"),
      phoneName: requiredString(message, "name"),
      phoneIdentityPublicKey: requiredString(message, "phoneIdentityPublicKey"),
    });
    database.touchDevice(bridgeDeviceId);
    send(phone, {
      type: "pairing.complete",
      installationId,
      bridgeDeviceId,
      phoneDeviceId: message.phoneDeviceId,
    });
    phone.close(1000, "Pairing complete");
  } catch (error) {
    console.error(`Rejected bridge pairing response: ${error instanceof Error ? error.message : String(error)}`);
  }
}

server.on("clientError", (_error, socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"));
server.listen(PORT, HOST, () => {
  console.log(`cchat relay staging server: http://${HOST}:${PORT}`);
  console.log(`public origin: ${PUBLIC_ORIGIN}`);
  console.log("status: locked; pairing and encrypted routing are not enabled");
});

function serveStatic(url: string, response: ServerResponse, headOnly: boolean): void {
  const pathname = new URL(url, PUBLIC_ORIGIN).pathname;
  const requested = pathname === "/" ? "/index.html" : pathname;
  const safePath = normalize(requested).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(publicDir, safePath);
  if (!filePath.startsWith(publicDir) || !existsSync(filePath) || !statSync(filePath).isFile()) {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }).end("Not found\n");
    return;
  }
  response.writeHead(200, {
    "Content-Type": mimeTypes[extname(filePath)] ?? "application/octet-stream",
    "Cache-Control": "public, max-age=300",
  });
  if (headOnly) response.end();
  else createReadStream(filePath).pipe(response);
}

function shutdown(): void {
  clearInterval(cleanup);
  server.closeAllConnections();
  server.close(() => {
    database.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 1_000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function authenticateBridgeRequest(authorization: string | undefined, installationId: string, bridgeDeviceId: string): void {
  const match = authorization?.match(/^Bearer ([A-Za-z0-9_-]{32,1024})$/);
  if (!match || !database.authenticateBridge(installationId, bridgeDeviceId, match[1]!)) throw new Error("Bridge authentication failed");
}

async function readJson(request: import("node:http").IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 16 * 1024) throw new Error("Request body is too large");
    chunks.push(chunk);
  }
  const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("JSON object required");
  return parsed as Record<string, unknown>;
}

function requiredString(value: Record<string, unknown>, key: string): string {
  const item = value[key];
  if (typeof item !== "string" || !item.trim()) throw new Error(`${key} is required`);
  return item;
}

function objectValue(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const item = value[key];
  if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(`${key} must be an object`);
  return item as Record<string, unknown>;
}

function send(socket: WebSocket, value: Record<string, unknown>): void {
  if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(value));
}

function json(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }).end(JSON.stringify(value));
}

function jsonError(response: ServerResponse, error: unknown): void {
  const message = error instanceof Error ? error.message : "Request failed";
  json(response, /bootstrap|authentication/i.test(message) ? 401 : 400, { error: message });
}
