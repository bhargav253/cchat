import { createServer } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { createHash, randomUUID } from "node:crypto";
import { WebSocket, WebSocketServer } from "ws";
import { loadRemoteConfig, RemoteBridge } from "./bridge/remote.ts";
import { BridgeWebAuthn } from "./bridge/webauthn.ts";

type JsonObject = Record<string, unknown>;
type Pending = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

const PORT = Number(process.env.CCHAT_PORT ?? 4317);
const HOST = process.env.CCHAT_HOST ?? "127.0.0.1";
const DEFAULT_CWD = process.env.CCHAT_DEFAULT_CWD ?? process.cwd();
const CODEX_MODE = process.env.CCHAT_CODEX_MODE ?? "shared";
const CODEX_URL = process.env.CCHAT_CODEX_URL ?? "ws://127.0.0.1:4500";
const CODEX_BIN = process.env.CCHAT_CODEX_BIN ?? "codex";
const publicDir = fileURLToPath(new URL("../public", import.meta.url));
const remoteConfig = await loadRemoteConfig();

class CodexAppServer {
  private child: ChildProcessWithoutNullStreams | null = null;
  private host: ChildProcessWithoutNullStreams | null = null;
  private hostSocket: WebSocket | null = null;
  private ownsHost = false;
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private approvalRequests = new Map<string, { rpcId: number; method: string; actionDigest: string }>();
  private listeners = new Set<(message: JsonObject) => void>();
  private readyPromise: Promise<void> | null = null;

  start(): Promise<void> {
    if (this.readyPromise) return this.readyPromise;
    this.readyPromise = this.launch();
    return this.readyPromise;
  }

  private async launch(): Promise<void> {
    if (CODEX_MODE === "shared") {
      if (!await websocketAvailable(CODEX_URL)) {
        this.ownsHost = true;
        this.host = spawn(CODEX_BIN, ["app-server", "--listen", CODEX_URL], {
          cwd: DEFAULT_CWD,
          env: process.env,
          stdio: ["pipe", "pipe", "pipe"],
        });
        this.host.stderr.on("data", (chunk: Buffer) => {
          const text = chunk.toString().trim();
          if (text) console.error(`[codex-host] ${text}`);
        });
        this.host.on("exit", (code, signal) => {
          this.emit({ type: "bridge.status", connected: false, error: `Shared Codex host exited (${code ?? signal ?? "unknown"})` });
        });
      }
      this.hostSocket = await connectWebSocket(CODEX_URL, this.host);
      this.hostSocket.on("message", (data) => this.receive(data.toString()));
      this.hostSocket.on("close", () => this.emit({ type: "bridge.status", connected: false, error: "Codex connection closed" }));
    }

    if (CODEX_MODE !== "shared") {
      this.child = spawn(CODEX_BIN, ["app-server", "--stdio"], {
        cwd: DEFAULT_CWD,
        env: process.env,
        stdio: ["pipe", "pipe", "pipe"],
      });

      this.child.on("exit", (code, signal) => {
        const error = new Error(`Codex App Server exited (${code ?? signal ?? "unknown"})`);
        for (const request of this.pending.values()) request.reject(error);
        this.pending.clear();
        this.emit({ type: "bridge.status", connected: false, error: error.message });
        this.child = null;
        this.readyPromise = null;
      });

      this.child.on("error", (error) => {
        this.emit({ type: "bridge.status", connected: false, error: error.message });
      });

      this.child.stderr.on("data", (chunk: Buffer) => {
        const text = chunk.toString().trim();
        if (text) console.error(`[codex] ${text}`);
      });

      const lines = createInterface({ input: this.child.stdout });
      lines.on("line", (line) => this.receive(line));
    }

    await this.request("initialize", {
      clientInfo: { name: "cchat", title: "cchat local bridge", version: "0.1.0" },
      capabilities: { experimentalApi: true },
    });
    this.notify("initialized", {});
    this.emit({ type: "bridge.status", connected: true });
  }

  onMessage(listener: (message: JsonObject) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  async listThreads(): Promise<unknown> {
    return this.request("thread/list", {
      limit: 100,
      sortKey: "recency_at",
      sortDirection: "desc",
      archived: false,
    });
  }

  async openThread(threadId: string): Promise<unknown> {
    // Resume both loads the model context and subscribes this connection to live events.
    return this.request("thread/resume", { threadId });
  }

  async createThread(cwd?: string): Promise<unknown> {
    return this.request("thread/start", {
      cwd: cwd || DEFAULT_CWD,
      approvalPolicy: "on-request",
      sandbox: "workspace-write",
      serviceName: "cchat",
    });
  }

  async startTurn(threadId: string, text: string): Promise<unknown> {
    return this.request("turn/start", {
      threadId,
      clientUserMessageId: randomUUID(),
      input: [{ type: "text", text, text_elements: [] }],
    });
  }

  async steerTurn(threadId: string, turnId: string, text: string): Promise<unknown> {
    return this.request("turn/steer", {
      threadId,
      expectedTurnId: turnId,
      clientUserMessageId: randomUUID(),
      input: [{ type: "text", text, text_elements: [] }],
    });
  }

  async interruptTurn(threadId: string, turnId: string): Promise<unknown> {
    return this.request("turn/interrupt", { threadId, turnId });
  }

  resolveApproval(requestId: string, decision: "accept" | "decline" | "cancel", expectedDigest?: string): void {
    const approval = this.approvalRequests.get(requestId);
    if (!approval) throw new Error("Approval is no longer pending");
    if (!approval.method.includes("requestApproval")) throw new Error("Unsupported approval type");
    if (expectedDigest !== undefined && expectedDigest !== approval.actionDigest) throw new Error("Approval digest mismatch");
    this.write({ id: approval.rpcId, result: { decision } });
    this.approvalRequests.delete(requestId);
    this.emit({ type: "approval.resolved", requestId, decision });
  }

  stop(): void {
    this.hostSocket?.close();
    this.child?.kill("SIGTERM");
    if (this.ownsHost) this.host?.kill("SIGTERM");
  }

  private request(method: string, params: JsonObject): Promise<unknown> {
    if (!this.child && this.hostSocket?.readyState !== WebSocket.OPEN) return Promise.reject(new Error("Codex App Server is not running"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.write({ method, id, params });
    });
  }

  private notify(method: string, params: JsonObject): void {
    this.write({ method, params });
  }

  private write(message: JsonObject): void {
    if (this.hostSocket?.readyState === WebSocket.OPEN) {
      this.hostSocket.send(JSON.stringify(message));
      return;
    }
    if (!this.child?.stdin.writable) throw new Error("Codex App Server transport is unavailable");
    this.child.stdin.write(`${JSON.stringify(message)}\n`);
  }

  private receive(line: string): void {
    let message: JsonObject;
    try {
      message = JSON.parse(line) as JsonObject;
    } catch {
      console.error("Ignored non-JSON app-server output");
      return;
    }

    if (typeof message.id === "number" && ("result" in message || "error" in message)) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(formatRpcError(message.error)));
      else pending.resolve(message.result);
      return;
    }

    if (typeof message.id === "number" && typeof message.method === "string") {
      const requestId = randomUUID();
      if (message.method === "item/commandExecution/requestApproval" ||
          message.method === "item/fileChange/requestApproval") {
        const actionDigest = createHash("sha256").update(JSON.stringify({ method: message.method, requestId, params: message.params })).digest("base64url");
        this.approvalRequests.set(requestId, { rpcId: message.id, method: message.method, actionDigest });
        this.emit({
          type: "approval.requested",
          requestId,
          approvalType: message.method,
          actionDigest,
          params: message.params,
        });
      } else {
        // Fail closed for protocol features the prototype does not deliberately expose.
        this.write({ id: message.id, error: { code: -32601, message: "Unsupported by cchat prototype" } });
        this.emit({ type: "bridge.warning", message: `Unsupported Codex request: ${message.method}` });
      }
      return;
    }

    if (typeof message.method === "string") {
      this.emit({ type: "codex.event", method: message.method, params: message.params });
    }
  }

  private emit(message: JsonObject): void {
    for (const listener of this.listeners) listener(message);
  }
}

function formatRpcError(error: unknown): string {
  if (typeof error === "object" && error && "message" in error) return String(error.message);
  return JSON.stringify(error);
}

const codex = new CodexAppServer();
const bridgeWebAuthn = remoteConfig ? await BridgeWebAuthn.load(remoteConfig.relayOrigin) : null;
const remoteBridge = remoteConfig ? new RemoteBridge(remoteConfig, {
  onEncryptedRequest: (request) => handleCodexAction(request, "remote"),
  webauthn: bridgeWebAuthn!,
}) : null;
const sockets = new Set<WebSocket>();

function send(socket: WebSocket, message: JsonObject): void {
  if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
}

function broadcast(message: JsonObject): void {
  for (const socket of sockets) send(socket, message);
}

codex.onMessage((message) => {
  broadcast(message);
  remoteBridge?.broadcastEncrypted(message);
});

const mimeTypes: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

const server = createServer((request, response) => {
  if (request.method === "GET" && request.url === "/admin/devices") {
    if (request.headers["x-cchat-cli"] !== "1" || request.headers.origin || !remoteBridge) {
      response.writeHead(403).end(); return;
    }
    response.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" }).end(JSON.stringify(remoteBridge.listTrustedPhones()));
    return;
  }
  if (request.method === "POST" && request.url === "/admin/revoke") {
    if (request.headers["x-cchat-cli"] !== "1" || request.headers.origin || !remoteBridge) {
      response.writeHead(403).end(); return;
    }
    void readLocalJson(request).then(async (body) => {
      await remoteBridge.revokePhone(requiredString(body, "phoneDeviceId"));
      response.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" }).end('{"revoked":true}');
    }).catch((error) => response.writeHead(400, { "Content-Type": "application/json" }).end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) })));
    return;
  }
  if (request.method === "POST" && request.url === "/admin/pair") {
    if (request.headers["x-cchat-cli"] !== "1" || request.headers.origin) {
      response.writeHead(403, { "Content-Type": "application/json", "Cache-Control": "no-store" }).end(JSON.stringify({ error: "CLI access required" }));
      return;
    }
    if (!remoteBridge) {
      response.writeHead(409, { "Content-Type": "application/json", "Cache-Control": "no-store" }).end(JSON.stringify({ error: "Bridge has not claimed a relay" }));
      return;
    }
    void remoteBridge.createInvitation().then((result) => {
      response.writeHead(201, { "Content-Type": "application/json", "Cache-Control": "no-store" }).end(JSON.stringify(result));
    }).catch((error) => {
      response.writeHead(502, { "Content-Type": "application/json", "Cache-Control": "no-store" }).end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
    });
    return;
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD, POST" }).end();
    return;
  }
  const requested = request.url === "/" ? "/index.html" : (request.url ?? "/index.html").split("?")[0]!;
  const safePath = normalize(requested).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(publicDir, safePath);
  if (!filePath.startsWith(publicDir) || !existsSync(filePath) || !statSync(filePath).isFile()) {
    response.writeHead(404).end("Not found");
    return;
  }
  response.writeHead(200, {
    "Content-Type": mimeTypes[extname(filePath)] ?? "application/octet-stream",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; connect-src 'self' ws://127.0.0.1:* ws://localhost:*; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });
  createReadStream(filePath).pipe(response);
});

async function readLocalJson(request: import("node:http").IncomingMessage): Promise<JsonObject> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 4096) throw new Error("Request too large");
    chunks.push(chunk);
  }
  const value = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("JSON object required");
  return value as JsonObject;
}

server.on("error", (error: NodeJS.ErrnoException) => {
  if (error.code === "EADDRINUSE") {
    console.error(`cchat is already running, or ${HOST}:${PORT} is used by another process.`);
  } else {
    console.error(`cchat HTTP server error: ${error.message}`);
  }
  codex.stop();
  process.exitCode = 1;
});

const websocketServer = new WebSocketServer({ server, path: "/bridge" });
websocketServer.on("connection", (socket, request) => {
  const origin = request.headers.origin;
  const allowedOrigins = new Set([`http://${HOST}:${PORT}`, `http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`]);
  if (origin && !allowedOrigins.has(origin)) {
    socket.close(1008, "Origin not allowed");
    return;
  }
  sockets.add(socket);
  send(socket, { type: "bridge.status", connected: true, defaultCwd: DEFAULT_CWD });
  socket.on("close", () => sockets.delete(socket));
  socket.on("message", async (raw) => {
    let request: JsonObject = {};
    try {
      request = JSON.parse(raw.toString()) as JsonObject;
      const requestId = String(request.requestId ?? "");
      const result = await handleCodexAction(request, "local");
      send(socket, { type: "response", requestId, result });
    } catch (error) {
      send(socket, { type: "response", requestId: String(request?.requestId ?? ""), error: error instanceof Error ? error.message : String(error) });
    }
  });
});

async function handleCodexAction(request: JsonObject, source: "local" | "remote"): Promise<unknown> {
  switch (request.type) {
    case "threads.list": return codex.listThreads();
    case "thread.open": return codex.openThread(requiredString(request, "threadId"));
    case "thread.create": return codex.createThread(optionalString(request, "cwd"));
    case "turn.start": return codex.startTurn(requiredString(request, "threadId"), requiredString(request, "text"));
    case "turn.steer": return codex.steerTurn(requiredString(request, "threadId"), requiredString(request, "turnId"), requiredString(request, "text"));
    case "turn.interrupt": return codex.interruptTurn(requiredString(request, "threadId"), requiredString(request, "turnId"));
    case "approval.resolve":
      codex.resolveApproval(
        requiredString(request, "approvalId"),
        approvalDecision(request.decision),
        source === "remote" ? requiredString(request, "actionDigest") : undefined,
      );
      return {};
    default: throw new Error("Unsupported bridge request");
  }
}

function requiredString(object: JsonObject, key: string): string {
  const value = object[key];
  if (typeof value !== "string" || !value.trim()) throw new Error(`${key} is required`);
  return value;
}

function optionalString(object: JsonObject, key: string): string | undefined {
  const value = object[key];
  return typeof value === "string" && value.trim() ? value : undefined;
}

function approvalDecision(value: unknown): "accept" | "decline" | "cancel" {
  if (value === "accept" || value === "decline" || value === "cancel") return value;
  throw new Error("Invalid approval decision");
}

await codex.start();
remoteBridge?.start();
server.listen(PORT, HOST, () => {
  console.log(`cchat local prototype: http://${HOST}:${PORT}`);
  console.log(`Codex working directory: ${DEFAULT_CWD}`);
  console.log(`Codex connection: ${CODEX_MODE === "shared" ? `shared localhost server (${CODEX_URL})` : "private stdio process"}`);
  if (CODEX_MODE === "shared") console.log(`CLI command: codex --remote ${CODEX_URL}`);
  console.log(`Remote relay: ${remoteConfig ? remoteConfig.relayOrigin : "not claimed"}`);
});

function shutdown(): void {
  remoteBridge?.stop();
  codex.stop();
  for (const socket of sockets) socket.terminate();
  websocketServer.close();
  server.closeAllConnections();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 1_000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function websocketAvailable(url: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new WebSocket(url);
    const timeout = setTimeout(() => {
      socket.terminate();
      resolve(false);
    }, 300);
    socket.once("open", () => {
      clearTimeout(timeout);
      socket.close();
      resolve(true);
    });
    socket.once("error", () => {
      clearTimeout(timeout);
      resolve(false);
    });
  });
}

function connectWebSocket(url: string, host: ChildProcessWithoutNullStreams | null): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error(`Timed out connecting to ${url}`)), 5_000);
    const connect = () => {
      if (host && host.exitCode !== null) {
        clearTimeout(deadline);
        reject(new Error("Codex App Server exited before accepting connections"));
        return;
      }
      const socket = new WebSocket(url);
      socket.once("open", () => {
        clearTimeout(deadline);
        resolve(socket);
      });
      socket.once("error", () => {
        socket.close();
        setTimeout(connect, 75);
      });
    };
    connect();
  });
}
