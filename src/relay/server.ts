import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer, type ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { RelayDatabase } from "./database.ts";

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
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" }).end();
    return;
  }
  serveStatic(request.url ?? "/", response, request.method === "HEAD");
});

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
