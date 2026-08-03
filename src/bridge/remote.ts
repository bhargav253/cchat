import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { WebSocket } from "ws";
import { generatePairingToken, verifyPairingRequest, type KeyPair, type PairingRequest } from "../security/e2ee.ts";

export type RemoteConfig = {
  relayOrigin: string;
  installationId: string;
  bridgeDeviceId: string;
  bridgeIdentity: KeyPair;
  bridgeAccessToken: string;
};

type PendingInvitation = { token: string; expiresAt: number };

export class RemoteBridge {
  readonly config: RemoteConfig;
  private socket: WebSocket | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private stopped = false;
  private pending = new Map<string, PendingInvitation>();

  constructor(config: RemoteConfig) {
    this.config = config;
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.socket?.close();
  }

  async createInvitation(): Promise<{ pairingUrl: string; expiresAt: number }> {
    const invitationId = `invite_${randomUUID().replaceAll("-", "")}`;
    const token = await generatePairingToken();
    const expiresAt = Date.now() + 5 * 60_000;
    const response = await fetch(`${this.config.relayOrigin}/api/v1/pairing/invitations`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.config.bridgeAccessToken}` },
      body: JSON.stringify({
        invitationId,
        installationId: this.config.installationId,
        bridgeDeviceId: this.config.bridgeDeviceId,
        tokenHash: createHash("sha256").update(token).digest("hex"),
      }),
    });
    if (!response.ok) throw new Error(await responseError(response));
    this.pending.set(invitationId, { token, expiresAt });
    this.purgePending();
    const fragment = new URLSearchParams({ invitation: invitationId, secret: token });
    return { pairingUrl: `${this.config.relayOrigin}/pair.html#${fragment}`, expiresAt };
  }

  private connect(): void {
    if (this.stopped) return;
    const url = new URL("/api/v1/connect", this.config.relayOrigin);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(url, { origin: this.config.relayOrigin, maxPayload: 64 * 1024 });
    this.socket = socket;
    socket.on("open", () => socket.send(JSON.stringify({
      type: "bridge.authenticate",
      installationId: this.config.installationId,
      bridgeDeviceId: this.config.bridgeDeviceId,
      accessToken: this.config.bridgeAccessToken,
    })));
    socket.on("message", (raw) => void this.receive(raw.toString()));
    socket.on("error", (error) => console.error(`[remote] ${error.message}`));
    socket.on("close", () => {
      if (this.socket === socket) this.socket = null;
      if (!this.stopped) this.reconnectTimer = setTimeout(() => this.connect(), 3_000);
    });
  }

  private async receive(raw: string): Promise<void> {
    let message: Record<string, unknown>;
    try { message = JSON.parse(raw) as Record<string, unknown>; }
    catch { return; }
    if (message.type === "bridge.authenticated") {
      console.log(`[remote] connected to ${this.config.relayOrigin}`);
      return;
    }
    if (message.type !== "pairing.request" || !this.socket) return;
    const connectionId = String(message.connectionId ?? "");
    const invitationId = String(message.invitationId ?? "");
    const pending = this.pending.get(invitationId);
    const request = message.request as PairingRequest | undefined;
    try {
      if (!pending || pending.expiresAt < Date.now() || !request) throw new Error("Invitation is unavailable or expired");
      if (request.installationId !== this.config.installationId ||
          request.bridgeIdentityPublicKey !== this.config.bridgeIdentity.publicKey ||
          !await verifyPairingRequest(request, pending.token)) throw new Error("Pairing proof is invalid");
      this.pending.delete(invitationId);
      this.socket.send(JSON.stringify({
        type: "pairing.approve",
        connectionId,
        invitationId,
        phoneDeviceId: request.phoneDeviceId,
        phoneIdentityPublicKey: request.phoneIdentityPublicKey,
        name: String(message.name ?? "Phone"),
      }));
    } catch (error) {
      this.socket.send(JSON.stringify({ type: "pairing.reject", connectionId, error: error instanceof Error ? error.message : String(error) }));
    }
  }

  private purgePending(): void {
    const now = Date.now();
    for (const [id, invitation] of this.pending) if (invitation.expiresAt < now) this.pending.delete(id);
  }
}

export async function loadRemoteConfig(): Promise<RemoteConfig | null> {
  const path = process.env.CCHAT_REMOTE_CONFIG ?? join(homedir(), ".config", "cchat", "remote.json");
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as RemoteConfig;
    if (!parsed.relayOrigin.startsWith("https://")) throw new Error("relayOrigin must use HTTPS");
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

async function responseError(response: Response): Promise<string> {
  try { return String((await response.json() as { error?: unknown }).error ?? `Relay returned ${response.status}`); }
  catch { return `Relay returned ${response.status}`; }
}
