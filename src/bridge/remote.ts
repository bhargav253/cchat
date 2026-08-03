import { createHash, randomUUID } from "node:crypto";
import { chmod, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { WebSocket } from "ws";
import {
  acceptPhoneHello,
  generatePairingToken,
  verifyPairingRequest,
  verifyPhoneConfirmation,
  type BridgeHello,
  type EncryptedChannel,
  type EncryptedEnvelope,
  type HandshakeConfirmation,
  type KeyPair,
  type PairingRequest,
  type PhoneHello,
} from "../security/e2ee.ts";
import { BridgeWebAuthn } from "./webauthn.ts";
import { BalancedAuthorization } from "./policy.ts";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";

export type RemoteConfig = {
  relayOrigin: string;
  installationId: string;
  bridgeDeviceId: string;
  bridgeIdentity: KeyPair;
  bridgeAccessToken: string;
  trustedPhones?: Record<string, { name: string; identityPublicKey: string }>;
};

type PendingInvitation = { token: string; expiresAt: number };

export class RemoteBridge {
  readonly config: RemoteConfig;
  private socket: WebSocket | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private stopped = false;
  private pending = new Map<string, PendingInvitation>();
  private handshakes = new Map<string, { state: Awaited<ReturnType<typeof acceptPhoneHello>>["state"]; channel: EncryptedChannel; phoneDeviceId: string }>();
  private channels = new Map<string, { channel: EncryptedChannel; phoneDeviceId: string; authorization: BalancedAuthorization }>();
  private readonly configPath: string;
  private readonly onEncryptedRequest: (request: Record<string, unknown>, phoneDeviceId: string) => Promise<unknown>;
  private readonly webauthn: BridgeWebAuthn;

  constructor(config: RemoteConfig, options?: {
    configPath?: string;
    onEncryptedRequest?: (request: Record<string, unknown>, phoneDeviceId: string) => Promise<unknown>;
    webauthn: BridgeWebAuthn;
  }) {
    this.config = config;
    this.config.trustedPhones ??= {};
    this.configPath = options?.configPath ?? remoteConfigPath();
    this.onEncryptedRequest = options?.onEncryptedRequest ?? (async () => { throw new Error("Remote Codex routing is not enabled"); });
    if (!options?.webauthn) throw new Error("Bridge WebAuthn service is required");
    this.webauthn = options.webauthn;
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

  broadcastEncrypted(message: Record<string, unknown>): void {
    for (const [connectionId, active] of this.channels) {
      if (!active.authorization.isUnlocked()) continue;
      this.sendRoute(connectionId, { kind: "envelope", envelope: active.channel.encrypt("event", message) });
    }
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

  listTrustedPhones(): Array<{ id: string; name: string }> {
    return Object.entries(this.config.trustedPhones ?? {}).map(([id, phone]) => ({ id, name: phone.name }));
  }

  async revokePhone(phoneDeviceId: string): Promise<void> {
    if (!this.config.trustedPhones?.[phoneDeviceId]) throw new Error("Unknown trusted phone");
    const response = await fetch(`${this.config.relayOrigin}/api/v1/devices/revoke`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${this.config.bridgeAccessToken}` },
      body: JSON.stringify({
        installationId: this.config.installationId,
        bridgeDeviceId: this.config.bridgeDeviceId,
        phoneDeviceId,
      }),
    });
    if (!response.ok) throw new Error(await responseError(response));
    delete this.config.trustedPhones[phoneDeviceId];
    await this.webauthn.revoke(phoneDeviceId);
    await this.persistConfig();
    for (const [connectionId, channel] of this.channels) {
      if (channel.phoneDeviceId === phoneDeviceId) {
        this.sendRoute(connectionId, { kind: "error", error: "Device revoked" });
        this.channels.delete(connectionId);
      }
    }
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
    if (message.type === "phone.connected") {
      await this.acceptEncryptedPhone(message);
      return;
    }
    if (message.type === "phone.frame") {
      await this.receivePhoneFrame(message);
      return;
    }
    if (message.type === "phone.disconnected") {
      const connectionId = String(message.connectionId ?? "");
      this.handshakes.delete(connectionId);
      this.channels.delete(connectionId);
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
      this.config.trustedPhones![request.phoneDeviceId] = {
        name: String(message.name ?? "Phone"),
        identityPublicKey: request.phoneIdentityPublicKey,
      };
      await this.persistConfig();
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

  private async acceptEncryptedPhone(message: Record<string, unknown>): Promise<void> {
    if (!this.socket) return;
    const connectionId = String(message.connectionId ?? "");
    const phoneDeviceId = String(message.phoneDeviceId ?? "");
    const phone = this.config.trustedPhones?.[phoneDeviceId];
    try {
      if (!phone) throw new Error("Phone is not trusted by this bridge");
      const frame = message.frame as { kind?: unknown; hello?: PhoneHello } | undefined;
      if (frame?.kind !== "hello" || !frame.hello) throw new Error("Expected phone handshake hello");
      const accepted = await acceptPhoneHello({
        hello: frame.hello,
        bridgeIdentity: this.config.bridgeIdentity,
        expectedInstallationId: this.config.installationId,
        expectedBridgeDeviceId: this.config.bridgeDeviceId,
        registeredPhoneIdentityPublicKey: phone.identityPublicKey,
      });
      this.handshakes.set(connectionId, { state: accepted.state, channel: accepted.channel, phoneDeviceId });
      this.sendRoute(connectionId, { kind: "hello", reply: accepted.reply satisfies BridgeHello });
    } catch (error) {
      this.sendRoute(connectionId, { kind: "error", error: error instanceof Error ? error.message : String(error) });
    }
  }

  private async receivePhoneFrame(message: Record<string, unknown>): Promise<void> {
    const connectionId = String(message.connectionId ?? "");
    const frame = message.frame as Record<string, unknown> | undefined;
    if (!frame) return;
    const handshake = this.handshakes.get(connectionId);
    if (handshake && frame.kind === "confirm") {
      if (!await verifyPhoneConfirmation(handshake.state, frame.confirmation as HandshakeConfirmation)) {
        this.sendRoute(connectionId, { kind: "error", error: "Handshake confirmation failed" });
        return;
      }
      this.handshakes.delete(connectionId);
      this.channels.set(connectionId, { channel: handshake.channel, phoneDeviceId: handshake.phoneDeviceId, authorization: new BalancedAuthorization() });
      this.sendRoute(connectionId, { kind: "ready", channelId: handshake.channel.channelId });
      return;
    }
    const active = this.channels.get(connectionId);
    if (!active || frame.kind !== "envelope") return;
    try {
      const payload = active.channel.decrypt(frame.envelope as EncryptedEnvelope) as Record<string, unknown>;
      const result = await this.handleEncryptedRequest(payload, active);
      this.sendRoute(connectionId, { kind: "envelope", envelope: active.channel.encrypt("response", { requestId: payload.requestId, result }) });
    } catch (error) {
      this.sendRoute(connectionId, { kind: "envelope", envelope: active.channel.encrypt("response", { error: error instanceof Error ? error.message : String(error) }) });
    }
  }

  private async handleEncryptedRequest(
    payload: Record<string, unknown>,
    active: { channel: EncryptedChannel; phoneDeviceId: string; authorization: BalancedAuthorization },
  ): Promise<unknown> {
    const phone = this.config.trustedPhones?.[active.phoneDeviceId];
    if (!phone) throw new Error("Phone is no longer trusted");
    switch (payload.type) {
      case "auth.status": return { registered: this.webauthn.hasCredential(active.phoneDeviceId), authenticatedUntil: active.authorization.status() };
      case "auth.register.options": return this.webauthn.registrationOptions(active.phoneDeviceId, phone.name);
      case "auth.register.verify":
        await this.webauthn.verifyRegistration(active.phoneDeviceId, payload.response as RegistrationResponseJSON);
        return { registered: true, authenticatedUntil: active.authorization.unlock() };
      case "auth.authenticate.options": return this.webauthn.authenticationOptions(active.phoneDeviceId, "session");
      case "auth.authenticate.verify":
        await this.webauthn.verifyAuthentication(active.phoneDeviceId, payload.response as AuthenticationResponseJSON);
        return { authenticatedUntil: active.authorization.unlock() };
      case "auth.approval.options":
        active.authorization.requireSession();
        return this.webauthn.authenticationOptions(active.phoneDeviceId, "approval", requiredString(payload, "actionDigest"));
      case "auth.approval.verify": {
        const verified = await this.webauthn.verifyAuthentication(active.phoneDeviceId, payload.response as AuthenticationResponseJSON);
        if (verified.purpose !== "approval" || !verified.actionDigest) throw new Error("Approval authentication binding failed");
        return { actionDigest: verified.actionDigest, expiresAt: active.authorization.authorizeApproval(verified.actionDigest) };
      }
      default:
        active.authorization.requireSession();
        if (payload.type === "approval.resolve") {
          const digest = requiredString(payload, "actionDigest");
          active.authorization.consumeApproval(digest);
        }
        return this.onEncryptedRequest(payload, active.phoneDeviceId);
    }
  }

  private sendRoute(connectionId: string, frame: Record<string, unknown>): void {
    if (this.socket?.readyState === WebSocket.OPEN) this.socket.send(JSON.stringify({ type: "phone.frame", connectionId, frame }));
  }

  private async persistConfig(): Promise<void> {
    const temporary = `${this.configPath}.tmp`;
    await writeFile(temporary, `${JSON.stringify(this.config, null, 2)}\n`, { mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, this.configPath);
  }

  private purgePending(): void {
    const now = Date.now();
    for (const [id, invitation] of this.pending) if (invitation.expiresAt < now) this.pending.delete(id);
  }
}

function requiredString(value: Record<string, unknown>, key: string): string {
  const item = value[key];
  if (typeof item !== "string" || !item.trim()) throw new Error(`${key} is required`);
  return item;
}

export async function loadRemoteConfig(): Promise<RemoteConfig | null> {
  const path = remoteConfigPath();
  try {
    const parsed = JSON.parse(await readFile(path, "utf8")) as RemoteConfig;
    if (!parsed.relayOrigin.startsWith("https://")) throw new Error("relayOrigin must use HTTPS");
    return parsed;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

function remoteConfigPath(): string {
  return process.env.CCHAT_REMOTE_CONFIG ?? join(homedir(), ".config", "cchat", "remote.json");
}

async function responseError(response: Response): Promise<string> {
  try { return String((await response.json() as { error?: unknown }).error ?? `Relay returned ${response.status}`); }
  catch { return `Relay returned ${response.status}`; }
}
