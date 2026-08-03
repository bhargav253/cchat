import {
  createPhoneHelloWithSigner,
  finishPhoneHandshake,
  type BridgeHello,
  type EncryptedChannel,
  type EncryptedEnvelope,
  type PhoneHandshakeState,
} from "../security/e2ee.ts";

export type StoredDevice = {
  version: 1;
  installationId: string;
  bridgeDeviceId: string;
  bridgeIdentityPublicKey: string;
  phoneDeviceId: string;
  phoneIdentityPublicKey: string;
  phoneIdentityPrivateKey: CryptoKey;
};

export class EncryptedTransport {
  private socket: WebSocket | null = null;
  private channel: EncryptedChannel | null = null;
  private handshake: PhoneHandshakeState | null = null;
  private pending = new Map<string, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();
  private eventListeners = new Set<(event: Record<string, unknown>) => void>();
  private closeListeners = new Set<() => void>();
  private suppressNextClose = false;

  constructor(private readonly device: StoredDevice) {}

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const protocol = location.protocol === "https:" ? "wss:" : "ws:";
      const socket = new WebSocket(`${protocol}//${location.host}/api/v1/connect`);
      this.socket = socket;
      const timeout = window.setTimeout(() => reject(new Error("Encrypted bridge connection timed out")), 15_000);
      socket.addEventListener("open", async () => {
        try {
          const initiated = await createPhoneHelloWithSigner({
            installationId: this.device.installationId,
            phoneDeviceId: this.device.phoneDeviceId,
            bridgeDeviceId: this.device.bridgeDeviceId,
            phoneIdentityPublicKey: this.device.phoneIdentityPublicKey,
            bridgeIdentityPublicKey: this.device.bridgeIdentityPublicKey,
            sign: async (message) => new Uint8Array(await crypto.subtle.sign("Ed25519", this.device.phoneIdentityPrivateKey, message.buffer as ArrayBuffer)),
          });
          this.handshake = initiated.state;
          socket.send(JSON.stringify({
            type: "phone.connect",
            installationId: this.device.installationId,
            phoneDeviceId: this.device.phoneDeviceId,
            frame: { kind: "hello", hello: initiated.hello },
          }));
        } catch (error) { reject(asError(error)); }
      });
      socket.addEventListener("message", (event) => void this.receive(String(event.data), () => {
        window.clearTimeout(timeout);
        resolve();
      }, reject));
      socket.addEventListener("error", () => reject(new Error("Encrypted relay connection failed")));
      socket.addEventListener("close", () => {
        this.channel = null;
        for (const pending of this.pending.values()) pending.reject(new Error("Encrypted connection closed"));
        this.pending.clear();
        if (this.suppressNextClose) this.suppressNextClose = false;
        else for (const listener of this.closeListeners) listener();
      });
    });
  }

  close(): void {
    this.suppressNextClose = true;
    this.socket?.close(1000, "Locked");
    this.socket = null;
    this.channel = null;
  }

  request(type: string, body: Record<string, unknown> = {}): Promise<unknown> {
    if (!this.channel || this.socket?.readyState !== WebSocket.OPEN) return Promise.reject(new Error("Encrypted bridge is not connected"));
    const requestId = crypto.randomUUID();
    const envelope = this.channel.encrypt("request", { ...body, type, requestId });
    this.socket.send(JSON.stringify({ type: "phone.frame", frame: { kind: "envelope", envelope } }));
    return new Promise((resolve, reject) => this.pending.set(requestId, { resolve, reject }));
  }

  onEvent(listener: (event: Record<string, unknown>) => void): () => void {
    this.eventListeners.add(listener);
    return () => this.eventListeners.delete(listener);
  }

  onClose(listener: () => void): () => void {
    this.closeListeners.add(listener);
    return () => this.closeListeners.delete(listener);
  }

  private async receive(raw: string, ready: () => void, reject: (error: Error) => void): Promise<void> {
    try {
      const message = JSON.parse(raw) as { type?: unknown; frame?: Record<string, unknown> };
      if (message.type !== "phone.frame" || !message.frame) return;
      if (message.frame.kind === "error") throw new Error(String(message.frame.error ?? "Encrypted handshake rejected"));
      if (message.frame.kind === "hello") {
        if (!this.handshake || !this.socket) throw new Error("Unexpected bridge handshake");
        const finished = await finishPhoneHandshake({
          state: this.handshake,
          reply: message.frame.reply as BridgeHello,
          bridgeIdentityPublicKey: this.device.bridgeIdentityPublicKey,
        });
        this.channel = finished.channel;
        this.socket.send(JSON.stringify({ type: "phone.frame", frame: { kind: "confirm", confirmation: finished.confirmation } }));
        return;
      }
      if (message.frame.kind === "ready") { this.handshake = null; ready(); return; }
      if (message.frame.kind !== "envelope" || !this.channel) return;
      const payload = this.channel.decrypt(message.frame.envelope as EncryptedEnvelope) as Record<string, unknown>;
      if (payload.requestId) {
        const pending = this.pending.get(String(payload.requestId));
        if (!pending) return;
        this.pending.delete(String(payload.requestId));
        if (payload.error) pending.reject(new Error(String(payload.error)));
        else pending.resolve(payload.result);
      } else {
        for (const listener of this.eventListeners) listener(payload);
      }
    } catch (error) { reject(asError(error)); this.close(); }
  }
}

export function loadDevice(): Promise<StoredDevice | null> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("cchat", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("device");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const request = open.result.transaction("device", "readonly").objectStore("device").get("current");
      request.onsuccess = () => { open.result.close(); resolve(request.result ?? null); };
      request.onerror = () => reject(request.error);
    };
  });
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
