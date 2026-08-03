import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { EncryptedTransport, loadDevice } from "./encrypted-transport.ts";

const title = document.querySelector<HTMLElement>("#home-title")!;
const copy = document.querySelector<HTMLElement>("#home-copy")!;
const button = document.querySelector<HTMLButtonElement>("#unlock-button")!;
const status = document.querySelector<HTMLElement>("#home-status")!;
const approvalPanel = document.querySelector<HTMLElement>("#approval-panel")!;
const approvalSummary = document.querySelector<HTMLElement>("#approval-summary")!;
const chatPanel = document.querySelector<HTMLElement>("#chat-panel")!;
const threadSelect = document.querySelector<HTMLSelectElement>("#thread-select")!;
const output = document.querySelector<HTMLElement>("#conversation-output")!;
const promptInput = document.querySelector<HTMLTextAreaElement>("#prompt-input")!;
let activeThreadId = "";
let activeTurnId = "";
let transport: EncryptedTransport | null = null;
let backgroundTimer: number | null = null;
let sessionTimer: number | null = null;

const device = await loadDevice();
if (!device) {
  title.textContent = "This device is not paired";
  copy.textContent = "Pairing will be enabled after the complete security validation is finished.";
  status.textContent = "Relay available · no conversation data exposed";
} else {
  try {
    status.textContent = "Establishing encrypted connection to your home bridge…";
    transport = new EncryptedTransport(device);
    await transport.connect();
    transport.onEvent(handleEncryptedEvent);
    const auth = await transport.request("auth.status") as { registered: boolean; authenticatedUntil: number };
    if (!auth.registered) await registerPasskey();
    else showLocked();
  } catch (error) { fail(error); }
}

function handleEncryptedEvent(event: Record<string, unknown>): void {
  if (event.type === "codex.event") {
    const params = event.params as Record<string, unknown> | undefined;
    const turn = params?.turn as Record<string, unknown> | undefined;
    if (typeof turn?.id === "string") activeTurnId = turn.id;
    output.textContent += `${JSON.stringify({ method: event.method, params: event.params }, null, 2)}\n`;
    output.scrollTop = output.scrollHeight;
  }
  if (event.type !== "approval.requested") return;
  const approvalId = String(event.requestId ?? "");
  const actionDigest = String(event.actionDigest ?? "");
  if (!approvalId || !actionDigest) return;
  approvalSummary.textContent = JSON.stringify({ approvalType: event.approvalType, params: event.params }, null, 2);
  approvalPanel.hidden = false;
  for (const element of approvalPanel.querySelectorAll<HTMLButtonElement>("button[data-decision]")) {
    element.onclick = () => void resolveApproval(approvalId, actionDigest, element.dataset.decision as "accept" | "decline");
  }
}

async function resolveApproval(approvalId: string, actionDigest: string, decision: "accept" | "decline"): Promise<void> {
  if (!transport) return;
  for (const element of approvalPanel.querySelectorAll<HTMLButtonElement>("button")) element.disabled = true;
  try {
    status.textContent = "Confirm this exact approval with Face ID…";
    const options = await transport.request("auth.approval.options", { actionDigest });
    const response = await startAuthentication({ optionsJSON: options as Parameters<typeof startAuthentication>[0]["optionsJSON"] });
    await transport.request("auth.approval.verify", { response });
    await transport.request("approval.resolve", { approvalId, actionDigest, decision });
    approvalPanel.hidden = true;
    status.textContent = `Approval ${decision === "accept" ? "accepted" : "declined"} after Face ID`;
  } catch (error) {
    fail(error);
    for (const element of approvalPanel.querySelectorAll<HTMLButtonElement>("button")) element.disabled = false;
  }
}

button.addEventListener("click", () => void unlock());
document.querySelector("#refresh-threads")!.addEventListener("click", () => void loadThreads());
threadSelect.addEventListener("change", () => void openThread(threadSelect.value));
document.querySelector("#send-prompt")!.addEventListener("click", () => void sendMessage());
document.querySelector("#interrupt-turn")!.addEventListener("click", () => void interrupt());
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    backgroundTimer = window.setTimeout(lock, 5 * 60_000);
  } else if (backgroundTimer !== null) {
    window.clearTimeout(backgroundTimer);
    backgroundTimer = null;
  }
});

async function registerPasskey(): Promise<void> {
  if (!transport) return;
  title.textContent = "Protect this phone";
  copy.textContent = "Create a passkey verified directly by your home bridge.";
  status.textContent = "Waiting for Face ID…";
  const options = await transport.request("auth.register.options");
  const response = await startRegistration({ optionsJSON: options as Parameters<typeof startRegistration>[0]["optionsJSON"] });
  const result = await transport.request("auth.register.verify", { response }) as { authenticatedUntil: number };
  showUnlocked(result.authenticatedUntil);
}

async function unlock(): Promise<void> {
  if (!transport) return;
  button.disabled = true;
  status.textContent = "Waiting for Face ID…";
  try {
    const options = await transport.request("auth.authenticate.options");
    const response = await startAuthentication({ optionsJSON: options as Parameters<typeof startAuthentication>[0]["optionsJSON"] });
    const result = await transport.request("auth.authenticate.verify", { response }) as { authenticatedUntil: number };
    showUnlocked(result.authenticatedUntil);
  } catch (error) { fail(error); button.disabled = false; }
}

function showLocked(): void {
  title.textContent = "Unlock cchat";
  copy.textContent = "Confirm with Face ID to open a 15-minute bridge-authorized session.";
  status.textContent = "Encrypted connection · locked";
  button.hidden = false;
  button.disabled = false;
}

function showUnlocked(expiresAt: number): void {
  title.textContent = "cchat unlocked";
  copy.textContent = "Your home bridge verified Face ID. Codex UI wiring is in progress.";
  status.textContent = `Encrypted and authenticated until ${new Date(expiresAt).toLocaleTimeString()}`;
  button.hidden = true;
  chatPanel.hidden = false;
  void loadThreads();
  if (sessionTimer !== null) window.clearTimeout(sessionTimer);
  sessionTimer = window.setTimeout(lock, Math.max(0, expiresAt - Date.now()));
}

function lock(): void {
  if (sessionTimer !== null) window.clearTimeout(sessionTimer);
  sessionTimer = null;
  transport?.close();
  transport = null;
  title.textContent = "cchat locked";
  copy.textContent = "The encrypted channel closed after five minutes in the background. Reload to reconnect.";
  status.textContent = "Locked";
  button.hidden = true;
  chatPanel.hidden = true;
}

async function loadThreads(): Promise<void> {
  if (!transport) return;
  try {
    const result = await transport.request("threads.list") as Record<string, unknown>;
    const threads = (result.data ?? result.threads ?? []) as Array<Record<string, unknown>>;
    threadSelect.replaceChildren(...threads.map((thread) => {
      const option = document.createElement("option");
      option.value = String(thread.id ?? "");
      option.textContent = String(thread.name ?? thread.title ?? thread.preview ?? thread.id ?? "Session").slice(0, 100);
      return option;
    }));
    if (threadSelect.value) await openThread(threadSelect.value);
  } catch (error) { fail(error); }
}

async function openThread(threadId: string): Promise<void> {
  if (!transport || !threadId) return;
  activeThreadId = threadId;
  output.textContent = JSON.stringify(await transport.request("thread.open", { threadId }), null, 2);
}

async function sendMessage(): Promise<void> {
  const text = promptInput.value.trim();
  if (!transport || !activeThreadId || !text) return;
  promptInput.value = "";
  output.textContent += `\nYou: ${text}\n`;
  const result = await transport.request("turn.start", { threadId: activeThreadId, text }) as Record<string, unknown>;
  const turn = result.turn as Record<string, unknown> | undefined;
  if (typeof turn?.id === "string") activeTurnId = turn.id;
}

async function interrupt(): Promise<void> {
  if (transport && activeThreadId && activeTurnId) await transport.request("turn.interrupt", { threadId: activeThreadId, turnId: activeTurnId });
}

function fail(error: unknown): void {
  status.textContent = error instanceof Error ? error.message : String(error);
  status.classList.add("error");
}
