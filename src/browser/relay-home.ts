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
const renderedItems = new Map<string, HTMLElement>();
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
    transport.onClose(() => {
      transport = null;
      chatPanel.hidden = true;
      title.textContent = "Connection closed";
      copy.textContent = "Reload and use Face ID to establish a new encrypted channel.";
      status.textContent = "Encrypted connection closed";
    });
    await transport.connect();
    transport.onEvent(handleEncryptedEvent);
    const auth = await transport.request("auth.status") as { registered: boolean; authenticatedUntil: number };
    if (!auth.registered) await registerPasskey();
    else showLocked();
  } catch (error) { fail(error); }
}

function handleEncryptedEvent(event: Record<string, unknown>): void {
  if (event.type === "codex.event") {
    const params = (event.params ?? {}) as Record<string, unknown>;
    if (params.threadId && activeThreadId && params.threadId !== activeThreadId) return;
    const turn = params?.turn as Record<string, unknown> | undefined;
    if (typeof turn?.id === "string") activeTurnId = turn.id;
    handleCodexEvent(String(event.method ?? ""), params);
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
  const result = await transport.request("thread.open", { threadId }) as { thread?: Record<string, unknown> };
  renderConversation(result.thread ?? {});
}

function renderConversation(thread: Record<string, unknown>): void {
  renderedItems.clear();
  output.replaceChildren();
  const turns = (thread.turns ?? []) as Array<Record<string, unknown>>;
  for (const turn of turns) for (const item of (turn.items ?? []) as Array<Record<string, unknown>>) renderItem(item, false);
  const active = [...turns].reverse().find((turn) => turn.status === "inProgress");
  activeTurnId = typeof active?.id === "string" ? active.id : "";
  scrollConversation();
}

function handleCodexEvent(method: string, params: Record<string, unknown>): void {
  if (method === "turn/started") {
    const turn = params.turn as Record<string, unknown> | undefined;
    activeTurnId = typeof turn?.id === "string" ? turn.id : activeTurnId;
  } else if (method === "turn/completed") {
    activeTurnId = "";
    void loadThreads();
  } else if (method === "item/started" || method === "item/completed") {
    if (params.item && typeof params.item === "object") renderItem(params.item as Record<string, unknown>);
  } else if (method === "item/agentMessage/delta") {
    appendDelta(String(params.itemId ?? ""), String(params.delta ?? ""), "agent");
  } else if (method === "item/reasoning/summaryTextDelta") {
    appendDelta(String(params.itemId ?? ""), String(params.delta ?? ""), "reasoning");
  } else if (method === "item/commandExecution/outputDelta" || method === "item/fileChange/outputDelta") {
    appendToolDelta(String(params.itemId ?? ""), String(params.delta ?? ""));
  } else if (method === "error" || method === "warning") {
    fail(String(params.message ?? (params.error as Record<string, unknown> | undefined)?.message ?? "Codex reported an error"));
  }
}

function renderItem(item: Record<string, unknown>, scroll = true): void {
  const id = String(item.id ?? crypto.randomUUID());
  let node = renderedItems.get(id);
  if (!node) {
    if (item.type === "userMessage") {
      node = document.createElement("div");
      node.className = "chat-message user";
      const content = (item.content ?? []) as Array<Record<string, unknown>>;
      node.textContent = content.map((part) => String(part.text ?? "")).join("");
    } else if (item.type === "agentMessage") {
      node = document.createElement("div"); node.className = "chat-message agent"; node.textContent = String(item.text ?? "");
    } else if (item.type === "reasoning") {
      node = document.createElement("div"); node.className = "chat-message reasoning"; node.textContent = ((item.summary ?? []) as unknown[]).map(String).join("\n");
    } else {
      const details = document.createElement("details"); details.className = "chat-tool";
      const summary = document.createElement("summary"); summary.textContent = toolTitle(item);
      const body = document.createElement("pre"); body.textContent = toolBody(item); body.dataset.toolBody = "true";
      details.append(summary, body); node = details;
    }
    node.dataset.itemId = id;
    renderedItems.set(id, node);
    output.append(node);
  } else if (item.type === "agentMessage") node.textContent = String(item.text ?? node.textContent);
  else if (item.type === "reasoning") node.textContent = ((item.summary ?? []) as unknown[]).map(String).join("\n");
  else {
    const body = node.querySelector<HTMLElement>("[data-tool-body]");
    if (body) body.textContent = toolBody(item);
  }
  if (scroll) scrollConversation();
}

function appendDelta(id: string, delta: string, kind: "agent" | "reasoning"): void {
  let node = renderedItems.get(id);
  if (!node) {
    node = document.createElement("div"); node.className = `chat-message ${kind}`; node.dataset.itemId = id;
    renderedItems.set(id, node); output.append(node);
  }
  node.textContent += delta;
  scrollConversation();
}

function appendToolDelta(id: string, delta: string): void {
  const body = renderedItems.get(id)?.querySelector<HTMLElement>("[data-tool-body]");
  if (body) body.textContent += delta;
  scrollConversation();
}

function toolTitle(item: Record<string, unknown>): string {
  if (item.type === "commandExecution") return `Terminal · ${String(item.status ?? "running")}`;
  if (item.type === "fileChange") return `Files changed · ${String(item.status ?? "running")}`;
  if (item.type === "mcpToolCall") return `${String(item.server ?? "MCP")} / ${String(item.tool ?? "tool")}`;
  if (item.type === "plan") return "Plan";
  return String(item.type ?? "Codex activity").replace(/([A-Z])/g, " $1");
}

function toolBody(item: Record<string, unknown>): string {
  if (item.type === "commandExecution") return [item.command, item.aggregatedOutput].filter(Boolean).map(String).join("\n\n");
  if (item.type === "fileChange") return ((item.changes ?? []) as Array<Record<string, unknown>>).map((change) => `${String(change.kind)}: ${String(change.path)}\n${String(change.diff ?? "")}`).join("\n\n");
  if (item.type === "plan") return String(item.text ?? "");
  return JSON.stringify(item, null, 2);
}

function scrollConversation(): void { requestAnimationFrame(() => { output.scrollTop = output.scrollHeight; }); }

async function sendMessage(): Promise<void> {
  const text = promptInput.value.trim();
  if (!transport || !activeThreadId || !text) return;
  promptInput.value = "";
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
