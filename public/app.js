const state = {
  socket: null,
  pending: new Map(),
  threads: [],
  thread: null,
  activeTurnId: null,
  items: new Map(),
  defaultCwd: "",
  reconnectDelay: 500,
  refreshInFlight: false,
};

const el = Object.fromEntries([
  "sidebar", "close-sidebar", "open-sidebar", "new-thread", "thread-list",
  "status-dot", "status-label", "status-detail", "thread-title", "thread-meta",
  "empty-state", "messages", "approval-tray", "composer", "prompt", "composer-hint",
  "send", "stop-turn", "new-thread-dialog", "new-thread-form", "cwd",
].map((id) => [id, document.getElementById(id)]));

connect();

function connect() {
  setStatus("connecting");
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${location.host}/bridge`);
  state.socket = socket;
  socket.addEventListener("open", async () => {
    state.reconnectDelay = 500;
    setStatus("online");
    try { await refreshThreads(); } catch (error) { showError(error); }
  });
  socket.addEventListener("message", ({ data }) => handle(JSON.parse(data)));
  socket.addEventListener("close", () => {
    setStatus("offline");
    for (const pending of state.pending.values()) pending.reject(new Error("Bridge disconnected"));
    state.pending.clear();
    const delay = state.reconnectDelay;
    state.reconnectDelay = Math.min(state.reconnectDelay * 2, 10_000);
    setTimeout(connect, delay);
  });
}

function request(type, params = {}) {
  if (state.socket?.readyState !== WebSocket.OPEN) return Promise.reject(new Error("Bridge is offline"));
  const requestId = crypto.randomUUID();
  return new Promise((resolve, reject) => {
    state.pending.set(requestId, { resolve, reject });
    state.socket.send(JSON.stringify({ type, requestId, ...params }));
    setTimeout(() => {
      if (state.pending.delete(requestId)) reject(new Error(`${type} timed out`));
    }, 30_000);
  });
}

function handle(message) {
  if (message.type === "response") {
    const pending = state.pending.get(message.requestId);
    if (!pending) return;
    state.pending.delete(message.requestId);
    message.error ? pending.reject(new Error(message.error)) : pending.resolve(message.result);
    return;
  }
  if (message.type === "bridge.status") {
    if (message.defaultCwd) state.defaultCwd = message.defaultCwd;
    setStatus(message.connected ? "online" : "offline", message.error);
    return;
  }
  if (message.type === "bridge.warning") {
    showError(new Error(message.message));
    return;
  }
  if (message.type === "approval.requested") {
    renderApproval(message);
    return;
  }
  if (message.type === "approval.resolved") {
    document.querySelector(`[data-approval-id="${CSS.escape(message.requestId)}"]`)?.remove();
    return;
  }
  if (message.type === "codex.event") handleCodexEvent(message.method, message.params);
}

async function refreshThreads() {
  if (state.refreshInFlight || state.socket?.readyState !== WebSocket.OPEN) return;
  state.refreshInFlight = true;
  try {
    const result = await request("threads.list");
    state.threads = result.data ?? [];
    renderThreads();
  } finally {
    state.refreshInFlight = false;
  }
}

function renderThreads() {
  el["thread-list"].replaceChildren(...state.threads.map((thread) => {
    const button = document.createElement("button");
    button.className = `thread${state.thread?.id === thread.id ? " active" : ""}`;
    const title = document.createElement("strong");
    title.textContent = thread.name || firstLine(thread.preview) || "Untitled session";
    const detail = document.createElement("small");
    detail.textContent = `${relativeTime(thread.recencyAt || thread.updatedAt)} · ${shortPath(thread.cwd)}`;
    button.append(title, detail);
    button.addEventListener("click", () => openThread(thread.id));
    return button;
  }));
}

async function openThread(threadId) {
  try {
    const result = await request("thread.open", { threadId });
    state.thread = result.thread;
    state.activeTurnId = activeTurn(result.thread)?.id ?? null;
    state.items.clear();
    renderThreads();
    renderConversation(result.thread);
    setComposer(true);
    el.sidebar.classList.remove("open");
  } catch (error) { showError(error); }
}

function renderConversation(thread) {
  el["empty-state"].classList.add("hidden");
  el.messages.classList.remove("hidden");
  el["thread-title"].textContent = thread.name || firstLine(thread.preview) || "Untitled session";
  el["thread-meta"].textContent = `${shortPath(thread.cwd)} · ${thread.modelProvider} · Codex ${thread.cliVersion}`;
  el.messages.replaceChildren();
  for (const turn of thread.turns ?? []) {
    for (const item of turn.items ?? []) renderItem(item, false);
  }
  scrollToBottom();
  updateTurnControls();
}

function renderItem(item, scroll = true) {
  let node = state.items.get(item.id);
  if (!node) {
    if (item.type === "userMessage") {
      node = document.createElement("div");
      node.className = "message user";
      node.textContent = item.content?.map((part) => part.text ?? "").join("") ?? "";
    } else if (item.type === "agentMessage") {
      node = document.createElement("div");
      node.className = "message agent";
      node.textContent = item.text ?? "";
    } else if (item.type === "reasoning") {
      node = document.createElement("div");
      node.className = "message reasoning";
      node.textContent = (item.summary ?? []).join("\n");
    } else {
      node = document.createElement("details");
      node.className = "tool-card";
      const summary = document.createElement("summary");
      summary.textContent = toolTitle(item);
      const body = document.createElement("pre");
      body.textContent = toolBody(item);
      node.append(summary, body);
      node._body = body;
    }
    node.dataset.itemId = item.id;
    state.items.set(item.id, node);
    el.messages.append(node);
  } else {
    if (item.type === "agentMessage") node.textContent = item.text ?? node.textContent;
    else if (node._body) node._body.textContent = toolBody(item);
  }
  if (scroll) scrollToBottom();
}

function handleCodexEvent(method, params = {}) {
  if (params.threadId && state.thread?.id && params.threadId !== state.thread.id) return;
  if (method === "thread/started" && params.thread) refreshThreads();
  if (method === "turn/started") {
    state.activeTurnId = params.turn?.id;
    updateTurnControls();
  } else if (method === "turn/completed") {
    state.activeTurnId = null;
    updateTurnControls();
    refreshThreads();
  } else if (method === "item/started" || method === "item/completed") {
    renderItem(params.item);
  } else if (method === "item/agentMessage/delta") {
    appendDelta(params.itemId, params.delta, "agent");
  } else if (method === "item/reasoning/summaryTextDelta") {
    appendDelta(params.itemId, params.delta, "reasoning");
  } else if (method === "item/commandExecution/outputDelta" || method === "item/fileChange/outputDelta") {
    appendToolDelta(params.itemId, params.delta);
  } else if (method === "error" || method === "warning") {
    showError(new Error(params.message || params.error?.message || "Codex reported an error"));
  }
}

function appendDelta(itemId, delta, className) {
  let node = state.items.get(itemId);
  if (!node) {
    node = document.createElement("div");
    node.className = `message ${className}`;
    node.dataset.itemId = itemId;
    state.items.set(itemId, node);
    el.messages.append(node);
  }
  node.textContent += delta ?? "";
  scrollToBottom();
}

function appendToolDelta(itemId, delta) {
  const node = state.items.get(itemId);
  if (node?._body) node._body.textContent += delta ?? "";
  scrollToBottom();
}

function renderApproval(message) {
  if (message.params?.threadId !== state.thread?.id) return;
  const card = document.createElement("article");
  card.className = "approval";
  card.dataset.approvalId = message.requestId;
  const title = document.createElement("h3");
  title.textContent = message.approvalType.includes("commandExecution") ? "Command needs approval" : "File change needs approval";
  const detail = document.createElement("pre");
  detail.textContent = message.params.command || message.params.reason || message.params.grantRoot || "Codex requested approval";
  const actions = document.createElement("div");
  actions.className = "approval-actions";
  for (const [label, decision, className] of [["Decline", "decline", ""], ["Approve once", "accept", "approve"]]) {
    const button = document.createElement("button");
    button.textContent = label;
    button.className = className;
    button.addEventListener("click", async () => {
      try {
        await request("approval.resolve", { approvalId: message.requestId, decision });
        card.remove();
      } catch (error) { showError(error); }
    });
    actions.append(button);
  }
  card.append(title, detail, actions);
  el["approval-tray"].append(card);
}

el.composer.addEventListener("submit", async (event) => {
  event.preventDefault();
  const text = el.prompt.value.trim();
  if (!text || !state.thread) return;
  el.prompt.value = "";
  resizeComposer();
  try {
    if (state.activeTurnId) {
      await request("turn.steer", { threadId: state.thread.id, turnId: state.activeTurnId, text });
    } else {
      const result = await request("turn.start", { threadId: state.thread.id, text });
      state.activeTurnId = result.turn.id;
      updateTurnControls();
    }
  } catch (error) { showError(error); }
});

el["stop-turn"].addEventListener("click", async () => {
  if (!state.thread || !state.activeTurnId) return;
  try { await request("turn.interrupt", { threadId: state.thread.id, turnId: state.activeTurnId }); }
  catch (error) { showError(error); }
});

el["new-thread"].addEventListener("click", () => {
  el.cwd.value = state.defaultCwd || "";
  el["new-thread-dialog"].showModal();
});

el["new-thread-form"].addEventListener("submit", async (event) => {
  const submitter = event.submitter?.value;
  if (submitter !== "create") return;
  event.preventDefault();
  try {
    const result = await request("thread.create", { cwd: el.cwd.value.trim() });
    el["new-thread-dialog"].close();
    await refreshThreads();
    await openThread(result.thread.id);
  } catch (error) { showError(error); }
});

el.prompt.addEventListener("input", resizeComposer);
el.prompt.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    el.composer.requestSubmit();
  }
});
el["open-sidebar"].addEventListener("click", () => el.sidebar.classList.add("open"));
el["close-sidebar"].addEventListener("click", () => el.sidebar.classList.remove("open"));

// A CLI-created thread is persisted after its first prompt. Polling keeps the
// browser session list current even though this App Server connection is not
// subscribed to a brand-new CLI thread yet.
setInterval(() => refreshThreads().catch(showError), 5_000);
window.addEventListener("focus", () => refreshThreads().catch(showError));
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") refreshThreads().catch(showError);
});

function setComposer(enabled) {
  el.prompt.disabled = !enabled;
  el.send.disabled = !enabled;
  el["composer-hint"].textContent = enabled ? "Enter to send · Shift+Enter for a new line" : "Select a session to begin";
}

function updateTurnControls() {
  el["stop-turn"].classList.toggle("hidden", !state.activeTurnId);
  el["composer-hint"].textContent = state.activeTurnId ? "Send to steer the active turn" : "Enter to send · Shift+Enter for a new line";
}

function setStatus(status, detail) {
  el["status-dot"].className = `status-dot ${status}`;
  el["status-label"].textContent = status === "online" ? "Codex connected" : status === "offline" ? "Bridge offline" : "Connecting";
  el["status-detail"].textContent = detail || "Local bridge";
}

function showError(error) {
  console.error(error);
  el["status-detail"].textContent = error.message || String(error);
}

function resizeComposer() {
  el.prompt.style.height = "auto";
  el.prompt.style.height = `${Math.min(el.prompt.scrollHeight, 180)}px`;
}

function scrollToBottom() { requestAnimationFrame(() => { el.messages.scrollTop = el.messages.scrollHeight; }); }
function activeTurn(thread) { return [...(thread.turns ?? [])].reverse().find((turn) => turn.status === "inProgress"); }
function firstLine(text = "") { return text.split("\n")[0].slice(0, 80); }
function shortPath(path = "") { const parts = path.split("/").filter(Boolean); return parts.length > 2 ? `…/${parts.slice(-2).join("/")}` : path || "Unknown folder"; }
function relativeTime(seconds) {
  if (!seconds) return "Unknown";
  const diff = Math.max(0, Date.now() / 1000 - seconds);
  if (diff < 60) return "Now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  return `${Math.floor(diff / 86400)}d`;
}
function toolTitle(item) {
  if (item.type === "commandExecution") return `Terminal · ${item.status || "running"}`;
  if (item.type === "fileChange") return `Files changed · ${item.status || "running"}`;
  if (item.type === "mcpToolCall") return `${item.server || "MCP"} / ${item.tool || "tool"}`;
  if (item.type === "plan") return "Plan";
  return item.type?.replace(/([A-Z])/g, " $1") || "Codex activity";
}
function toolBody(item) {
  if (item.type === "commandExecution") return [item.command, item.aggregatedOutput].filter(Boolean).join("\n\n");
  if (item.type === "fileChange") return (item.changes ?? []).map((change) => `${change.kind}: ${change.path}\n${change.diff || ""}`).join("\n\n");
  if (item.type === "plan") return item.text || "";
  return JSON.stringify(item, null, 2);
}
