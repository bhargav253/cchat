import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { EncryptedTransport, loadDevice } from "./encrypted-transport.ts";

type Obj = Record<string, unknown>;
const byId = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const el = {
  gate: byId("security-gate"), shell: byId("app-shell"), title: byId("home-title"), copy: byId("home-copy"), gateStatus: byId("home-status"), unlock: byId<HTMLButtonElement>("unlock-button"),
  sidebar: byId("sidebar"), scrim: byId("drawer-scrim"), threadList: byId("thread-list"), threadTitle: byId("thread-title"), threadMeta: byId("thread-meta"),
  empty: byId("empty-state"), messages: byId("messages"), approvals: byId("approval-tray"), prompt: byId<HTMLTextAreaElement>("prompt"), composer: byId<HTMLFormElement>("composer"),
  send: byId<HTMLButtonElement>("send"), stop: byId<HTMLButtonElement>("stop-turn"), hint: byId("composer-hint"), status: byId("status-detail"), cwd: byId<HTMLInputElement>("cwd"), dialog: byId<HTMLDialogElement>("new-thread-dialog"),
};
let transport: EncryptedTransport | null = null;
let threads: Obj[] = [], thread: Obj | null = null, activeTurnId = "";
let backgroundTimer: number | null = null, sessionTimer: number | null = null;
const items = new Map<string, HTMLElement>();

await initialize();

async function initialize() {
  const device = await loadDevice();
  if (!device) { el.title.textContent = "This device is not paired"; el.copy.textContent = "Create a one-time QR code from your home bridge."; return; }
  try {
    el.gateStatus.textContent = "Establishing encrypted connection…";
    transport = new EncryptedTransport(device);
    transport.onEvent(handleEvent);
    transport.onClose(showDisconnected);
    await transport.connect();
    const auth = await transport.request("auth.status") as { registered: boolean };
    if (!auth.registered) await registerPasskey(); else showLocked();
  } catch (error) { gateError(error); }
}

async function registerPasskey() {
  if (!transport) return;
  el.title.textContent = "Protect this phone"; el.copy.textContent = "Create a passkey verified directly by your home bridge.";
  const options = await transport.request("auth.register.options");
  const response = await startRegistration({ optionsJSON: options as Parameters<typeof startRegistration>[0]["optionsJSON"] });
  const result = await transport.request("auth.register.verify", { response }) as { authenticatedUntil: number };
  showApp(result.authenticatedUntil);
}

function showLocked() { el.title.textContent = "Unlock cchat"; el.copy.textContent = "Confirm with Face ID to open a 15-minute session."; el.unlock.hidden = false; el.gateStatus.textContent = "Encrypted connection · locked"; }
el.unlock.onclick = async () => {
  if (!transport) return location.reload();
  el.unlock.disabled = true;
  try {
    const options = await transport.request("auth.authenticate.options");
    const response = await startAuthentication({ optionsJSON: options as Parameters<typeof startAuthentication>[0]["optionsJSON"] });
    const result = await transport.request("auth.authenticate.verify", { response }) as { authenticatedUntil: number };
    showApp(result.authenticatedUntil);
  } catch (error) { gateError(error); el.unlock.disabled = false; }
};

function showApp(expiresAt: number) {
  el.gate.classList.add("hidden"); el.shell.classList.remove("hidden");
  if (sessionTimer !== null) clearTimeout(sessionTimer);
  sessionTimer = window.setTimeout(lock, Math.max(0, expiresAt - Date.now()));
  void refreshThreads();
}
function lock() { transport?.close(); transport = null; el.shell.classList.add("hidden"); el.gate.classList.remove("hidden"); el.title.textContent = "cchat locked"; el.copy.textContent = "Reload and use Face ID to reconnect."; el.unlock.hidden = true; }
function showDisconnected() { transport = null; el.status.textContent = "Encrypted connection closed"; el.shell.classList.add("hidden"); el.gate.classList.remove("hidden"); el.title.textContent = "Connection closed"; el.copy.textContent = "Reload to establish a fresh encrypted channel."; el.unlock.hidden = true; }

async function request(type: string, body: Obj = {}) { if (!transport) throw new Error("Bridge is disconnected"); return transport.request(type, body); }
async function refreshThreads() { const result = await request("threads.list") as Obj; threads = (result.data ?? []) as Obj[]; renderThreads(); }
function renderThreads() {
  el.threadList.replaceChildren(...threads.map((t) => { const b=document.createElement("button"); b.className=`thread${thread?.id===t.id?" active":""}`; const s=document.createElement("strong"); s.textContent=String(t.name||firstLine(String(t.preview??""))||"Untitled session"); const d=document.createElement("small"); d.textContent=`${relativeTime(Number(t.recencyAt||t.updatedAt))} · ${shortPath(String(t.cwd??""))}`; b.append(s,d); b.onclick=()=>void openThread(String(t.id)); return b; }));
}
async function openThread(id: string) { const result=await request("thread.open",{threadId:id}) as {thread:Obj}; thread=result.thread; renderThreads(); renderConversation(thread); closeDrawer(); }
function renderConversation(t: Obj) { items.clear(); el.messages.replaceChildren(); el.empty.classList.add("hidden"); el.messages.classList.remove("hidden"); el.threadTitle.textContent=String(t.name||firstLine(String(t.preview??""))||"Untitled session"); el.threadMeta.textContent=`${shortPath(String(t.cwd??""))} · encrypted home bridge`; for(const turn of (t.turns??[]) as Obj[]) for(const item of (turn.items??[]) as Obj[]) renderItem(item,false); const active=[...((t.turns??[]) as Obj[])].reverse().find(x=>x.status==="inProgress"); activeTurnId=String(active?.id??""); setComposer(true); scroll(); }

function handleEvent(event: Obj) {
  if(event.type==="approval.requested") return renderApproval(event);
  if(event.type!=="codex.event") return;
  const p=(event.params??{}) as Obj; if(p.threadId&&thread?.id&&p.threadId!==thread.id)return; const m=String(event.method??"");
  if(m==="turn/started") activeTurnId=String((p.turn as Obj)?.id??""); else if(m==="turn/completed"){activeTurnId="";void refreshThreads();}
  else if((m==="item/started"||m==="item/completed")&&p.item)renderItem(p.item as Obj);
  else if(m==="item/agentMessage/delta")appendDelta(String(p.itemId),String(p.delta??""),"agent");
  else if(m==="item/reasoning/summaryTextDelta")appendDelta(String(p.itemId),String(p.delta??""),"reasoning");
  else if(m.includes("outputDelta"))appendToolDelta(String(p.itemId),String(p.delta??"")); updateControls();
}
function renderItem(item: Obj, doScroll=true) { const id=String(item.id??crypto.randomUUID()); let n=items.get(id); if(!n){ if(item.type==="userMessage"){n=document.createElement("div");n.className="message user";n.textContent=((item.content??[]) as Obj[]).map(x=>String(x.text??"")).join("");}else if(item.type==="agentMessage"){n=document.createElement("div");n.className="message agent";n.textContent=String(item.text??"");}else if(item.type==="reasoning"){n=document.createElement("div");n.className="message reasoning";n.textContent=((item.summary??[]) as unknown[]).map(String).join("\n");}else{const d=document.createElement("details");d.className="tool-card";const s=document.createElement("summary");s.textContent=toolTitle(item);const pre=document.createElement("pre");pre.textContent=toolBody(item);pre.dataset.body="1";d.append(s,pre);n=d;} n.dataset.itemId=id;items.set(id,n);el.messages.append(n);}else if(item.type==="agentMessage")n.textContent=String(item.text??n.textContent);else{const b=n.querySelector<HTMLElement>("[data-body]");if(b)b.textContent=toolBody(item);}if(doScroll)scroll(); }
function appendDelta(id:string,delta:string,kind:string){let n=items.get(id);if(!n){n=document.createElement("div");n.className=`message ${kind}`;items.set(id,n);el.messages.append(n);}n.textContent+=delta;scroll();}
function appendToolDelta(id:string,delta:string){const b=items.get(id)?.querySelector<HTMLElement>("[data-body]");if(b)b.textContent+=delta;scroll();}

function renderApproval(a:Obj){if((a.params as Obj)?.threadId!==thread?.id)return;const card=document.createElement("article");card.className="approval";const h=document.createElement("h3");h.textContent=String(a.approvalType).includes("command")?"Command needs approval":"File change needs approval";const pre=document.createElement("pre");pre.textContent=String((a.params as Obj)?.command||(a.params as Obj)?.reason||"Codex requested approval");const actions=document.createElement("div");actions.className="approval-actions";for(const [label,decision] of [["Decline","decline"],["Face ID and approve","accept"]] as const){const b=document.createElement("button");b.textContent=label;b.onclick=()=>void approve(a,decision,card);actions.append(b);}card.append(h,pre,actions);el.approvals.append(card);}
async function approve(a:Obj,decision:string,card:HTMLElement){const digest=String(a.actionDigest);const options=await request("auth.approval.options",{actionDigest:digest});const response=await startAuthentication({optionsJSON:options as Parameters<typeof startAuthentication>[0]["optionsJSON"]});await request("auth.approval.verify",{response});await request("approval.resolve",{approvalId:a.requestId,actionDigest:digest,decision});card.remove();}

el.composer.onsubmit=async(e)=>{e.preventDefault();const text=el.prompt.value.trim();if(!text||!thread)return;el.prompt.value="";if(activeTurnId)await request("turn.steer",{threadId:thread.id,turnId:activeTurnId,text});else{const r=await request("turn.start",{threadId:thread.id,text}) as Obj;activeTurnId=String((r.turn as Obj)?.id??"");}updateControls();};
el.stop.onclick=()=>void(thread&&activeTurnId&&request("turn.interrupt",{threadId:thread.id,turnId:activeTurnId}));
byId("open-sidebar").onclick=openDrawer;byId("close-sidebar").onclick=closeDrawer;el.scrim.onclick=closeDrawer;
byId("new-thread").onclick=()=>el.dialog.showModal();byId<HTMLFormElement>("new-thread-form").onsubmit=async(e)=>{if((e as SubmitEvent).submitter?.getAttribute("value")!=="create")return;e.preventDefault();const r=await request("thread.create",{cwd:el.cwd.value.trim()}) as Obj;el.dialog.close();await refreshThreads();await openThread(String((r.thread as Obj).id));};
document.addEventListener("visibilitychange",()=>{if(document.hidden)backgroundTimer=window.setTimeout(lock,5*60_000);else if(backgroundTimer!==null){clearTimeout(backgroundTimer);backgroundTimer=null;}});
setInterval(()=>{if(transport)void refreshThreads().catch(()=>{});},5000);
function setComposer(on:boolean){el.prompt.disabled=!on;el.send.disabled=!on;updateControls();}function updateControls(){el.stop.classList.toggle("hidden",!activeTurnId);el.hint.textContent=activeTurnId?"Send to steer the active turn":"Enter to send · Shift+Enter for a new line";}
function openDrawer(){el.sidebar.classList.add("open");el.scrim.classList.add("visible");}function closeDrawer(){el.sidebar.classList.remove("open");el.scrim.classList.remove("visible");}
function gateError(x:unknown){el.gateStatus.textContent=x instanceof Error?x.message:String(x);}function scroll(){requestAnimationFrame(()=>el.messages.scrollTop=el.messages.scrollHeight);}
function firstLine(s:string){return s.split("\n")[0]!.slice(0,80);}function shortPath(s:string){const p=s.split("/").filter(Boolean);return p.length>2?`…/${p.slice(-2).join("/")}`:s||"Unknown folder";}function relativeTime(s:number){if(!s)return "Unknown";const d=Math.max(0,Date.now()/1000-s);return d<60?"Now":d<3600?`${Math.floor(d/60)}m`:d<86400?`${Math.floor(d/3600)}h`:`${Math.floor(d/86400)}d`;}
function toolTitle(i:Obj){if(i.type==="commandExecution")return`Terminal · ${i.status||"running"}`;if(i.type==="fileChange")return`Files changed · ${i.status||"running"}`;if(i.type==="mcpToolCall")return`${i.server||"MCP"} / ${i.tool||"tool"}`;return String(i.type||"Codex activity");}function toolBody(i:Obj){if(i.type==="commandExecution")return[i.command,i.aggregatedOutput].filter(Boolean).join("\n\n");if(i.type==="fileChange")return((i.changes??[]) as Obj[]).map(c=>`${c.kind}: ${c.path}\n${c.diff||""}`).join("\n\n");return JSON.stringify(i,null,2);}
