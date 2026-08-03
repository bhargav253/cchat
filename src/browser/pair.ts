import { createPairingProof, generateNonExportableIdentity } from "./device-identity.ts";

type Invitation = {
  id: string;
  installationId: string;
  bridgeDeviceId: string;
  bridgeIdentityPublicKey: string;
  expiresAt: number;
};

const status = document.querySelector<HTMLElement>("#pair-status")!;
const button = document.querySelector<HTMLButtonElement>("#pair-button")!;
const nameInput = document.querySelector<HTMLInputElement>("#device-name")!;
const fragment = new URLSearchParams(location.hash.slice(1));
const invitationId = fragment.get("invitation");
const pairingToken = fragment.get("secret");
history.replaceState(null, "", `${location.pathname}${location.search}`);

if (!invitationId || !pairingToken) {
  fail("This pairing link is incomplete. Create a new link from your bridge.");
} else {
  button.disabled = false;
  button.addEventListener("click", () => void pair(invitationId, pairingToken));
}

async function pair(invitation: string, secret: string): Promise<void> {
  button.disabled = true;
  status.textContent = "Creating this phone’s private identity…";
  try {
    const metadataResponse = await fetch(`/api/v1/pairing/invitations/${encodeURIComponent(invitation)}`, { cache: "no-store" });
    if (!metadataResponse.ok) throw new Error(await responseError(metadataResponse));
    const metadata = await metadataResponse.json() as Invitation;
    const identity = await generateNonExportableIdentity();
    const phoneDeviceId = `phone_${crypto.randomUUID().replaceAll("-", "")}`;
    const request = await createPairingProof({
      pairingToken: secret,
      installationId: metadata.installationId,
      phoneDeviceId,
      bridgeIdentityPublicKey: metadata.bridgeIdentityPublicKey,
      phoneIdentityPublicKey: identity.publicKey,
    });
    status.textContent = "Waiting for your home bridge to verify the one-time proof…";
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${location.host}/api/v1/connect`);
    const timeout = window.setTimeout(() => socket.close(4000, "Pairing timeout"), 20_000);
    socket.addEventListener("open", () => socket.send(JSON.stringify({
      type: "phone.pair",
      invitationId: invitation,
      name: nameInput.value.trim() || "Phone",
      request,
    })));
    socket.addEventListener("message", async (event) => {
      try {
        const message = JSON.parse(String(event.data)) as Record<string, unknown>;
        if (message.type === "pairing.rejected") throw new Error(String(message.error ?? "Pairing rejected"));
        if (message.type !== "pairing.complete") return;
        window.clearTimeout(timeout);
        await saveDevice({
          version: 1,
          installationId: metadata.installationId,
          bridgeDeviceId: metadata.bridgeDeviceId,
          bridgeIdentityPublicKey: metadata.bridgeIdentityPublicKey,
          phoneDeviceId,
          phoneIdentityPublicKey: identity.publicKey,
          phoneIdentityPrivateKey: identity.privateKey,
        });
        status.textContent = "Identity paired. Continuing to bridge-verified Face ID setup…";
        button.textContent = "Paired";
        socket.close(1000, "Complete");
        location.replace("/");
      } catch (error) {
        fail(error instanceof Error ? error.message : String(error));
        socket.close(1008, "Pairing rejected");
      }
    });
    socket.addEventListener("close", (event) => {
      window.clearTimeout(timeout);
      if (event.code !== 1000 && button.textContent !== "Paired") fail(event.reason || "Pairing connection closed");
    });
    socket.addEventListener("error", () => fail("Could not connect to the encrypted relay"));
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}

function saveDevice(value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("cchat", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("device");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const transaction = open.result.transaction("device", "readwrite");
      transaction.objectStore("device").put(value, "current");
      transaction.oncomplete = () => { open.result.close(); resolve(); };
      transaction.onerror = () => reject(transaction.error);
    };
  });
}

function fail(message: string): void {
  status.textContent = message;
  status.classList.add("error");
  button.disabled = true;
}

async function responseError(response: Response): Promise<string> {
  try { return String((await response.json() as { error?: unknown }).error ?? `Request failed (${response.status})`); }
  catch { return `Request failed (${response.status})`; }
}
