import { startAuthentication } from "@simplewebauthn/browser";

const title = document.querySelector<HTMLElement>("#home-title")!;
const copy = document.querySelector<HTMLElement>("#home-copy")!;
const button = document.querySelector<HTMLButtonElement>("#unlock-button")!;
const status = document.querySelector<HTMLElement>("#home-status")!;

const device = await loadDevice();
if (!device) {
  title.textContent = "This device is not paired";
  copy.textContent = "Run npm run pair on your home bridge and scan its one-time QR code.";
  status.textContent = "Relay available · no conversation data exposed";
} else {
  title.textContent = "Unlock cchat";
  copy.textContent = "Confirm with Face ID to open a short-lived private session.";
  button.hidden = false;
  button.addEventListener("click", () => void unlock(device.phoneDeviceId));
  status.textContent = "Paired device · locked";
}

async function unlock(deviceId: string): Promise<void> {
  button.disabled = true;
  status.textContent = "Waiting for Face ID…";
  try {
    const headers = { "Content-Type": "application/json" };
    const optionsResponse = await fetch("/api/v1/webauthn/authenticate/options", {
      method: "POST", headers, body: JSON.stringify({ deviceId }),
    });
    if (!optionsResponse.ok) throw new Error(await responseError(optionsResponse));
    const assertion = await startAuthentication({ optionsJSON: await optionsResponse.json() });
    const verifyResponse = await fetch("/api/v1/webauthn/authenticate/verify", {
      method: "POST", headers, body: JSON.stringify({ deviceId, response: assertion }),
    });
    if (!verifyResponse.ok) throw new Error(await responseError(verifyResponse));
    const result = await verifyResponse.json() as { sessionToken: string; expiresAt: number };
    sessionStorage.setItem("cchat.session", JSON.stringify(result));
    title.textContent = "cchat unlocked";
    copy.textContent = "Your Face ID session is active. Encrypted Codex routing is the next milestone.";
    status.textContent = "Authenticated · relay stores no conversations";
    button.hidden = true;
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : String(error);
    status.classList.add("error");
    button.disabled = false;
  }
}

function loadDevice(): Promise<{ phoneDeviceId: string } | null> {
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

async function responseError(response: Response): Promise<string> {
  try { return String((await response.json() as { error?: unknown }).error ?? `Request failed (${response.status})`); }
  catch { return `Request failed (${response.status})`; }
}
