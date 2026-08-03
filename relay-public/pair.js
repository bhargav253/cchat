// src/browser/device-identity.ts
async function generateNonExportableIdentity() {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  if (keys.privateKey.extractable) throw new Error("Browser created an extractable private key");
  return { publicKey: base64url(publicBytes), privateKey: keys.privateKey };
}
async function createPairingProof(params) {
  const tokenBytes = decodeBase64url(params.pairingToken);
  const tokenKey = await crypto.subtle.importKey("raw", tokenBytes.buffer, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  const transcript = frame("cchat-pairing-v1", params.installationId, params.phoneDeviceId, params.bridgeIdentityPublicKey, params.phoneIdentityPublicKey);
  const fullProof = new Uint8Array(await crypto.subtle.sign("HMAC", tokenKey, transcript.buffer));
  return { version: 1, ...params, pairingToken: void 0, proof: base64url(fullProof.slice(0, 32)) };
}
function frame(...values) {
  const encoded = values.map((value) => new TextEncoder().encode(value));
  const output = new Uint8Array(encoded.reduce((total, value) => total + 4 + value.length, 0));
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const value of encoded) {
    view.setUint32(offset, value.length, false);
    offset += 4;
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}
function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function decodeBase64url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

// src/browser/pair.ts
var status = document.querySelector("#pair-status");
var button = document.querySelector("#pair-button");
var nameInput = document.querySelector("#device-name");
var fragment = new URLSearchParams(location.hash.slice(1));
var invitationId = fragment.get("invitation");
var pairingToken = fragment.get("secret");
history.replaceState(null, "", `${location.pathname}${location.search}`);
if (!invitationId || !pairingToken) {
  fail("This pairing link is incomplete. Create a new link from your bridge.");
} else {
  button.disabled = false;
  button.addEventListener("click", () => void pair(invitationId, pairingToken));
}
async function pair(invitation, secret) {
  button.disabled = true;
  status.textContent = "Creating this phone\u2019s private identity\u2026";
  try {
    const metadataResponse = await fetch(`/api/v1/pairing/invitations/${encodeURIComponent(invitation)}`, { cache: "no-store" });
    if (!metadataResponse.ok) throw new Error(await responseError(metadataResponse));
    const metadata = await metadataResponse.json();
    const identity = await generateNonExportableIdentity();
    const phoneDeviceId = `phone_${crypto.randomUUID().replaceAll("-", "")}`;
    const request = await createPairingProof({
      pairingToken: secret,
      installationId: metadata.installationId,
      phoneDeviceId,
      bridgeIdentityPublicKey: metadata.bridgeIdentityPublicKey,
      phoneIdentityPublicKey: identity.publicKey
    });
    status.textContent = "Waiting for your home bridge to verify the one-time proof\u2026";
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${location.host}/api/v1/connect`);
    const timeout = window.setTimeout(() => socket.close(4e3, "Pairing timeout"), 2e4);
    socket.addEventListener("open", () => socket.send(JSON.stringify({
      type: "phone.pair",
      invitationId: invitation,
      name: nameInput.value.trim() || "Phone",
      request
    })));
    socket.addEventListener("message", async (event) => {
      try {
        const message = JSON.parse(String(event.data));
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
          phoneIdentityPrivateKey: identity.privateKey
        });
        status.textContent = "Identity paired. Continuing to bridge-verified Face ID setup\u2026";
        button.textContent = "Paired";
        socket.close(1e3, "Complete");
        location.replace("/");
      } catch (error) {
        fail(error instanceof Error ? error.message : String(error));
        socket.close(1008, "Pairing rejected");
      }
    });
    socket.addEventListener("close", (event) => {
      window.clearTimeout(timeout);
      if (event.code !== 1e3 && button.textContent !== "Paired") fail(event.reason || "Pairing connection closed");
    });
    socket.addEventListener("error", () => fail("Could not connect to the encrypted relay"));
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
function saveDevice(value) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("cchat", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("device");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const transaction = open.result.transaction("device", "readwrite");
      transaction.objectStore("device").put(value, "current");
      transaction.oncomplete = () => {
        open.result.close();
        resolve();
      };
      transaction.onerror = () => reject(transaction.error);
    };
  });
}
function fail(message) {
  status.textContent = message;
  status.classList.add("error");
  button.disabled = true;
}
async function responseError(response) {
  try {
    return String((await response.json()).error ?? `Request failed (${response.status})`);
  } catch {
    return `Request failed (${response.status})`;
  }
}
