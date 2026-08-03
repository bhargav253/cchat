export type BrowserIdentity = { publicKey: string; privateKey: CryptoKey };

export async function generateNonExportableIdentity(): Promise<BrowserIdentity> {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  if (keys.privateKey.extractable) throw new Error("Browser created an extractable private key");
  return { publicKey: base64url(publicBytes), privateKey: keys.privateKey };
}

export async function createPairingProof(params: {
  pairingToken: string;
  installationId: string;
  phoneDeviceId: string;
  bridgeIdentityPublicKey: string;
  phoneIdentityPublicKey: string;
}): Promise<Record<string, unknown>> {
  const tokenBytes = decodeBase64url(params.pairingToken);
  const tokenKey = await crypto.subtle.importKey("raw", tokenBytes.buffer as ArrayBuffer, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  const transcript = frame("cchat-pairing-v1", params.installationId, params.phoneDeviceId, params.bridgeIdentityPublicKey, params.phoneIdentityPublicKey);
  const fullProof = new Uint8Array(await crypto.subtle.sign("HMAC", tokenKey, transcript.buffer as ArrayBuffer));
  return { version: 1, ...params, pairingToken: undefined, proof: base64url(fullProof.slice(0, 32)) };
}

function frame(...values: string[]): Uint8Array {
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

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeBase64url(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
