import assert from "node:assert/strict";
import test from "node:test";
import {
  acceptPhoneHello,
  createPhoneHelloWithSigner,
  finishPhoneHandshake,
  generateIdentity,
  generatePairingToken,
  verifyPairingRequest,
  verifyPhoneConfirmation,
  type PairingRequest,
} from "../security/e2ee.ts";
import { createPairingProof, generateNonExportableIdentity } from "./device-identity.ts";

test("non-exportable WebCrypto phone identity creates a bridge-compatible pairing proof", async () => {
  const bridge = await generateIdentity();
  const phone = await generateNonExportableIdentity();
  assert.equal(phone.privateKey.extractable, false);
  await assert.rejects(() => crypto.subtle.exportKey("pkcs8", phone.privateKey), /extractable/);
  const token = await generatePairingToken();
  const request = await createPairingProof({
    pairingToken: token,
    installationId: "installation_01",
    phoneDeviceId: "phone_device_01",
    bridgeIdentityPublicKey: bridge.publicKey,
    phoneIdentityPublicKey: phone.publicKey,
  });
  assert.equal(await verifyPairingRequest(request as unknown as PairingRequest, token), true);
});

test("non-exportable WebCrypto identity authenticates an encrypted bridge channel", async () => {
  const bridge = await generateIdentity();
  const phone = await generateNonExportableIdentity();
  const initiated = await createPhoneHelloWithSigner({
    installationId: "installation_01",
    phoneDeviceId: "phone_device_01",
    bridgeDeviceId: "bridge_device_01",
    phoneIdentityPublicKey: phone.publicKey,
    bridgeIdentityPublicKey: bridge.publicKey,
    sign: async (message) => new Uint8Array(await crypto.subtle.sign("Ed25519", phone.privateKey, message.buffer as ArrayBuffer)),
  });
  const accepted = await acceptPhoneHello({
    hello: initiated.hello,
    bridgeIdentity: bridge,
    expectedInstallationId: "installation_01",
    expectedBridgeDeviceId: "bridge_device_01",
    registeredPhoneIdentityPublicKey: phone.publicKey,
  });
  const finished = await finishPhoneHandshake({
    state: initiated.state,
    reply: accepted.reply,
    bridgeIdentityPublicKey: bridge.publicKey,
  });
  assert.equal(await verifyPhoneConfirmation(accepted.state, finished.confirmation), true);
  const envelope = finished.channel.encrypt("request", { secret: "phone plaintext" });
  assert.deepEqual(accepted.channel.decrypt(envelope), { secret: "phone plaintext" });
});
