import assert from "node:assert/strict";
import test from "node:test";
import { generateIdentity, generatePairingToken, verifyPairingRequest, type PairingRequest } from "../security/e2ee.ts";
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
