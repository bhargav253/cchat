import assert from "node:assert/strict";
import test from "node:test";
import { generateIdentity } from "../security/e2ee.ts";
import { RelayDatabase } from "./database.ts";
import { WebAuthnService } from "./webauthn.ts";

test("Face ID registration options require user verification and an active paired phone", async () => {
  const database = new RelayDatabase(":memory:");
  const bridge = await generateIdentity();
  const phone = await generateIdentity();
  const bootstrap = "webauthn-bootstrap-token-at-least-thirty-two-characters";
  database.initializeBootstrap(bootstrap);
  database.claimInstallation({
    rawBootstrapToken: bootstrap,
    installationId: "installation_01",
    bridgeDeviceId: "bridge_device_01",
    bridgeIdentityPublicKey: bridge.publicKey,
  });
  database.registerPhone({
    id: "phone_device_01",
    installationId: "installation_01",
    name: "iPhone",
    identityPublicKey: phone.publicKey,
  });
  const service = new WebAuthnService(database, {
    rpName: "cchat",
    rpID: "cchat.example.com",
    expectedOrigin: "https://cchat.example.com",
  });
  const options = await service.registrationOptions("phone_device_01");
  assert.equal(options.authenticatorSelection?.userVerification, "required");
  assert.equal(options.authenticatorSelection?.residentKey, "required");
  assert.equal(options.attestation, "none");

  database.revokeDevice("phone_device_01", "bridge_device_01");
  await assert.rejects(() => service.registrationOptions("phone_device_01"), /revoked phone/);
  database.close();
});

test("WebAuthn refuses non-HTTPS production origins", () => {
  const database = new RelayDatabase(":memory:");
  assert.throws(() => new WebAuthnService(database, {
    rpName: "cchat",
    rpID: "cchat.example.com",
    expectedOrigin: "http://cchat.example.com",
  }), /HTTPS origin/);
  database.close();
});
