import assert from "node:assert/strict";
import test from "node:test";
import { generateIdentity } from "../security/e2ee.ts";
import { hashSecret, RelayDatabase } from "./database.ts";

test("relay database stores control-plane records and no transcript tables", async () => {
  const database = new RelayDatabase(":memory:");
  const bridge = await generateIdentity();
  const bootstrap = "bootstrap-token-with-at-least-thirty-two-characters";
  assert.equal(database.initializeBootstrap(bootstrap), true);
  assert.equal(database.initializeBootstrap(bootstrap), false);
  database.claimInstallation({
    rawBootstrapToken: bootstrap,
    installationId: "installation_01",
    bridgeDeviceId: "bridge_device_01",
    bridgeIdentityPublicKey: bridge.publicKey,
    bridgeAccessToken: "bridge-access-token-with-at-least-thirty-two-characters",
    now: 1_000,
  });
  assert.throws(() => database.claimInstallation({
    rawBootstrapToken: bootstrap,
    installationId: "installation_02",
    bridgeDeviceId: "bridge_device_02",
    bridgeIdentityPublicKey: bridge.publicKey,
    bridgeAccessToken: "bridge-access-token-with-at-least-thirty-two-characters",
  }), /already-used/);

  const tables = database.tableNames();
  assert.deepEqual(tables, [
    "audit_events",
    "devices",
    "installations",
    "pairing_invitations",
    "settings",
    "webauthn_credentials",
  ]);
  for (const forbidden of ["messages", "threads", "turns", "transcripts", "commands"]) {
    assert.equal(tables.includes(forbidden), false);
  }
  database.close();
});

test("pairing invitations are short-lived and single use", async () => {
  const database = new RelayDatabase(":memory:");
  const bridge = await generateIdentity();
  const bootstrap = "another-bootstrap-token-at-least-thirty-two-characters";
  database.initializeBootstrap(bootstrap);
  database.claimInstallation({
    rawBootstrapToken: bootstrap,
    installationId: "installation_01",
    bridgeDeviceId: "bridge_device_01",
    bridgeIdentityPublicKey: bridge.publicKey,
    bridgeAccessToken: "bridge-access-token-with-at-least-thirty-two-characters",
    now: 1_000,
  });
  database.createPairingInvitation({
    id: "invite_00000001",
    installationId: "installation_01",
    tokenHash: hashSecret("pairing-token-with-at-least-thirty-two-characters"),
    now: 2_000,
    expiresAt: 302_000,
  });
  database.consumePairingInvitation({ id: "invite_00000001", installationId: "installation_01", now: 3_000 });
  assert.throws(() => database.consumePairingInvitation({ id: "invite_00000001", installationId: "installation_01", now: 4_000 }), /already used/);

  const phone = await generateIdentity();
  database.registerPhone({
    id: "phone_device_01",
    installationId: "installation_01",
    name: "Bhargava's iPhone",
    identityPublicKey: phone.publicKey,
    now: 5_000,
  });
  assert.equal(database.listDevices("installation_01").length, 2);
  assert.equal(database.revokeDevice("phone_device_01", "bridge_device_01", 6_000), true);
  assert.notEqual(database.getDevice("phone_device_01")?.revokedAt, null);
  database.close();
});
