import assert from "node:assert/strict";
import test from "node:test";
import {
  acceptPhoneHello,
  createPairingRequest,
  createPhoneHello,
  finishPhoneHandshake,
  generateIdentity,
  generatePairingToken,
  verifyPairingRequest,
  verifyPhoneConfirmation,
  type EncryptedEnvelope,
} from "./e2ee.ts";

test("pairing proof binds the installation, devices, and identity keys", async () => {
  const bridge = await generateIdentity();
  const phone = await generateIdentity();
  const token = await generatePairingToken();
  const request = await createPairingRequest({
    pairingToken: token,
    installationId: "installation-a",
    phoneDeviceId: "phone-a",
    bridgeIdentityPublicKey: bridge.publicKey,
    phoneIdentityPublicKey: phone.publicKey,
  });
  assert.equal(await verifyPairingRequest(request, token), true);
  assert.equal(await verifyPairingRequest({ ...request, phoneDeviceId: "attacker" }, token), false);
});

test("authenticated ephemeral handshake derives matching directional keys", async () => {
  const bridge = await generateIdentity();
  const phone = await generateIdentity();
  const initiated = await createPhoneHello({
    installationId: "installation-a",
    phoneDeviceId: "phone-a",
    bridgeDeviceId: "bridge-a",
    phoneIdentity: phone,
    bridgeIdentityPublicKey: bridge.publicKey,
  });
  const accepted = await acceptPhoneHello({
    hello: initiated.hello,
    bridgeIdentity: bridge,
    expectedInstallationId: "installation-a",
    expectedBridgeDeviceId: "bridge-a",
    registeredPhoneIdentityPublicKey: phone.publicKey,
  });
  const finished = await finishPhoneHandshake({
    state: initiated.state,
    reply: accepted.reply,
    bridgeIdentityPublicKey: bridge.publicKey,
  });
  assert.equal(await verifyPhoneConfirmation(accepted.state, finished.confirmation), true);
  assert.equal(finished.channel.channelId, accepted.channel.channelId);

  const toBridge = finished.channel.encrypt("threads.list", { limit: 10 });
  assert.deepEqual(accepted.channel.decrypt(toBridge), { limit: 10 });
  const toPhone = accepted.channel.encrypt("threads.snapshot", { data: ["one"] });
  assert.deepEqual(finished.channel.decrypt(toPhone), { data: ["one"] });
});

test("tampering, replay, wrong direction, and identity substitution fail closed", async () => {
  const bridge = await generateIdentity();
  const phone = await generateIdentity();
  const attacker = await generateIdentity();
  const initiated = await createPhoneHello({
    installationId: "installation-a",
    phoneDeviceId: "phone-a",
    bridgeDeviceId: "bridge-a",
    phoneIdentity: phone,
    bridgeIdentityPublicKey: bridge.publicKey,
  });
  await assert.rejects(() => acceptPhoneHello({
    hello: initiated.hello,
    bridgeIdentity: bridge,
    expectedInstallationId: "installation-a",
    expectedBridgeDeviceId: "bridge-a",
    registeredPhoneIdentityPublicKey: attacker.publicKey,
  }), /identity binding/);

  const accepted = await acceptPhoneHello({
    hello: initiated.hello,
    bridgeIdentity: bridge,
    expectedInstallationId: "installation-a",
    expectedBridgeDeviceId: "bridge-a",
    registeredPhoneIdentityPublicKey: phone.publicKey,
  });
  const finished = await finishPhoneHandshake({
    state: initiated.state,
    reply: accepted.reply,
    bridgeIdentityPublicKey: bridge.publicKey,
  });
  const envelope = finished.channel.encrypt("turn.start", { text: "hello" });
  const tampered: EncryptedEnvelope = { ...envelope, messageType: "approval.resolve" };
  assert.throws(() => accepted.channel.decrypt(tampered));
  assert.deepEqual(accepted.channel.decrypt(envelope), { text: "hello" });
  assert.throws(() => accepted.channel.decrypt(envelope), /replayed or out of order/);
  assert.throws(() => finished.channel.decrypt({ ...envelope, counter: "1" }), /direction mismatch/);
});
