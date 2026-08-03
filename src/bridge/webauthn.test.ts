import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BridgeWebAuthn } from "./webauthn.ts";

test("bridge owns passkey challenges and requires local user verification", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cchat-webauthn-"));
  try {
    const service = await BridgeWebAuthn.load("https://mycchat.win", join(directory, "webauthn.json"));
    const options = await service.registrationOptions("phone_device_01", "Test phone");
    assert.equal(options.authenticatorSelection?.userVerification, "required");
    assert.equal(options.authenticatorSelection?.residentKey, "required");
    assert.equal(options.attestation, "none");
    await assert.rejects(() => service.authenticationOptions("phone_device_01", "session"), /no registered passkey/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("bridge WebAuthn refuses an insecure production origin", async () => {
  await assert.rejects(() => BridgeWebAuthn.load("http://mycchat.win"), /requires HTTPS/);
});
