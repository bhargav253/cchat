import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { WebSocket } from "ws";
import { createPairingRequest, generateIdentity, generatePairingToken, verifyPairingRequest } from "../security/e2ee.ts";
import { hashSecret, RelayDatabase } from "./database.ts";

test("relay pairs a phone only after the authenticated bridge approves its proof", async (context) => {
  const directory = await mkdtemp(join(tmpdir(), "cchat-relay-test-"));
  const databasePath = join(directory, "relay.sqlite");
  const bootstrapToken = randomBytes(32).toString("base64url");
  const database = new RelayDatabase(databasePath);
  database.initializeBootstrap(bootstrapToken);
  database.close();
  const port = 20_000 + Math.floor(Math.random() * 20_000);
  const origin = "https://cchat.test";
  const relayProcess = spawn(process.execPath, [join(process.cwd(), "src/relay/server.ts")], {
    env: { ...process.env, CCHAT_RELAY_DB: databasePath, CCHAT_RELAY_PORT: String(port), CCHAT_PUBLIC_ORIGIN: origin },
    stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(async () => {
    relayProcess.kill("SIGTERM");
    await new Promise((resolve) => relayProcess.once("exit", resolve));
    await rm(directory, { recursive: true, force: true });
  });
  await waitForHealth(`http://127.0.0.1:${port}/healthz`);

  const bridgeIdentity = await generateIdentity();
  const installationId = `install_${randomUUID().replaceAll("-", "")}`;
  const bridgeDeviceId = `bridge_${randomUUID().replaceAll("-", "")}`;
  const accessToken = randomBytes(32).toString("base64url");
  assert.equal((await fetch(`http://127.0.0.1:${port}/api/v1/installations/claim`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
      bootstrapToken, installationId, bridgeDeviceId,
      bridgeIdentityPublicKey: bridgeIdentity.publicKey, bridgeAccessToken: accessToken,
    }),
  })).status, 201);

  const bridge = await openSocket(`ws://127.0.0.1:${port}/api/v1/connect`, origin);
  bridge.send(JSON.stringify({ type: "bridge.authenticate", installationId, bridgeDeviceId, accessToken }));
  assert.equal((await nextMessage(bridge)).type, "bridge.authenticated");

  const invitationId = `invite_${randomUUID().replaceAll("-", "")}`;
  const pairingToken = await generatePairingToken();
  assert.equal((await fetch(`http://127.0.0.1:${port}/api/v1/pairing/invitations`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify({ invitationId, installationId, bridgeDeviceId, tokenHash: hashSecret(pairingToken) }),
  })).status, 201);

  const phoneIdentity = await generateIdentity();
  const phoneDeviceId = `phone_${randomUUID().replaceAll("-", "")}`;
  const request = await createPairingRequest({
    pairingToken, installationId, phoneDeviceId,
    bridgeIdentityPublicKey: bridgeIdentity.publicKey,
    phoneIdentityPublicKey: phoneIdentity.publicKey,
  });
  const phone = await openSocket(`ws://127.0.0.1:${port}/api/v1/connect`, origin);
  phone.send(JSON.stringify({ type: "phone.pair", invitationId, name: "Test phone", request }));
  const routed = await nextMessage(bridge);
  assert.equal(routed.type, "pairing.request");
  assert.equal(await verifyPairingRequest(routed.request as typeof request, pairingToken), true);
  bridge.send(JSON.stringify({
    type: "pairing.approve", connectionId: routed.connectionId, invitationId,
    phoneDeviceId, phoneIdentityPublicKey: phoneIdentity.publicKey, name: "Test phone",
  }));
  assert.equal((await nextMessage(phone)).type, "pairing.complete");
  bridge.close();

  const check = new RelayDatabase(databasePath);
  assert.equal(check.getDevice(phoneDeviceId)?.identityPublicKey, phoneIdentity.publicKey);
  assert.notEqual(check.getPairingInvitation(invitationId)?.usedAt, null);
  check.close();
});

async function waitForHealth(url: string): Promise<void> {
  for (let attempt = 0; attempt < 40; attempt++) {
    try { if ((await fetch(url)).ok) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("Relay did not become healthy");
}

function openSocket(url: string, origin: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, { origin });
    socket.once("open", () => resolve(socket));
    socket.once("error", reject);
  });
}

function nextMessage(socket: WebSocket): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Timed out waiting for WebSocket message")), 2_000);
    socket.once("message", (raw) => { clearTimeout(timeout); resolve(JSON.parse(raw.toString()) as Record<string, unknown>); });
  });
}
