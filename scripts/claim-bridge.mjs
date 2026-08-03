import { randomBytes, randomUUID } from "node:crypto";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { stdin } from "node:process";
import { generateIdentity } from "../src/security/e2ee.ts";

const relayOrigin = (process.env.CCHAT_PUBLIC_ORIGIN ?? "https://mycchat.win").replace(/\/$/, "");
const bootstrapToken = process.argv[2] === "--stdin"
  ? (await readStdin()).trim().split(/\r?\n/).at(-1)
  : process.argv[2];
if (!bootstrapToken || bootstrapToken.length < 32) {
  console.error("Usage: npm run bridge:claim -- <one-time-bootstrap-token>\n   or: <token-command> | npm run bridge:claim -- --stdin");
  process.exit(1);
}
const configDir = join(homedir(), ".config", "cchat");
const configPath = join(configDir, "remote.json");
const bridgeIdentity = await generateIdentity();
const config = {
  relayOrigin,
  installationId: `install_${randomUUID().replaceAll("-", "")}`,
  bridgeDeviceId: `bridge_${randomUUID().replaceAll("-", "")}`,
  bridgeIdentity,
  bridgeAccessToken: randomBytes(32).toString("base64url"),
};
const response = await fetch(`${relayOrigin}/api/v1/installations/claim`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ ...config, bridgeIdentityPublicKey: bridgeIdentity.publicKey, bootstrapToken, bridgeIdentity: undefined }),
});
if (!response.ok) {
  let message = `Relay returned ${response.status}`;
  try { message = String((await response.json()).error ?? message); } catch {}
  throw new Error(message);
}
await mkdir(configDir, { recursive: true, mode: 0o700 });
await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600, flag: "wx" });
await chmod(configPath, 0o600);
console.log(`Bridge claimed successfully. Configuration saved to ${configPath}`);
console.log("Restart the bridge with: systemctl --user restart cchat.service");

async function readStdin() {
  const chunks = [];
  for await (const chunk of stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}
