import { execFile } from "node:child_process";
import { mkdir, writeFile, access } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const dryRun = process.argv.includes("--dry-run");
const projectDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const configDir = join(homedir(), ".config", "cchat");
const userUnitDir = join(homedir(), ".config", "systemd", "user");
const environmentPath = join(configDir, "environment");
const unitPath = join(userUnitDir, "cchat.service");
const codexPath = (await run("which", ["codex"])).stdout.trim();
const servicePath = [...new Set([
  dirname(process.execPath),
  dirname(codexPath),
  "/usr/local/bin",
  "/usr/bin",
  "/bin",
])].join(":");

function systemdQuote(value) {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"').replaceAll("%", "%%")}"`;
}

function systemdPath(value) {
  // Path-valued directives do not strip quotes the same way command lines do.
  // Escape whitespace and specifier markers instead of quoting the whole path.
  return value
    .replaceAll("\\", "\\x5c")
    .replaceAll(" ", "\\x20")
    .replaceAll("\t", "\\x09")
    .replaceAll("%", "%%");
}

const unit = `[Unit]
Description=cchat local Codex bridge
Documentation=https://github.com/bhargav253/cchat
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${systemdPath(projectDir)}
ExecStart=${systemdQuote(process.execPath)} ${systemdQuote(join(projectDir, "src", "server.ts"))}
Environment="NODE_ENV=production"
Environment=${systemdQuote(`PATH=${servicePath}`)}
Environment=${systemdQuote(`CCHAT_CODEX_BIN=${codexPath}`)}
EnvironmentFile=-%h/.config/cchat/environment
Restart=on-failure
RestartSec=3
TimeoutStopSec=5
KillMode=mixed
NoNewPrivileges=true
UMask=0077

[Install]
WantedBy=default.target
`;

if (dryRun) {
  process.stdout.write(unit);
  process.exit(0);
}

await mkdir(configDir, { recursive: true, mode: 0o700 });
await mkdir(userUnitDir, { recursive: true, mode: 0o700 });
try {
  await access(environmentPath);
} catch {
  await writeFile(environmentPath, [
    "# Optional cchat overrides. Values use systemd EnvironmentFile syntax.",
    `CCHAT_DEFAULT_CWD=${projectDir}`,
    "CCHAT_HOST=127.0.0.1",
    "CCHAT_PORT=4317",
    "CCHAT_CODEX_URL=ws://127.0.0.1:4500",
    "",
  ].join("\n"), { mode: 0o600 });
}
await writeFile(unitPath, unit, { mode: 0o600 });
await run("systemctl", ["--user", "daemon-reload"]);
await run("systemctl", ["--user", "enable", "--now", "cchat.service"]);

console.log(`Installed and started ${unitPath}`);
console.log(`Configuration: ${environmentPath}`);
console.log("Status: systemctl --user status cchat.service");
