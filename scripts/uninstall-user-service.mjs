import { execFile } from "node:child_process";
import { unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const unitPath = join(homedir(), ".config", "systemd", "user", "cchat.service");

await run("systemctl", ["--user", "disable", "--now", "cchat.service"]).catch(() => {});
await unlink(unitPath).catch((error) => {
  if (error?.code !== "ENOENT") throw error;
});
await run("systemctl", ["--user", "daemon-reload"]);
console.log("Removed cchat.service. Preserved ~/.config/cchat/environment.");
