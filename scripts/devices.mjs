const headers = { "X-Cchat-CLI": "1" };
const [command, phoneDeviceId] = process.argv.slice(2);
if (!command || command === "list") {
  const response = await fetch("http://127.0.0.1:4317/admin/devices", { headers });
  if (!response.ok) throw new Error(`Local bridge returned ${response.status}`);
  const devices = await response.json();
  if (devices.length === 0) console.log("No trusted phones.");
  else for (const device of devices) console.log(`${device.id}\t${device.name}`);
} else if (command === "revoke" && phoneDeviceId) {
  const response = await fetch("http://127.0.0.1:4317/admin/revoke", {
    method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify({ phoneDeviceId }),
  });
  if (!response.ok) throw new Error(String((await response.json()).error ?? `Local bridge returned ${response.status}`));
  console.log(`Revoked ${phoneDeviceId}`);
} else {
  console.error("Usage: npm run devices -- list\n   or: npm run devices -- revoke <phone-device-id>");
  process.exit(1);
}
