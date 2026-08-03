import QRCode from "qrcode";

const response = await fetch("http://127.0.0.1:4317/admin/pair", { method: "POST", headers: { "X-Cchat-CLI": "1" } });
if (!response.ok) {
  let message = `Local bridge returned ${response.status}`;
  try { message = String((await response.json()).error ?? message); } catch {}
  throw new Error(message);
}
const result = await response.json();
console.log(await QRCode.toString(result.pairingUrl, { type: "terminal", small: true }));
console.log("Open this one-time link on your phone within five minutes:");
console.log(result.pairingUrl);
