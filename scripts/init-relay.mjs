import { randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { RelayDatabase } from "../src/relay/database.ts";

const databasePath = resolve(process.argv[2] ?? process.env.CCHAT_RELAY_DB ?? "./data/relay.sqlite");
const token = randomBytes(32).toString("base64url");
const database = new RelayDatabase(databasePath);
const created = database.initializeBootstrap(token);
database.close();

if (!created) {
  console.error(`Relay database is already initialized: ${databasePath}`);
  process.exit(1);
}

console.log(`Initialized relay database: ${databasePath}`);
console.log("One-time bridge bootstrap token (store securely; it will not be shown again):");
console.log(token);
