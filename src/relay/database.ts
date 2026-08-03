import { createHash, timingSafeEqual } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

export type DeviceKind = "bridge" | "phone";
export type DeviceRecord = {
  id: string;
  installationId: string;
  kind: DeviceKind;
  name: string;
  identityPublicKey: string;
  createdAt: number;
  lastSeenAt: number | null;
  revokedAt: number | null;
};

export class RelayDatabase {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ":memory:") chmodSync(path, 0o600);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      PRAGMA secure_delete = ON;
      PRAGMA busy_timeout = 5000;

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS installations (
        id TEXT PRIMARY KEY,
        bridge_device_id TEXT NOT NULL UNIQUE,
        bridge_identity_public_key TEXT NOT NULL,
        created_at INTEGER NOT NULL
      ) STRICT;

      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('bridge', 'phone')),
        name TEXT NOT NULL,
        identity_public_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        revoked_at INTEGER,
        UNIQUE (installation_id, identity_public_key)
      ) STRICT;

      CREATE TABLE IF NOT EXISTS pairing_invitations (
        id TEXT PRIMARY KEY,
        installation_id TEXT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
      ) STRICT;

      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        actor_device_id TEXT,
        target_device_id TEXT,
        outcome TEXT NOT NULL,
        metadata TEXT NOT NULL
      ) STRICT;

      CREATE INDEX IF NOT EXISTS devices_installation_idx ON devices(installation_id);
      CREATE INDEX IF NOT EXISTS pairing_expiry_idx ON pairing_invitations(expires_at);
      CREATE INDEX IF NOT EXISTS audit_time_idx ON audit_events(occurred_at);

      DROP TABLE IF EXISTS webauthn_credentials;
    `);
  }

  close(): void {
    this.db.close();
  }

  initializeBootstrap(rawToken: string): boolean {
    validateSecret(rawToken);
    const existing = this.db.prepare("SELECT value FROM settings WHERE key = 'bootstrap_token_hash'").get();
    if (existing) return false;
    this.db.prepare("INSERT INTO settings (key, value) VALUES ('bootstrap_token_hash', ?)").run(hashSecret(rawToken));
    return true;
  }

  claimInstallation(params: {
    rawBootstrapToken: string;
    installationId: string;
    bridgeDeviceId: string;
    bridgeIdentityPublicKey: string;
    bridgeAccessToken: string;
    now?: number;
  }): void {
    validateId(params.installationId, "installationId");
    validateId(params.bridgeDeviceId, "bridgeDeviceId");
    validatePublicKey(params.bridgeIdentityPublicKey);
    const now = params.now ?? Date.now();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.db.prepare("SELECT value FROM settings WHERE key = 'bootstrap_token_hash'").get() as { value: string } | undefined;
      if (!row || !secretMatches(params.rawBootstrapToken, row.value)) throw new Error("Invalid or already-used bootstrap token");
      this.db.prepare(`
        INSERT INTO installations (id, bridge_device_id, bridge_identity_public_key, created_at)
        VALUES (?, ?, ?, ?)
      `).run(params.installationId, params.bridgeDeviceId, params.bridgeIdentityPublicKey, now);
      this.db.prepare(`
        INSERT INTO devices (id, installation_id, kind, name, identity_public_key, created_at)
        VALUES (?, ?, 'bridge', 'Ubuntu bridge', ?, ?)
      `).run(params.bridgeDeviceId, params.installationId, params.bridgeIdentityPublicKey, now);
      validateSecret(params.bridgeAccessToken);
      this.db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)")
        .run(`bridge_access_token_hash:${params.installationId}`, hashSecret(params.bridgeAccessToken));
      this.db.prepare("DELETE FROM settings WHERE key = 'bootstrap_token_hash'").run();
      this.addAudit("installation.claimed", params.bridgeDeviceId, params.bridgeDeviceId, "success", {}, now);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  authenticateBridge(installationId: string, bridgeDeviceId: string, rawAccessToken: string): DeviceRecord | null {
    const device = this.getDevice(bridgeDeviceId);
    if (!device || device.kind !== "bridge" || device.installationId !== installationId || device.revokedAt !== null) return null;
    const row = this.db.prepare("SELECT value FROM settings WHERE key = ?")
      .get(`bridge_access_token_hash:${installationId}`) as { value: string } | undefined;
    return row && secretMatches(rawAccessToken, row.value) ? device : null;
  }

  createPairingInvitation(params: {
    id: string;
    installationId: string;
    tokenHash: string;
    expiresAt: number;
    now?: number;
  }): void {
    validateId(params.id, "invitationId");
    validateId(params.installationId, "installationId");
    if (!/^[a-f0-9]{64}$/.test(params.tokenHash)) throw new Error("Invalid pairing token hash");
    const now = params.now ?? Date.now();
    if (params.expiresAt <= now || params.expiresAt > now + 10 * 60_000) throw new Error("Pairing invitation expiry must be within ten minutes");
    this.db.prepare(`
      INSERT INTO pairing_invitations (id, installation_id, token_hash, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(params.id, params.installationId, params.tokenHash, now, params.expiresAt);
  }

  getPairingInvitation(id: string): {
    id: string;
    installationId: string;
    bridgeDeviceId: string;
    bridgeIdentityPublicKey: string;
    expiresAt: number;
    usedAt: number | null;
  } | null {
    const row = this.db.prepare(`
      SELECT p.id, p.installation_id, p.expires_at, p.used_at,
             i.bridge_device_id, i.bridge_identity_public_key
      FROM pairing_invitations p
      JOIN installations i ON i.id = p.installation_id
      WHERE p.id = ?
    `).get(id) as Record<string, unknown> | undefined;
    return row ? {
      id: String(row.id),
      installationId: String(row.installation_id),
      bridgeDeviceId: String(row.bridge_device_id),
      bridgeIdentityPublicKey: String(row.bridge_identity_public_key),
      expiresAt: Number(row.expires_at),
      usedAt: row.used_at === null ? null : Number(row.used_at),
    } : null;
  }

  completePairing(params: {
    invitationId: string;
    installationId: string;
    phoneDeviceId: string;
    phoneName: string;
    phoneIdentityPublicKey: string;
    now?: number;
  }): void {
    const now = params.now ?? Date.now();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.consumePairingInvitation({ id: params.invitationId, installationId: params.installationId, now });
      this.registerPhone({
        id: params.phoneDeviceId,
        installationId: params.installationId,
        name: params.phoneName,
        identityPublicKey: params.phoneIdentityPublicKey,
        now,
      });
      this.addAudit("device.paired", params.phoneDeviceId, params.phoneDeviceId, "success", {}, now);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  consumePairingInvitation(params: {
    id: string;
    installationId: string;
    now?: number;
  }): void {
    const now = params.now ?? Date.now();
    const result = this.db.prepare(`
      UPDATE pairing_invitations
      SET used_at = ?
      WHERE id = ? AND installation_id = ? AND used_at IS NULL AND expires_at >= ?
    `).run(now, params.id, params.installationId, now);
    if (result.changes !== 1) throw new Error("Pairing invitation is invalid, expired, or already used");
  }

  registerPhone(params: {
    id: string;
    installationId: string;
    name: string;
    identityPublicKey: string;
    now?: number;
  }): void {
    validateId(params.id, "deviceId");
    validateId(params.installationId, "installationId");
    validatePublicKey(params.identityPublicKey);
    if (!params.name.trim() || params.name.length > 80) throw new Error("Invalid device name");
    const now = params.now ?? Date.now();
    this.db.prepare(`
      INSERT INTO devices (id, installation_id, kind, name, identity_public_key, created_at)
      VALUES (?, ?, 'phone', ?, ?, ?)
    `).run(params.id, params.installationId, params.name.trim(), params.identityPublicKey, now);
  }

  getDevice(id: string): DeviceRecord | null {
    const row = this.db.prepare(`
      SELECT id, installation_id, kind, name, identity_public_key, created_at, last_seen_at, revoked_at
      FROM devices WHERE id = ?
    `).get(id) as Record<string, unknown> | undefined;
    return row ? mapDevice(row) : null;
  }

  listDevices(installationId: string): DeviceRecord[] {
    return (this.db.prepare(`
      SELECT id, installation_id, kind, name, identity_public_key, created_at, last_seen_at, revoked_at
      FROM devices WHERE installation_id = ? ORDER BY created_at ASC
    `).all(installationId) as Record<string, unknown>[]).map(mapDevice);
  }

  touchDevice(id: string, now = Date.now()): boolean {
    return this.db.prepare("UPDATE devices SET last_seen_at = ? WHERE id = ? AND revoked_at IS NULL").run(now, id).changes === 1;
  }

  revokeDevice(id: string, actorDeviceId: string, now = Date.now()): boolean {
    const result = this.db.prepare("UPDATE devices SET revoked_at = ? WHERE id = ? AND kind = 'phone' AND revoked_at IS NULL").run(now, id);
    if (result.changes === 1) this.addAudit("device.revoked", actorDeviceId, id, "success", {}, now);
    return result.changes === 1;
  }

  purgeExpired(now = Date.now()): { invitations: number; auditEvents: number } {
    const invitations = this.db.prepare("DELETE FROM pairing_invitations WHERE expires_at < ?").run(now).changes;
    const auditEvents = this.db.prepare("DELETE FROM audit_events WHERE occurred_at < ?").run(now - 30 * 24 * 60 * 60_000).changes;
    return { invitations: Number(invitations), auditEvents: Number(auditEvents) };
  }

  tableNames(): string[] {
    return (this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as { name: string }[]).map((row) => row.name);
  }

  private addAudit(
    eventType: string,
    actorDeviceId: string | null,
    targetDeviceId: string | null,
    outcome: string,
    metadata: Record<string, string | number | boolean>,
    now: number,
  ): void {
    this.db.prepare(`
      INSERT INTO audit_events (occurred_at, event_type, actor_device_id, target_device_id, outcome, metadata)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(now, eventType, actorDeviceId, targetDeviceId, outcome, JSON.stringify(metadata));
  }
}

export function hashSecret(raw: string): string {
  validateSecret(raw);
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

function secretMatches(raw: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashSecret(raw), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function validateSecret(value: string): void {
  if (value.length < 32 || value.length > 1024) throw new Error("Secret must contain at least 32 characters");
}

function validateId(value: string, name: string): void {
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(value)) throw new Error(`Invalid ${name}`);
}

function validatePublicKey(value: string): void {
  if (!/^[A-Za-z0-9_-]{40,128}$/.test(value)) throw new Error("Invalid public key encoding");
}

function mapDevice(row: Record<string, unknown>): DeviceRecord {
  return {
    id: String(row.id),
    installationId: String(row.installation_id),
    kind: row.kind as DeviceKind,
    name: String(row.name),
    identityPublicKey: String(row.identity_public_key),
    createdAt: Number(row.created_at),
    lastSeenAt: row.last_seen_at === null ? null : Number(row.last_seen_at),
    revokedAt: row.revoked_at === null ? null : Number(row.revoked_at),
  };
}
