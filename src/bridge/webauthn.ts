import { randomBytes } from "node:crypto";
import { chmod, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";

type StoredCredential = {
  id: string;
  publicKey: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
};
type Store = { credentials: Record<string, StoredCredential[]> };
type Challenge = { value: string; expiresAt: number; purpose: "session" | "approval"; actionDigest?: string };

export class BridgeWebAuthn {
  private readonly path: string;
  private readonly origin: string;
  private readonly rpID: string;
  private store: Store;
  private registrationChallenges = new Map<string, { value: string; expiresAt: number }>();
  private authenticationChallenges = new Map<string, Challenge>();

  private constructor(path: string, origin: string, store: Store) {
    this.path = path;
    this.origin = origin;
    this.rpID = new URL(origin).hostname;
    this.store = store;
  }

  static async load(origin: string, path = join(homedir(), ".config", "cchat", "webauthn.json")): Promise<BridgeWebAuthn> {
    if (!origin.startsWith("https://") && !origin.startsWith("http://localhost")) throw new Error("Bridge WebAuthn requires HTTPS");
    let store: Store = { credentials: {} };
    try { store = JSON.parse(await readFile(path, "utf8")) as Store; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    return new BridgeWebAuthn(path, origin, store);
  }

  hasCredential(deviceId: string): boolean {
    return (this.store.credentials[deviceId]?.length ?? 0) > 0;
  }

  async registrationOptions(deviceId: string, name: string) {
    if (this.hasCredential(deviceId)) throw new Error("This phone already has a passkey");
    const options = await generateRegistrationOptions({
      rpName: "cchat",
      rpID: this.rpID,
      userID: new TextEncoder().encode(deviceId),
      userName: name,
      userDisplayName: name,
      attestationType: "none",
      timeout: 60_000,
      authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
      preferredAuthenticatorType: "localDevice",
      supportedAlgorithmIDs: [-7, -8],
    });
    this.registrationChallenges.set(deviceId, { value: options.challenge, expiresAt: Date.now() + 65_000 });
    return options;
  }

  async verifyRegistration(deviceId: string, response: RegistrationResponseJSON): Promise<void> {
    const challenge = this.takeRegistrationChallenge(deviceId);
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.registrationInfo?.userVerified) throw new Error("Passkey registration was not verified");
    const credential = verification.registrationInfo.credential;
    this.store.credentials[deviceId] = [{
      id: credential.id,
      publicKey: Buffer.from(credential.publicKey).toString("base64url"),
      counter: credential.counter,
      transports: response.response.transports ?? [],
    }];
    await this.persist();
  }

  async authenticationOptions(deviceId: string, purpose: "session" | "approval", actionDigest?: string) {
    const credentials = this.store.credentials[deviceId];
    if (!credentials?.length) throw new Error("This phone has no registered passkey");
    if (purpose === "approval" && !/^[A-Za-z0-9_-]{43}$/.test(actionDigest ?? "")) throw new Error("A valid action digest is required");
    const nonce = randomBytes(32);
    const options = await generateAuthenticationOptions({
      rpID: this.rpID,
      timeout: 60_000,
      userVerification: "required",
      challenge: nonce,
      allowCredentials: credentials.map((credential) => ({ id: credential.id, transports: credential.transports })),
    });
    this.authenticationChallenges.set(deviceId, { value: options.challenge, expiresAt: Date.now() + 65_000, purpose, actionDigest });
    return options;
  }

  async verifyAuthentication(deviceId: string, response: AuthenticationResponseJSON): Promise<{ purpose: "session" | "approval"; actionDigest?: string }> {
    const challenge = this.authenticationChallenges.get(deviceId);
    this.authenticationChallenges.delete(deviceId);
    if (!challenge || challenge.expiresAt < Date.now()) throw new Error("Passkey challenge is missing or expired");
    const credential = this.store.credentials[deviceId]?.find((candidate) => candidate.id === response.id);
    if (!credential) throw new Error("Unknown passkey credential");
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.value,
      expectedOrigin: this.origin,
      expectedRPID: this.rpID,
      requireUserVerification: true,
      credential: {
        id: credential.id,
        publicKey: Buffer.from(credential.publicKey, "base64url"),
        counter: credential.counter,
        transports: credential.transports,
      },
    });
    if (!verification.verified || !verification.authenticationInfo.userVerified) throw new Error("Passkey authentication was not verified");
    credential.counter = verification.authenticationInfo.newCounter;
    await this.persist();
    return { purpose: challenge.purpose, actionDigest: challenge.actionDigest };
  }

  revoke(deviceId: string): Promise<void> {
    delete this.store.credentials[deviceId];
    return this.persist();
  }

  private takeRegistrationChallenge(deviceId: string): string {
    const challenge = this.registrationChallenges.get(deviceId);
    this.registrationChallenges.delete(deviceId);
    if (!challenge || challenge.expiresAt < Date.now()) throw new Error("Registration challenge is missing or expired");
    return challenge.value;
  }

  private async persist(): Promise<void> {
    const temporary = `${this.path}.tmp`;
    await writeFile(temporary, `${JSON.stringify(this.store, null, 2)}\n`, { mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, this.path);
  }
}
