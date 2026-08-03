import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { RelayDatabase } from "./database.ts";

type Challenge = { value: string; expiresAt: number };

export class WebAuthnService {
  private readonly registrationChallenges = new Map<string, Challenge>();
  private readonly authenticationChallenges = new Map<string, Challenge>();
  private readonly database: RelayDatabase;
  private readonly config: { rpName: string; rpID: string; expectedOrigin: string };

  constructor(
    database: RelayDatabase,
    config: { rpName: string; rpID: string; expectedOrigin: string },
  ) {
    if (!config.expectedOrigin.startsWith("https://") && !config.expectedOrigin.startsWith("http://localhost")) {
      throw new Error("WebAuthn requires an HTTPS origin outside localhost");
    }
    this.database = database;
    this.config = config;
  }

  async registrationOptions(deviceId: string): Promise<Awaited<ReturnType<typeof generateRegistrationOptions>>> {
    const device = this.requireActivePhone(deviceId);
    const existing = this.database.listWebAuthnCredentials(deviceId);
    const options = await generateRegistrationOptions({
      rpName: this.config.rpName,
      rpID: this.config.rpID,
      userID: new TextEncoder().encode(deviceId),
      userName: device.name,
      userDisplayName: device.name,
      attestationType: "none",
      timeout: 60_000,
      excludeCredentials: existing.map((credential) => ({
        id: credential.id,
        transports: credential.transports as AuthenticatorTransportFuture[],
      })),
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
      preferredAuthenticatorType: "localDevice",
      supportedAlgorithmIDs: [-7, -8],
    });
    this.registrationChallenges.set(deviceId, { value: options.challenge, expiresAt: Date.now() + 65_000 });
    return options;
  }

  async verifyRegistration(deviceId: string, response: RegistrationResponseJSON): Promise<void> {
    this.requireActivePhone(deviceId);
    const challenge = takeChallenge(this.registrationChallenges, deviceId);
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: this.config.expectedOrigin,
      expectedRPID: this.config.rpID,
      requireUserVerification: true,
    });
    if (!verification.verified || !verification.registrationInfo?.userVerified) throw new Error("Face ID registration was not verified");
    const { credential, credentialBackedUp } = verification.registrationInfo;
    this.database.addWebAuthnCredential({
      credentialId: credential.id,
      deviceId,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: response.response.transports ?? [],
      backedUp: credentialBackedUp,
    });
  }

  async authenticationOptions(deviceId: string): Promise<Awaited<ReturnType<typeof generateAuthenticationOptions>>> {
    this.requireActivePhone(deviceId);
    const credentials = this.database.listWebAuthnCredentials(deviceId);
    if (credentials.length === 0) throw new Error("No Face ID credential is registered for this device");
    const options = await generateAuthenticationOptions({
      rpID: this.config.rpID,
      timeout: 60_000,
      userVerification: "required",
      allowCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: credential.transports as AuthenticatorTransportFuture[],
      })),
    });
    this.authenticationChallenges.set(deviceId, { value: options.challenge, expiresAt: Date.now() + 65_000 });
    return options;
  }

  async verifyAuthentication(deviceId: string, response: AuthenticationResponseJSON): Promise<void> {
    this.requireActivePhone(deviceId);
    const challenge = takeChallenge(this.authenticationChallenges, deviceId);
    const credential = this.database.getWebAuthnCredential(response.id);
    if (!credential || credential.deviceId !== deviceId) throw new Error("Unknown Face ID credential");
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: this.config.expectedOrigin,
      expectedRPID: this.config.rpID,
      requireUserVerification: true,
      credential: {
        id: credential.id,
        publicKey: new Uint8Array(credential.publicKey),
        counter: credential.counter,
        transports: credential.transports as AuthenticatorTransportFuture[],
      },
    });
    if (!verification.verified || !verification.authenticationInfo.userVerified) throw new Error("Face ID authentication was not verified");
    this.database.updateWebAuthnCounter(credential.id, verification.authenticationInfo.newCounter);
  }

  private requireActivePhone(deviceId: string) {
    const device = this.database.getDevice(deviceId);
    if (!device || device.kind !== "phone" || device.revokedAt !== null) throw new Error("Unknown or revoked phone");
    return device;
  }
}

function takeChallenge(challenges: Map<string, Challenge>, deviceId: string): string {
  const challenge = challenges.get(deviceId);
  challenges.delete(deviceId);
  if (!challenge || challenge.expiresAt < Date.now()) throw new Error("WebAuthn challenge is missing or expired");
  return challenge.value;
}
