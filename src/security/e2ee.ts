import sodium from "libsodium-wrappers-sumo";

export type KeyPair = { publicKey: string; privateKey: string };
export type PairingRequest = {
  version: 1;
  installationId: string;
  phoneDeviceId: string;
  bridgeIdentityPublicKey: string;
  phoneIdentityPublicKey: string;
  proof: string;
};
export type PhoneHello = {
  version: 1;
  installationId: string;
  phoneDeviceId: string;
  bridgeDeviceId: string;
  phoneIdentityPublicKey: string;
  bridgeIdentityPublicKey: string;
  phoneEphemeralPublicKey: string;
  signature: string;
};
export type BridgeHello = {
  version: 1;
  bridgeEphemeralPublicKey: string;
  signature: string;
};
export type HandshakeConfirmation = { signature: string };
export type EncryptedEnvelope = {
  version: 1;
  channelId: string;
  direction: "phone-to-bridge" | "bridge-to-phone";
  counter: string;
  messageId: string;
  messageType: string;
  ciphertext: string;
};

type PhoneHandshakeState = {
  hello: PhoneHello;
  phoneIdentityPrivateKey: Uint8Array;
  phoneEphemeralPublicKey: Uint8Array;
  phoneEphemeralPrivateKey: Uint8Array;
};
type BridgeHandshakeState = {
  transcript: Uint8Array;
  phoneIdentityPublicKey: Uint8Array;
};

const b64Variant = () => sodium.base64_variants.URLSAFE_NO_PADDING;
const encode = (bytes: Uint8Array) => sodium.to_base64(bytes, b64Variant());
const decode = (value: string) => sodium.from_base64(value, b64Variant());
const text = (value: string) => sodium.from_string(value);

export async function initializeCrypto(): Promise<void> {
  await sodium.ready;
}

export async function generateIdentity(): Promise<KeyPair> {
  await initializeCrypto();
  const keys = sodium.crypto_sign_keypair();
  return { publicKey: encode(keys.publicKey), privateKey: encode(keys.privateKey) };
}

export async function generatePairingToken(): Promise<string> {
  await initializeCrypto();
  return encode(sodium.randombytes_buf(sodium.crypto_auth_KEYBYTES));
}

export async function createPairingRequest(params: {
  pairingToken: string;
  installationId: string;
  phoneDeviceId: string;
  bridgeIdentityPublicKey: string;
  phoneIdentityPublicKey: string;
}): Promise<PairingRequest> {
  await initializeCrypto();
  const transcript = pairingTranscript(params);
  return {
    version: 1,
    installationId: params.installationId,
    phoneDeviceId: params.phoneDeviceId,
    bridgeIdentityPublicKey: params.bridgeIdentityPublicKey,
    phoneIdentityPublicKey: params.phoneIdentityPublicKey,
    proof: encode(sodium.crypto_auth(transcript, decode(params.pairingToken))),
  };
}

export async function verifyPairingRequest(request: PairingRequest, pairingToken: string): Promise<boolean> {
  await initializeCrypto();
  if (request.version !== 1) return false;
  return sodium.crypto_auth_verify(
    decode(request.proof),
    pairingTranscript(request),
    decode(pairingToken),
  );
}

export async function createPhoneHello(params: {
  installationId: string;
  phoneDeviceId: string;
  bridgeDeviceId: string;
  phoneIdentity: KeyPair;
  bridgeIdentityPublicKey: string;
}): Promise<{ state: PhoneHandshakeState; hello: PhoneHello }> {
  await initializeCrypto();
  const ephemeral = sodium.crypto_kx_keypair();
  const unsigned = {
    version: 1 as const,
    installationId: params.installationId,
    phoneDeviceId: params.phoneDeviceId,
    bridgeDeviceId: params.bridgeDeviceId,
    phoneIdentityPublicKey: params.phoneIdentity.publicKey,
    bridgeIdentityPublicKey: params.bridgeIdentityPublicKey,
    phoneEphemeralPublicKey: encode(ephemeral.publicKey),
  };
  const signature = sodium.crypto_sign_detached(phoneHelloTranscript(unsigned), decode(params.phoneIdentity.privateKey));
  const hello: PhoneHello = { ...unsigned, signature: encode(signature) };
  return {
    hello,
    state: {
      hello,
      phoneIdentityPrivateKey: decode(params.phoneIdentity.privateKey),
      phoneEphemeralPublicKey: ephemeral.publicKey,
      phoneEphemeralPrivateKey: ephemeral.privateKey,
    },
  };
}

export async function acceptPhoneHello(params: {
  hello: PhoneHello;
  bridgeIdentity: KeyPair;
  expectedInstallationId: string;
  expectedBridgeDeviceId: string;
  registeredPhoneIdentityPublicKey: string;
}): Promise<{
  state: BridgeHandshakeState;
  reply: BridgeHello;
  channel: EncryptedChannel;
}> {
  await initializeCrypto();
  const { hello } = params;
  if (hello.version !== 1 ||
      hello.installationId !== params.expectedInstallationId ||
      hello.bridgeDeviceId !== params.expectedBridgeDeviceId ||
      hello.bridgeIdentityPublicKey !== params.bridgeIdentity.publicKey ||
      hello.phoneIdentityPublicKey !== params.registeredPhoneIdentityPublicKey) {
    throw new Error("Handshake identity binding failed");
  }
  if (!sodium.crypto_sign_verify_detached(
    decode(hello.signature),
    phoneHelloTranscript(hello),
    decode(params.registeredPhoneIdentityPublicKey),
  )) throw new Error("Invalid phone handshake signature");

  const ephemeral = sodium.crypto_kx_keypair();
  const transcript = sessionTranscript(hello, encode(ephemeral.publicKey));
  const signature = sodium.crypto_sign_detached(transcript, decode(params.bridgeIdentity.privateKey));
  const sessionKeys = sodium.crypto_kx_server_session_keys(
    ephemeral.publicKey,
    ephemeral.privateKey,
    decode(hello.phoneEphemeralPublicKey),
  );
  return {
    state: { transcript, phoneIdentityPublicKey: decode(params.registeredPhoneIdentityPublicKey) },
    reply: { version: 1, bridgeEphemeralPublicKey: encode(ephemeral.publicKey), signature: encode(signature) },
    channel: new EncryptedChannel({
      channelId: channelId(transcript),
      sendKey: sessionKeys.sharedTx,
      receiveKey: sessionKeys.sharedRx,
      sendDirection: "bridge-to-phone",
    }),
  };
}

export async function finishPhoneHandshake(params: {
  state: PhoneHandshakeState;
  reply: BridgeHello;
  bridgeIdentityPublicKey: string;
}): Promise<{ confirmation: HandshakeConfirmation; channel: EncryptedChannel }> {
  await initializeCrypto();
  if (params.reply.version !== 1) throw new Error("Unsupported handshake version");
  const transcript = sessionTranscript(params.state.hello, params.reply.bridgeEphemeralPublicKey);
  if (!sodium.crypto_sign_verify_detached(
    decode(params.reply.signature),
    transcript,
    decode(params.bridgeIdentityPublicKey),
  )) throw new Error("Invalid bridge handshake signature");
  const sessionKeys = sodium.crypto_kx_client_session_keys(
    params.state.phoneEphemeralPublicKey,
    params.state.phoneEphemeralPrivateKey,
    decode(params.reply.bridgeEphemeralPublicKey),
  );
  return {
    confirmation: { signature: encode(sodium.crypto_sign_detached(transcript, params.state.phoneIdentityPrivateKey)) },
    channel: new EncryptedChannel({
      channelId: channelId(transcript),
      sendKey: sessionKeys.sharedTx,
      receiveKey: sessionKeys.sharedRx,
      sendDirection: "phone-to-bridge",
    }),
  };
}

export async function verifyPhoneConfirmation(state: BridgeHandshakeState, confirmation: HandshakeConfirmation): Promise<boolean> {
  await initializeCrypto();
  return sodium.crypto_sign_verify_detached(
    decode(confirmation.signature),
    state.transcript,
    state.phoneIdentityPublicKey,
  );
}

export class EncryptedChannel {
  readonly channelId: string;
  private readonly sendKey: Uint8Array;
  private readonly receiveKey: Uint8Array;
  private readonly sendDirection: EncryptedEnvelope["direction"];
  private sendCounter = 0n;
  private receiveCounter = -1n;

  constructor(params: {
    channelId: string;
    sendKey: Uint8Array;
    receiveKey: Uint8Array;
    sendDirection: EncryptedEnvelope["direction"];
  }) {
    this.channelId = params.channelId;
    this.sendKey = params.sendKey;
    this.receiveKey = params.receiveKey;
    this.sendDirection = params.sendDirection;
  }

  encrypt(messageType: string, payload: unknown): EncryptedEnvelope {
    if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(messageType)) throw new Error("Invalid encrypted message type");
    const counter = this.sendCounter++;
    const messageId = encode(sodium.randombytes_buf(16));
    const header = {
      version: 1 as const,
      channelId: this.channelId,
      direction: this.sendDirection,
      counter: counter.toString(),
      messageId,
      messageType,
    };
    const plaintext = text(JSON.stringify(payload));
    const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      envelopeAad(header),
      null,
      nonce(counter),
      this.sendKey,
    );
    return { ...header, ciphertext: encode(ciphertext) };
  }

  decrypt(envelope: EncryptedEnvelope): unknown {
    if (envelope.version !== 1 || envelope.channelId !== this.channelId) throw new Error("Encrypted channel mismatch");
    const expectedDirection = this.sendDirection === "phone-to-bridge" ? "bridge-to-phone" : "phone-to-bridge";
    if (envelope.direction !== expectedDirection) throw new Error("Encrypted direction mismatch");
    const counter = parseCounter(envelope.counter);
    if (counter !== this.receiveCounter + 1n) throw new Error("Encrypted message replayed or out of order");
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      decode(envelope.ciphertext),
      envelopeAad(envelope),
      nonce(counter),
      this.receiveKey,
    );
    const parsed = JSON.parse(sodium.to_string(plaintext));
    this.receiveCounter = counter;
    return parsed;
  }
}

function pairingTranscript(params: {
  installationId: string;
  phoneDeviceId: string;
  bridgeIdentityPublicKey: string;
  phoneIdentityPublicKey: string;
}): Uint8Array {
  return frame("cchat-pairing-v1", params.installationId, params.phoneDeviceId, params.bridgeIdentityPublicKey, params.phoneIdentityPublicKey);
}

function phoneHelloTranscript(hello: Omit<PhoneHello, "signature"> | PhoneHello): Uint8Array {
  return frame(
    "cchat-phone-hello-v1",
    hello.installationId,
    hello.phoneDeviceId,
    hello.bridgeDeviceId,
    hello.phoneIdentityPublicKey,
    hello.bridgeIdentityPublicKey,
    hello.phoneEphemeralPublicKey,
  );
}

function sessionTranscript(hello: PhoneHello, bridgeEphemeralPublicKey: string): Uint8Array {
  return frame(
    "cchat-session-v1",
    hello.installationId,
    hello.phoneDeviceId,
    hello.bridgeDeviceId,
    hello.phoneIdentityPublicKey,
    hello.bridgeIdentityPublicKey,
    hello.phoneEphemeralPublicKey,
    bridgeEphemeralPublicKey,
  );
}

function frame(...values: string[]): Uint8Array {
  const encoded = values.map(text);
  const size = encoded.reduce((total, value) => total + 4 + value.length, 0);
  const output = new Uint8Array(size);
  const view = new DataView(output.buffer);
  let offset = 0;
  for (const value of encoded) {
    view.setUint32(offset, value.length, false);
    offset += 4;
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

function channelId(transcript: Uint8Array): string {
  return encode(sodium.crypto_generichash(16, transcript, null));
}

function envelopeAad(envelope: Omit<EncryptedEnvelope, "ciphertext"> | EncryptedEnvelope): Uint8Array {
  return frame(
    "cchat-envelope-v1",
    envelope.channelId,
    envelope.direction,
    envelope.counter,
    envelope.messageId,
    envelope.messageType,
  );
}

function nonce(counter: bigint): Uint8Array {
  if (counter < 0n || counter > 0xffff_ffff_ffff_ffffn) throw new Error("Encrypted counter exhausted");
  const output = new Uint8Array(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  new DataView(output.buffer).setBigUint64(output.length - 8, counter, false);
  return output;
}

function parseCounter(value: string): bigint {
  if (!/^(0|[1-9][0-9]{0,19})$/.test(value)) throw new Error("Invalid encrypted counter");
  const counter = BigInt(value);
  if (counter > 0xffff_ffff_ffff_ffffn) throw new Error("Invalid encrypted counter");
  return counter;
}
