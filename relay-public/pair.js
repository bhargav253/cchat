// node_modules/@simplewebauthn/browser/esm/helpers/bufferToBase64URLString.js
function bufferToBase64URLString(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = "";
  for (const charCode of bytes) {
    str += String.fromCharCode(charCode);
  }
  const base64String = btoa(str);
  return base64String.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// node_modules/@simplewebauthn/browser/esm/helpers/base64URLStringToBuffer.js
function base64URLStringToBuffer(base64URLString) {
  const base64 = base64URLString.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - base64.length % 4) % 4;
  const padded = base64.padEnd(base64.length + padLength, "=");
  const binary = atob(padded);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return buffer;
}

// node_modules/@simplewebauthn/browser/esm/helpers/browserSupportsWebAuthn.js
function browserSupportsWebAuthn() {
  return _browserSupportsWebAuthnInternals.stubThis(globalThis?.PublicKeyCredential !== void 0 && typeof globalThis.PublicKeyCredential === "function");
}
var _browserSupportsWebAuthnInternals = {
  stubThis: (value) => value
};

// node_modules/@simplewebauthn/browser/esm/helpers/toPublicKeyCredentialDescriptor.js
function toPublicKeyCredentialDescriptor(descriptor) {
  const { id } = descriptor;
  return {
    ...descriptor,
    id: base64URLStringToBuffer(id),
    /**
     * `descriptor.transports` is an array of our `AuthenticatorTransportFuture` that includes newer
     * transports that TypeScript's DOM lib is ignorant of. Convince TS that our list of transports
     * are fine to pass to WebAuthn since browsers will recognize the new value.
     */
    transports: descriptor.transports
  };
}

// node_modules/@simplewebauthn/browser/esm/helpers/isValidDomain.js
function isValidDomain(hostname) {
  return (
    // Consider localhost valid as well since it's okay wrt Secure Contexts
    hostname === "localhost" || // Support punycode (ACE) or ascii labels and domains
    /^((xn--[a-z0-9-]+|[a-z0-9]+(-[a-z0-9]+)*)\.)+([a-z]{2,}|xn--[a-z0-9-]+)$/i.test(hostname)
  );
}

// node_modules/@simplewebauthn/browser/esm/helpers/webAuthnError.js
var WebAuthnError = class extends Error {
  constructor({ message, code, cause, name }) {
    super(message, { cause });
    Object.defineProperty(this, "code", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
    this.name = name ?? cause.name;
    this.code = code;
  }
};

// node_modules/@simplewebauthn/browser/esm/helpers/identifyRegistrationError.js
function identifyRegistrationError({ error, options }) {
  const { publicKey } = options;
  if (!publicKey) {
    throw Error("options was missing required publicKey property");
  }
  if (error.name === "AbortError") {
    if (options.signal instanceof AbortSignal) {
      return new WebAuthnError({
        message: "Registration ceremony was sent an abort signal",
        code: "ERROR_CEREMONY_ABORTED",
        cause: error
      });
    }
  } else if (error.name === "ConstraintError") {
    if (publicKey.authenticatorSelection?.requireResidentKey === true) {
      return new WebAuthnError({
        message: "Discoverable credentials were required but no available authenticator supported it",
        code: "ERROR_AUTHENTICATOR_MISSING_DISCOVERABLE_CREDENTIAL_SUPPORT",
        cause: error
      });
    } else if (
      // @ts-ignore: `mediation` doesn't yet exist on CredentialCreationOptions but it's possible as of Sept 2024
      options.mediation === "conditional" && publicKey.authenticatorSelection?.userVerification === "required"
    ) {
      return new WebAuthnError({
        message: "User verification was required during automatic registration but it could not be performed",
        code: "ERROR_AUTO_REGISTER_USER_VERIFICATION_FAILURE",
        cause: error
      });
    } else if (publicKey.authenticatorSelection?.userVerification === "required") {
      return new WebAuthnError({
        message: "User verification was required but no available authenticator supported it",
        code: "ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT",
        cause: error
      });
    }
  } else if (error.name === "InvalidStateError") {
    return new WebAuthnError({
      message: "The authenticator was previously registered",
      code: "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED",
      cause: error
    });
  } else if (error.name === "NotAllowedError") {
    return new WebAuthnError({
      message: error.message,
      code: "ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY",
      cause: error
    });
  } else if (error.name === "NotSupportedError") {
    const validPubKeyCredParams = publicKey.pubKeyCredParams.filter((param) => param.type === "public-key");
    if (validPubKeyCredParams.length === 0) {
      return new WebAuthnError({
        message: 'No entry in pubKeyCredParams was of type "public-key"',
        code: "ERROR_MALFORMED_PUBKEYCREDPARAMS",
        cause: error
      });
    }
    return new WebAuthnError({
      message: "No available authenticator supported any of the specified pubKeyCredParams algorithms",
      code: "ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG",
      cause: error
    });
  } else if (error.name === "SecurityError") {
    const effectiveDomain = globalThis.location.hostname;
    if (!isValidDomain(effectiveDomain)) {
      return new WebAuthnError({
        message: `${globalThis.location.hostname} is an invalid domain`,
        code: "ERROR_INVALID_DOMAIN",
        cause: error
      });
    } else if (publicKey.rp.id !== effectiveDomain) {
      return new WebAuthnError({
        message: `The RP ID "${publicKey.rp.id}" is invalid for this domain`,
        code: "ERROR_INVALID_RP_ID",
        cause: error
      });
    }
  } else if (error.name === "TypeError") {
    if (publicKey.user.id.byteLength < 1 || publicKey.user.id.byteLength > 64) {
      return new WebAuthnError({
        message: "User ID was not between 1 and 64 characters",
        code: "ERROR_INVALID_USER_ID_LENGTH",
        cause: error
      });
    }
  } else if (error.name === "UnknownError") {
    return new WebAuthnError({
      message: "The authenticator was unable to process the specified options, or could not create a new credential",
      code: "ERROR_AUTHENTICATOR_GENERAL_ERROR",
      cause: error
    });
  }
  return error;
}

// node_modules/@simplewebauthn/browser/esm/helpers/webAuthnAbortService.js
var BaseWebAuthnAbortService = class {
  constructor() {
    Object.defineProperty(this, "controller", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: void 0
    });
  }
  createNewAbortSignal() {
    if (this.controller) {
      const abortError = new Error("Cancelling existing WebAuthn API call for new one");
      abortError.name = "AbortError";
      this.controller.abort(abortError);
    }
    const newController = new AbortController();
    this.controller = newController;
    return newController.signal;
  }
  cancelCeremony() {
    if (this.controller) {
      const abortError = new Error("Manually cancelling existing WebAuthn API call");
      abortError.name = "AbortError";
      this.controller.abort(abortError);
      this.controller = void 0;
    }
  }
};
var WebAuthnAbortService = new BaseWebAuthnAbortService();

// node_modules/@simplewebauthn/browser/esm/helpers/toAuthenticatorAttachment.js
var attachments = ["cross-platform", "platform"];
function toAuthenticatorAttachment(attachment) {
  if (!attachment) {
    return;
  }
  if (attachments.indexOf(attachment) < 0) {
    return;
  }
  return attachment;
}

// node_modules/@simplewebauthn/browser/esm/methods/startRegistration.js
async function startRegistration(options) {
  if (!options.optionsJSON && options.challenge) {
    console.warn("startRegistration() was not called correctly. It will try to continue with the provided options, but this call should be refactored to use the expected call structure instead. See https://simplewebauthn.dev/docs/packages/browser#typeerror-cannot-read-properties-of-undefined-reading-challenge for more information.");
    options = { optionsJSON: options };
  }
  const { optionsJSON, useAutoRegister = false } = options;
  if (!browserSupportsWebAuthn()) {
    throw new Error("WebAuthn is not supported in this browser");
  }
  const publicKey = {
    ...optionsJSON,
    challenge: base64URLStringToBuffer(optionsJSON.challenge),
    user: {
      ...optionsJSON.user,
      id: base64URLStringToBuffer(optionsJSON.user.id)
    },
    excludeCredentials: optionsJSON.excludeCredentials?.map(toPublicKeyCredentialDescriptor)
  };
  const createOptions = {};
  if (useAutoRegister) {
    createOptions.mediation = "conditional";
  }
  createOptions.publicKey = publicKey;
  createOptions.signal = WebAuthnAbortService.createNewAbortSignal();
  let credential;
  try {
    credential = await navigator.credentials.create(createOptions);
  } catch (err) {
    throw identifyRegistrationError({ error: err, options: createOptions });
  }
  if (!credential) {
    throw new Error("Registration was not completed");
  }
  const { id, rawId, response, type } = credential;
  let transports = void 0;
  if (typeof response.getTransports === "function") {
    transports = response.getTransports();
  }
  let responsePublicKeyAlgorithm = void 0;
  if (typeof response.getPublicKeyAlgorithm === "function") {
    try {
      responsePublicKeyAlgorithm = response.getPublicKeyAlgorithm();
    } catch (error) {
      warnOnBrokenImplementation("getPublicKeyAlgorithm()", error);
    }
  }
  let responsePublicKey = void 0;
  if (typeof response.getPublicKey === "function") {
    try {
      const _publicKey = response.getPublicKey();
      if (_publicKey !== null) {
        responsePublicKey = bufferToBase64URLString(_publicKey);
      }
    } catch (error) {
      warnOnBrokenImplementation("getPublicKey()", error);
    }
  }
  let responseAuthenticatorData;
  if (typeof response.getAuthenticatorData === "function") {
    try {
      responseAuthenticatorData = bufferToBase64URLString(response.getAuthenticatorData());
    } catch (error) {
      warnOnBrokenImplementation("getAuthenticatorData()", error);
    }
  }
  return {
    id,
    rawId: bufferToBase64URLString(rawId),
    response: {
      attestationObject: bufferToBase64URLString(response.attestationObject),
      clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
      transports,
      publicKeyAlgorithm: responsePublicKeyAlgorithm,
      publicKey: responsePublicKey,
      authenticatorData: responseAuthenticatorData
    },
    type,
    clientExtensionResults: credential.getClientExtensionResults(),
    authenticatorAttachment: toAuthenticatorAttachment(credential.authenticatorAttachment)
  };
}
function warnOnBrokenImplementation(methodName, cause) {
  console.warn(`The browser extension that intercepted this WebAuthn API call incorrectly implemented ${methodName}. You should report this error to them.
`, cause);
}

// src/browser/device-identity.ts
async function generateNonExportableIdentity() {
  const keys = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  if (keys.privateKey.extractable) throw new Error("Browser created an extractable private key");
  return { publicKey: base64url(publicBytes), privateKey: keys.privateKey };
}
async function createPairingProof(params) {
  const tokenBytes = decodeBase64url(params.pairingToken);
  const tokenKey = await crypto.subtle.importKey("raw", tokenBytes.buffer, { name: "HMAC", hash: "SHA-512" }, false, ["sign"]);
  const transcript = frame("cchat-pairing-v1", params.installationId, params.phoneDeviceId, params.bridgeIdentityPublicKey, params.phoneIdentityPublicKey);
  const fullProof = new Uint8Array(await crypto.subtle.sign("HMAC", tokenKey, transcript.buffer));
  return { version: 1, ...params, pairingToken: void 0, proof: base64url(fullProof.slice(0, 32)) };
}
function frame(...values) {
  const encoded = values.map((value) => new TextEncoder().encode(value));
  const output = new Uint8Array(encoded.reduce((total, value) => total + 4 + value.length, 0));
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
function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
function decodeBase64url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

// src/browser/pair.ts
var status = document.querySelector("#pair-status");
var button = document.querySelector("#pair-button");
var nameInput = document.querySelector("#device-name");
var fragment = new URLSearchParams(location.hash.slice(1));
var invitationId = fragment.get("invitation");
var pairingToken = fragment.get("secret");
history.replaceState(null, "", `${location.pathname}${location.search}`);
if (!invitationId || !pairingToken) {
  fail("This pairing link is incomplete. Create a new link from your bridge.");
} else {
  button.disabled = false;
  button.addEventListener("click", () => void pair(invitationId, pairingToken));
}
async function pair(invitation, secret) {
  button.disabled = true;
  status.textContent = "Creating this phone\u2019s private identity\u2026";
  try {
    const metadataResponse = await fetch(`/api/v1/pairing/invitations/${encodeURIComponent(invitation)}`, { cache: "no-store" });
    if (!metadataResponse.ok) throw new Error(await responseError(metadataResponse));
    const metadata = await metadataResponse.json();
    const identity = await generateNonExportableIdentity();
    const phoneDeviceId = `phone_${crypto.randomUUID().replaceAll("-", "")}`;
    const request = await createPairingProof({
      pairingToken: secret,
      installationId: metadata.installationId,
      phoneDeviceId,
      bridgeIdentityPublicKey: metadata.bridgeIdentityPublicKey,
      phoneIdentityPublicKey: identity.publicKey
    });
    status.textContent = "Waiting for your home bridge to verify the one-time proof\u2026";
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${location.host}/api/v1/connect`);
    const timeout = window.setTimeout(() => socket.close(4e3, "Pairing timeout"), 2e4);
    socket.addEventListener("open", () => socket.send(JSON.stringify({
      type: "phone.pair",
      invitationId: invitation,
      name: nameInput.value.trim() || "Phone",
      request
    })));
    socket.addEventListener("message", async (event) => {
      try {
        const message = JSON.parse(String(event.data));
        if (message.type === "pairing.rejected") throw new Error(String(message.error ?? "Pairing rejected"));
        if (message.type !== "pairing.complete") return;
        window.clearTimeout(timeout);
        const enrollmentToken = String(message.enrollmentToken ?? "");
        if (!enrollmentToken) throw new Error("Relay did not authorize Face ID enrollment");
        status.textContent = "Confirm Face ID to protect cchat access\u2026";
        await registerPasskey(phoneDeviceId, enrollmentToken);
        await saveDevice({
          version: 1,
          installationId: metadata.installationId,
          bridgeDeviceId: metadata.bridgeDeviceId,
          bridgeIdentityPublicKey: metadata.bridgeIdentityPublicKey,
          phoneDeviceId,
          phoneIdentityPublicKey: identity.publicKey,
          phoneIdentityPrivateKey: identity.privateKey
        });
        status.textContent = "Paired and protected with Face ID.";
        button.textContent = "Secured";
        socket.close(1e3, "Complete");
      } catch (error) {
        fail(error instanceof Error ? error.message : String(error));
        socket.close(1008, "Pairing rejected");
      }
    });
    socket.addEventListener("close", (event) => {
      window.clearTimeout(timeout);
      if (event.code !== 1e3 && button.textContent !== "Paired") fail(event.reason || "Pairing connection closed");
    });
    socket.addEventListener("error", () => fail("Could not connect to the encrypted relay"));
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
async function registerPasskey(deviceId, enrollmentToken) {
  const headers = { "Content-Type": "application/json", Authorization: `Bearer ${enrollmentToken}` };
  const optionsResponse = await fetch("/api/v1/webauthn/register/options", {
    method: "POST",
    headers,
    body: JSON.stringify({ deviceId })
  });
  if (!optionsResponse.ok) throw new Error(await responseError(optionsResponse));
  const registration = await startRegistration({ optionsJSON: await optionsResponse.json() });
  const verifyResponse = await fetch("/api/v1/webauthn/register/verify", {
    method: "POST",
    headers,
    body: JSON.stringify({ deviceId, response: registration })
  });
  if (!verifyResponse.ok) throw new Error(await responseError(verifyResponse));
}
function saveDevice(value) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("cchat", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("device");
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const transaction = open.result.transaction("device", "readwrite");
      transaction.objectStore("device").put(value, "current");
      transaction.oncomplete = () => {
        open.result.close();
        resolve();
      };
      transaction.onerror = () => reject(transaction.error);
    };
  });
}
function fail(message) {
  status.textContent = message;
  status.classList.add("error");
  button.disabled = true;
}
async function responseError(response) {
  try {
    return String((await response.json()).error ?? `Request failed (${response.status})`);
  } catch {
    return `Request failed (${response.status})`;
  }
}
