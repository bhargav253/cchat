# Security design

## Status

This document describes work in progress. The localhost UI is functional, but
the encrypted relay path is not yet connected to it and must not be deployed as
a public service.

## Trust boundaries

- The Ubuntu bridge and paired phone are trusted with Codex plaintext.
- The relay is trusted for availability and routing only.
- The relay must not receive conversation keys or plaintext Codex content.
- Browser code delivered by the relay remains a risk: a compromised relay can
  serve malicious JavaScript. Reproducible, minimal, tightly controlled
  frontend deployments are required; a signed native client would provide a
  stronger client-code boundary in the future.

## Device enrollment

There is no public signup and no username or password.

1. The bridge creates a random, single-use pairing token with a maximum lifetime
   of ten minutes.
2. A QR code binds the installation identifier, bridge identity public key,
   invitation identifier, and pairing token.
3. The phone creates a non-exportable WebCrypto Ed25519 identity key locally.
4. The phone authenticates the pairing transcript with the invitation token.
5. The bridge verifies the proof and registers the phone public key through its
   authenticated relay connection.
6. The invitation is consumed exactly once.
7. The phone registers a WebAuthn platform credential using a separate,
   two-minute enrollment authorization with user verification
   required. On iPhone this normally invokes Face ID or the device passcode.

The pairing token is not a durable credential. The relay stores only its
SHA-256 hash and expiry state.

## Session encryption

The current protocol core uses libsodium and versioned, length-prefixed
transcripts.

- Ed25519 identity signatures authenticate the phone and bridge.
- Each connection creates new X25519 ephemeral key pairs.
- Both ephemeral public keys, both identity public keys, installation ID, and
  device IDs are bound into the signed handshake transcript.
- Libsodium `crypto_kx` derives separate transmit and receive keys.
- XChaCha20-Poly1305 encrypts application envelopes.
- Protocol version, channel ID, direction, counter, message ID, and message type
  are authenticated as associated data.
- Each direction has an independent monotonically increasing counter.
- Replayed, skipped, reordered, cross-channel, wrong-direction, or modified
  envelopes fail closed.
- Reconnection performs a new ephemeral handshake and starts new counters.

The implementation has automated positive and negative tests, but it still
requires independent protocol and implementation review before production use.

## Face ID and device keys

WebAuthn and E2E identity keys have different purposes:

- WebAuthn proves that the person using the paired browser completed local user
  verification.
- The phone identity key proves possession of the paired cchat device identity.
  Its private `CryptoKey` is non-exportable and stored by IndexedDB only after
  WebAuthn registration succeeds. Same-origin JavaScript can request signatures
  while running but cannot export the private key bytes.
- Ephemeral X25519 keys provide fresh encryption keys for each connection.

A synced passkey alone is not treated as the E2E device identity. A connection
must satisfy relay session authorization and the encrypted device handshake.
Successful WebAuthn authentication creates a short-lived 15-minute relay
session held in browser `sessionStorage`; it is not a durable device secret.

## Relay database

SQLite stores only:

- installation identity records;
- paired device public records and revocation state;
- short-lived pairing invitation hashes;
- WebAuthn credential public keys and counters;
- configuration state; and
- metadata-only audit events.

It has no tables for messages, threads, turns, transcripts, commands, diffs,
paths, or approvals. Conversation history remains in Codex storage on Ubuntu.

## Approval rules

- Unknown approval types fail closed.
- Approval messages are never queued offline.
- The first valid answer resolves a request; later answers are rejected.
- Persistent session-wide approval is excluded from the initial release.
- High-risk approvals will require a fresh WebAuthn assertion bound to the exact
  action digest.

## Operational requirements

- Dedicated Linode instance.
- Public inbound TCP 443 only, with SSH key access tightly restricted.
- Caddy terminates TLS; the relay listens on loopback.
- No third-party frontend scripts, analytics, fonts, or advertisements.
- Strict CSP, Origin validation, body limits, rate limits, and short log
  retention.
- Bridge App Server remains loopback-only or uses a user-protected Unix socket.
- Secrets and private keys never enter Git or server logs.
