# Security policy

## Current status

cchat is experimental. The current prototype has no remote authentication,
device pairing, Face ID/WebAuthn, relay authorization, or end-to-end encryption.
It must remain bound to localhost and must not be exposed to the internet or a
shared network.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose a workstation,
Codex session, credential, source repository, or private conversation. Contact
the repository owner privately through the security contact configured on the
GitHub repository.

Include the affected version, reproduction steps, impact, and any suggested
mitigation. Please avoid accessing data that does not belong to you.

## Supported versions

There is no production-supported release yet. Security fixes are applied only
to the latest revision on the default branch.

## Security boundaries

- Codex App Server and the local bridge must bind only to loopback or a
  user-protected Unix socket.
- The browser-to-bridge protocol is an explicit allowlist; arbitrary Codex RPC
  passthrough is prohibited.
- The future relay must treat all conversation payloads as opaque end-to-end
  encrypted envelopes.
- Approval requests must fail closed when their type or state is unknown.
- Secrets, transcripts, commands, paths, diffs, and approval content must not be
  written to relay logs.
