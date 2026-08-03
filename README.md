# cchat

> **Security status:** experimental localhost prototype. Do not expose this
> revision to the internet or a shared network.

cchat is a local-first companion UI for existing Codex sessions. The current repository contains a Phase 0 localhost prototype: a small TypeScript bridge hosts Codex App Server on a loopback-only WebSocket and presents a mobile-friendly browser UI.

The prototype does **not** yet include the Linode relay, authentication, device pairing, or end-to-end encryption. It binds to localhost by default and should not be exposed to a network.

## Requirements

- Ubuntu, macOS, or another environment supported by Codex CLI
- An installed and authenticated `codex` command with App Server support
- Node.js 22 or newer

This prototype was initially tested against Codex CLI 0.146.0. App Server is experimental, so compatibility with later versions must be tested.

## Run the local prototype

```bash
npm install
npm start
```

Open <http://127.0.0.1:4317>.

The bridge starts App Server on a shared localhost listener. To open the regular Codex terminal against that same server, run this in another terminal:

```bash
npm link
cchat-cli
```

Without installing the convenience command, the equivalent invocation is
`codex --remote ws://127.0.0.1:4500`.

Threads created from either interface belong to the shared App Server. Select the same thread from the session list in the browser and CLI to test handoff. Avoid sending simultaneous turns from both clients while multi-client behavior is still being evaluated.

By default, new threads use the directory from which cchat was started. Override it with:

```bash
CCHAT_DEFAULT_CWD=/absolute/path/to/project npm start
```

The server deliberately binds to `127.0.0.1`. Do not set `CCHAT_HOST` to a public interface: this prototype has no authentication or end-to-end encryption.

For troubleshooting, the old isolated behavior is still available:

```bash
CCHAT_CODEX_MODE=private npm start
```

## Run continuously on the workstation

After testing the foreground process, install the user-level service:

```bash
npm run service:install
```

It starts automatically when your user service manager starts. Useful commands:

```bash
npm run service:status
journalctl --user -u cchat.service -f
npm run service:uninstall
```

Optional overrides live in `~/.config/cchat/environment`. The installer leaves
that file in place when the service is removed. Stop a manually started cchat
process before installing the service so port 4317 is available.

## What is implemented

- Existing Codex thread listing
- Automatic discovery of CLI-created threads
- Persisted conversation loading through `thread/resume`
- New threads with workspace-write sandboxing and on-request approvals
- Turn start, steering, and interruption
- Streaming agent, reasoning, command, file-change, and tool events
- One-time command and file-change approval decisions
- A strict browser-to-bridge action allowlist

## Difference from Codex CLI

cchat is a client of the same Codex App Server protocol, not another AI agent. Codex still owns thread history, context, model calls, tools, local execution, sandboxing, and approval decisions.

The prototype currently lacks several CLI conveniences: slash commands, attachments, rich terminal interaction, plan controls, model/effort selection, search, and complete handling for every tool or elicitation type. Those gaps will be evaluated before the relay is built.

The secure relay, device pairing, Face ID/WebAuthn, and end-to-end encryption layers are planned but not yet implemented. Do not expose the current prototype beyond localhost.

The protocol and relay security work is tracked in
[docs/security-design.md](docs/security-design.md). Cryptographic primitives and
control-plane storage have automated tests, but are not yet connected to the
browser/bridge data path.

The locked staging deployment for `mycchat.win` is documented in
[docs/deployment.md](docs/deployment.md).

## Pair a phone

After deploying the relay, claim it once using its bootstrap token:

```bash
npm run bridge:claim -- <one-time-bootstrap-token>
systemctl --user restart cchat.service
```

Then create a five-minute, single-use QR code:

```bash
npm run pair
```

The pairing secret is carried in the URL fragment, removed from the phone's
address bar immediately, and verified by the home bridge rather than the relay.
Face ID/passkey registration and encrypted Codex message routing are the next
implementation milestone.

## License

MIT
