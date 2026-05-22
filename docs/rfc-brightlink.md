---
title: "BrightLink Protocol v1: Hardware-Anchored Credential Delivery for Developer Workflows"
parent: "Papers"
nav_order: 19
---

# BrightLink Protocol v1 — A Specification for Hardware-Anchored Ephemeral-Credential Delivery

**Authors:** Jessica Mulein
**Status:** Proposal / Draft Standard, replication-grade
**Version:** 1.0 (BrightLink v1)
**Date:** May 2026
**Built on:** [Enclave Bridge Protocol (EBP/1)](enclave-bridge-protocol).

> **One-line pitch.** BrightLink delivers short-lived developer credentials from arbitrary CLI tools to a single hardware-anchored desktop agent (BrightNexus on Apple Silicon) over a Unix socket. Key custody runs through Apple's Secure Enclave; sessions are authenticated by an SEP-signed transcript; credentials live with their declared TTL on a clean menu-bar UI; nothing touches the clipboard, scrollback, history, or `~/.aws/credentials`.

> **Scope.** BrightLink v1 covers (a) the EBP/1-extension command surface (`LINK_REGISTER`, `LINK_DELIVER`), (b) the bilateral session-key derivation, (c) the canonical SEP-signed transcript layout, (d) the AES-256-GCM length-prefixed AAD construction for delivered credentials, (e) the standardised payload schemas (`ephemeral-auth`, `db-connection`, `plaintext`, `api-token`, `cloud-session`, `ssh-credential`, `kubeconfig-context`, `totp-seed`, `mtls-cert`), and (f) the policy controls a deployer is expected to expose (peer-attestation enforcement, credential TTL ceiling).

> **Out of scope (v1).** Geo-context payloads, advisory pre-exec, agent → shell push, and the geo query socket are reserved as future commands (`LINK_PUSH`, `LINK_GEO_*`, `LINK_AUDIT_EMIT`). Implementations MUST acknowledge those command names with the suffix `"not implemented in this build"` so v1-aware clients can detect a v1-aware bridge that has not yet shipped them. They will not move on the wire until those drafts are finalised.

---

## 1. Abstract

Modern terminal workflows generate ephemeral credentials constantly: AWS STS sessions, OAuth tokens, scratch database passwords, kubeconfig contexts. The default delivery surface is `export FOO=...` followed by a credential half-life that's whatever the developer's tmux history retention is set to. Password managers raise the floor — they ask the user for explicit consent on every read — but at the cost of an agent that owns much more than ephemeral credentials and a UI flow that's wrong for things that live for ten minutes.

BrightLink v1 is a Unix-socket protocol between CLI tools (the **shell**) and a single resident desktop agent (the **bridge**). Each shell registers once, anchoring its session in a hardware-signed transcript that the shell verifies before trusting the bridge's identity. After registration, the shell delivers credential payloads as authenticated AES-256-GCM ciphertexts over the same socket. The bridge surfaces those credentials in a menu-bar UI scoped to their declared TTL: when the credential expires, it disappears.

The protocol is greenfield. There is no clipboard hop, no terminal-emulator participation, no daemon plurality, and no string-rich text format that needs to be parsed out of a stream. Everything the bridge sees is a JSON object on a Unix socket, AEAD-tagged under a session key derived from a hardware-rooted handshake.

**Keywords:** Apple Secure Enclave, ECIES, secp256k1, P-256, AES-256-GCM, HKDF, BrightDate, ephemeral credentials, terminal protocol, hardware-anchored trust.

---

## 2. The Problem

### 2.1 Ephemeral credentials want a different home than passwords

Long-lived secrets (your GitHub PAT, your production DB password) belong in a password manager: an agent that asks for consent on every read, that the user trusts to outlive any one terminal session, and that's worth the friction of typing a master password. Ephemeral credentials are the opposite: they live for ten minutes, they need to be visible to the next `aws s3 ls`, and asking for consent on every read produces a workflow nobody will use.

The de-facto delivery vector — `export AWS_SESSION_TOKEN=...` — is fast and frictionless and also writes the secret into the environment of every child process forever. tmux scrollback, shell history, debug-mode logs, anything that snapshots `/proc/self/environ`. The credential lives wherever those things live, which is much longer than ten minutes.

### 2.2 One agent, one capability surface

BrightLink collapses credential delivery into one process: **BrightNexus**, a SwiftUI menu-bar agent on macOS Apple Silicon, with key custody anchored to the device's Secure Enclave. The user runs one app, grants it one capability surface, and gets back one menu of currently-live credentials.
---

## 3. Architecture Overview

```
┌──────────────────────┐                     ┌──────────────────────────────────┐
│ Terminal             │                     │ BrightNexus (the bridge)         │
│  ┌────────────────┐  │                     │  (SwiftUI menu-bar, Apple        │
│  │ bsh shell +    │  │                     │   Silicon; or compatible impl)   │
│  │ bsh-inject     │  │                     │                                  │
│  │ + arbitrary    │  │                     │  ┌────────────────────────────┐  │
│  │ CLI tools      │  │                     │  │ EBP/1 surface:             │  │
│  └────────────────┘  │                     │  │  HEARTBEAT, GET_PUBLIC_KEY │  │
└──────────────────────┘                     │  │  ENCLAVE_SIGN/_DECRYPT,    │  │
            ▲                                │  │  ENABLE_TOTP, EXPORT_KEY,  │  │
            │ Unix socket                    │  │  LIST_KEYS …               │  │
            │ EBP/1 + BrightLink             │  ├────────────────────────────┤  │
            │                                │  │ BrightLink (§4):           │  │
            │                                │  │  LINK_REGISTER             │  │
            ▼                                │  │  LINK_DELIVER              │  │
┌──────────────────────────────┐             │  │  (LINK_PUSH, LINK_GEO_*,   │  │
│ enclave-bridge-client        │             │  │   LINK_AUDIT_EMIT —        │  │
│   (TypeScript / Node)        │             │  │   reserved)                │  │
└──────────────────────────────┘             │  └────────────────────────────┘  │
                                             │  ┌────────────────────────────┐  │
                                             │  │ EphemeralStore +           │  │
                                             │  │  Menu Bar + Dashboard UI   │  │
                                             │  └────────────────────────────┘  │
                                             └──────────────────────────────────┘
                                                          │
                                                          ▼
                                                ┌───────────────────────────────────────┐
                                                │ Apple Secure Enclave (P-256)          │
                                                │ secp256k1 priv (~/.brightchain/       │
                                                │     brightnexus/ecies-privkey.bin)    │
                                                │ TOTP config (~/.brightchain/          │
                                                │     brightnexus/totp-config.json)     │
                                                └───────────────────────────────────────┘
```

The bridge keeps its EBP/1 command surface unchanged; BrightLink adds two implemented commands (`LINK_REGISTER`, `LINK_DELIVER`) and reserves five more (`LINK_PUSH`, `LINK_GEO_*`, `LINK_AUDIT_EMIT`) for future drafts. A BrightLink-aware client speaks both EBP/1 and BrightLink through the same `EnclaveBridgeClient` class.

---

## 4. Wire Specification

### 4.1 Out-of-Band Cryptographic Registration

Before any credential delivery takes place, a CLI session registers with the local user-restricted bridge.

1. **Local Channel.** The bridge hosts an `AF_UNIX`/`SOCK_STREAM` socket exclusively accessible by the local user (filesystem permissions enforced by the host OS). The canonical path is:

   ```
   $HOME/.brightchain/brightnexus/brightnexus.sock
   ```

   Clients MAY override via the `BRIGHTNEXUS_SOCKET` environment variable. There are no legacy fallback paths in BrightLink.

2. **Ephemeral Exchange.** The shell connects to the EBP/1 socket and performs the `LINK_REGISTER` exchange defined in §4.5. The exchange yields a unique 32-byte session key (`K_session`) and a 16-byte transient `sessionId`, both bound to the bridge's P-256 signature over the registration transcript. The handshake never transmits `K_session` in cleartext: client → bridge contributions arrive inside an ECIES envelope addressed to the bridge's persistent secp256k1 public key (from `GET_PUBLIC_KEY`); the bridge's contribution is returned inside an ECIES envelope addressed to the client's ephemeral secp256k1 key from the same handshake.

3. **Memory Residence.** `K_session` resides strictly within the active memory space of that specific shell process and the bridge. Both ends destroy their copies on session expiry, on agent restart, and on explicit teardown.

4. **Session Expiry.** Sessions have a maximum lifetime of **8 hours** regardless of activity. The bridge MUST refuse to process `LINK_DELIVER` for expired sessions and MUST log the attempt. Shells that outlive their session must re-register.

5. **Squatting Defense.** The bridge MUST verify that no file exists at the chosen socket path before binding for the first time after install, and MUST abort with a fatal error rather than overwriting an unexpected file.

6. **Single Bridge.** The bridge fulfils all roles: ECIES key custody, P-256 transcript signing, credential storage, menu-bar UI. Implementations targeting platforms without a Secure Enclave SHOULD provide an EBP/1-compatible bridge that uses an OS keyring for secp256k1 key custody and either a TPM or software signing for the registration transcript; such implementations are still wire-compatible with this RFC at the BrightLink layer.

### 4.2 Wire-Level Distinguishability

`VERSION` / `INFO` responses carry a `brightlinkProtocolVersion: 1` field. BrightLink-aware clients pin on this. EBP/1-only bridges that don't speak BrightLink return EBP/1's generic `"Unknown command: <cmd>"` for `LINK_REGISTER`; BrightLink-aware bridges that haven't yet shipped a particular reserved command return an error string ending `"not implemented in this build"`. This lets clients distinguish three regimes: not-aware, aware-but-incomplete, and aware-and-implemented.

### 4.3 Concurrency, Lifetime, and Per-Session State

- One bridge process serves many concurrent shells. Each shell holds one EBP/1 connection.
- One connection holds at most one BrightLink session at a time. Re-issuing `LINK_REGISTER` on the same connection invalidates the prior session and resets the per-session rate limiter.
- Per-connection state owned by the bridge: `K_session`, `sessionId`, `bridgeIssuedAtUnix`, `expiresAtUnix`, `lastInboundCounter`, agent-info block, deliver-failure rate-limiter state.
- Per-connection state owned by the shell: `K_session`, `sessionId`, the bridge's pinned SEP P-256 public key (TOFU), `outboundCounter`.
- Connection close wipes `K_session` on both sides. Stored credentials persist for their declared TTL regardless — closing the shell does not invalidate credentials the shell already delivered.

### 4.4 Rate Limiting

The bridge enforces a per-session **failure-only** rate limit on `LINK_DELIVER`: after **30 consecutive structural-or-decryption failures within a 60-second window**, the bridge tears down the session and requires re-registration. Successful deliveries are not rate-limited.

Rationale: a remote attacker who has somehow injected JSON onto the local socket but doesn't hold `K_session` will trip GCM authentication on every attempt. 30 failures in a minute is well above any plausible legitimate failure rate (counter races, transient JSON-construction bugs) and well below the rate at which an attacker could probe the GCM tag space.

### 4.5 The `LINK_REGISTER` Command

The handshake establishes `K_session`, derives a transcript covering every input either side contributed, and gets that transcript signed by the bridge's SEP-anchored P-256 key. The shell verifies that signature against the SEP public key (`GET_ENCLAVE_PUBLIC_KEY`) and pins it on first use.

#### 4.5.0 Pinning to DD-ECIES (Normative)

The outer envelope encryption is **strictly** DD-ECIES Basic mode (cipher-suite byte `0x21`) over secp256k1. Compressed (33-byte) ephemeral public keys only — uncompressed (65-byte) ephemerals are rejected. The §5.3 tolerance from the DD-ECIES draft is opted out for both directions of the BrightLink registration handshake.

#### 4.5.1 Envelope Plaintext Schema

The client builds, JSON-serialises, and ECIES-encrypts:

```json
{
  "v": 1,
  "clientPub": "<base64 65-byte uncompressed secp256k1>",
  "clientShare": "<base64 32 bytes>",
  "issuedAtBd": <BrightDate scalar — days since J2000.0>,
  "ttlSeconds": <int — requested session lifetime, capped at 28800>,
  "agent": { "name": "<string>", "version": "<string>", "platform": "<string>" }
}
```

`agent.*` fields default to `"unknown"` at the bridge if missing or non-string. Each field is truncated to 64 characters.

#### 4.5.2 Session-Key Derivation

Both ends compute:

```
IKM   = clientShare ‖ bridgeShare       (64 bytes)
salt  = clientNonce ‖ sessionId          (32 bytes)
info  = "brightlink-session-key-v1"      (25 bytes UTF-8)
K_session = HKDF-SHA256(IKM, salt, info, 32)
```

The HKDF info string is **case- and byte-exact**. A typo here breaks every delivery silently.

#### 4.5.3 Canonical Transcript and Bridge Response

The bridge constructs a canonical 238-byte transcript:

```
"BrightLink v1 transcript\0"                            25 bytes
LE32(len(clientNonce))   ‖ clientNonce                  4 + 16
LE32(len(clientPub))     ‖ clientPub                    4 + 65
LE32(len(clientShare))   ‖ clientShare                  4 + 32
LE32(len(sessionId))     ‖ sessionId                    4 + 16
LE32(len(bridgeShare))   ‖ bridgeShare                  4 + 32
LE32(8)                  ‖ u64_be(round(issuedAtBd*86400))
LE32(8)                  ‖ u64_be(bridgeIssuedAtUnix)
LE32(4)                  ‖ u32_be(ttlSeconds)
                                                   = 238 bytes
```

`LE32(n)` is a 4-byte little-endian length prefix. `u64_be` and `u32_be` are big-endian.

The bridge signs the transcript with its SEP P-256 key (DER-encoded ECDSA) and returns:

```json
{
  "ok": true,
  "sessionId": "<base64 16 bytes>",
  "bridgeIssuedAtUnix": <int>,
  "ttlSeconds": <int — granted, possibly clamped>,
  "responseEnvelope": "<base64 ECIES envelope to clientPub carrying bridgeShare>",
  "transcriptSig": "<base64 DER ECDSA-P256>"
}
```

#### 4.5.4 Client-Side Procedure

1. Generate `clientNonce` (16 bytes), `clientShare` (32 bytes), and an ephemeral secp256k1 keypair (`clientPub`/`clientPriv`).
2. Build the §4.5.1 plaintext, ECIES-encrypt to the bridge's `GET_PUBLIC_KEY`.
3. Send `LINK_REGISTER` with `clientNonce` (base64), `envelope` (base64), `protocolVersion: 1`.
4. Receive the response; ECIES-decrypt `responseEnvelope` with `clientPriv` to recover `bridgeShare`.
5. Reconstruct the §4.5.3 transcript from inputs the client knows + the bridge's response fields.
6. Verify `transcriptSig` against the SEP key (TOFU on first registration; pin-match on every subsequent registration).
7. Derive `K_session` via §4.5.2.
8. Wipe `clientPriv`, `clientShare`, `bridgeShare`, and any intermediate IKM. Retain only `K_session`, `sessionId`, and the SEP key pin.

#### 4.5.5 Trust on First Use vs Pinning the SEP Key

The first successful `LINK_REGISTER` on a fresh client install pins the bridge's SEP public key. Every subsequent `LINK_REGISTER` against the same bridge MUST byte-match the pinned key, or the client refuses with a TOFU-mismatch error. This bounds the "lying bridge" attack to first-install on a fresh device — a reasonable boundary for a local-developer tool.

#### 4.5.6 Errors

The bridge returns plain-string `error` fields. Clients SHOULD match on the literal English strings:

- `"Unsupported BrightLink protocol version"` — client sent `protocolVersion != 1`.
- `"Missing clientNonce"` / `"Missing envelope"` — request shape error.
- `"Decryption failed"` — outer ECIES envelope decode/AEAD failure.
- `"Invalid envelope plaintext"` — inner JSON is not the §4.5.1 schema, or `v != 1`.
- `"Stale registration"` — `issuedAtBd * 86400` more than 60s in the future.
- internal errors prefixed `"internal: "` — bridge bug; client SHOULD log and retry once.

### 4.6 The `LINK_DELIVER` Command (Shell → Agent)

After registration, the shell delivers credential payloads as JSON requests. There is no terminal-emulator path. There is no out-of-band stream filter. There is one path: a JSON object on the EBP/1 socket.

#### 4.6.1 Request

```json
{
  "cmd":        "LINK_DELIVER",
  "counter":    <uint64 — strictly greater than the last accepted>,
  "type":       "<string — one of §5 schema identifiers>",
  "context":    "<string — routing context, e.g. URL or zone name>",
  "iv":         "<base64 12 bytes>",
  "ciphertext": "<base64>",
  "authTag":    "<base64 16 bytes>"
}
```

`counter` is the shell's per-session monotonic outbound counter, starting at 1.

#### 4.6.2 Length-Prefixed AAD

The AES-256-GCM Additional Authenticated Data is constructed with length-prefixed encoding:

```
AAD = LE32(1) ‖ dir_tag                            (1 = length, dir_tag = 0x01 for shell→agent)
    ‖ LE32(8) ‖ u64_be(counter)
    ‖ LE32(len(type))    ‖ type_utf8
    ‖ LE32(len(context)) ‖ context_utf8
```

Both sides reconstruct AAD identically. A captured ciphertext cannot be replayed under a different direction, type, context, or counter even if `K_session` were extracted.

#### 4.6.3 Replay Window

The bridge maintains `lastInboundCounter` per session, initialised to 0. On receipt:

1. The bridge verifies `counter > lastInboundCounter` and `counter ≤ lastInboundCounter + 1000`.
2. If the AES-GCM authentication succeeds, the bridge sets `lastInboundCounter = counter` and stores the credential.
3. Counter values out of window are rejected with `"Counter replayed"` or `"Counter out of replay window"` and count toward §4.4 rate-limit accounting.

#### 4.6.4 Response

Successful deliveries return `{"ok": true, "type": "<echoed>", "context": "<echoed>"}`. The echo lets the shell confirm the bridge stored the credential under the expected routing context after any body-side overrides (§5).

### 4.7 Reserved Commands

The following command names are reserved and return `"<cmd> not implemented in this build"`:

- `LINK_PUSH` — bridge-initiated push of agent → shell credentials. Future v1.x will land this; the wire shape will mirror `LINK_DELIVER` with `dir_tag = 0x02`.
- `LINK_GEO_GET`, `LINK_GEO_STATUS`, `LINK_GEO_REFRESH`, `LINK_GEO_AUDIT` — geo-context surface (zones, transitions, advisory pre-exec).
- `LINK_AUDIT_EMIT` — bulk audit export.

A BrightLink-aware bridge MUST acknowledge these names with the literal `"not implemented in this build"` suffix.

### 4.8 Peer Attestation, TTL Clamping, and Provenance

The bridge captures the connecting peer's audit token (codesign identity, team ID) at `accept(2)` time. Two policy modes:

- **Log-only (default).** Every `LINK_DELIVER` records the attestation result alongside the stored credential. Unsigned binaries are accepted; the credential is tagged with `"unsigned"` provenance in the menu-bar UI.
- **Enforce.** `LINK_DELIVER` from a peer that fails attestation is rejected with `"Peer attestation failed"`.

The bridge also enforces a configurable per-credential TTL ceiling (default 1 hour, range 1–480 minutes). Payloads requesting a longer TTL are silently clamped at storage time; the response is unaffected. The user-facing UI displays the resolved (post-clamp) expiry.

### 4.9 Memory Hygiene

- The bridge wipes `K_session` on connection close, on session re-registration, and on rate-limit teardown. Stored payloads are wiped on TTL expiry.
- The shell wipes `K_session` on `disconnect()` and on `linkUnregister()`.
- Both ends use best-effort overwrites of intermediate IKM and share buffers; readers should assume the language runtime's GC may have aliased copies that survive the explicit clear.

---

## 5. Standardised Payload Schemas

All payloads are AES-256-GCM-sealed JSON objects. The plaintext top-level keys are common across schemas:

| Field | Type | Description |
| --- | --- | --- |
| `ttl` | `int` | Requested TTL in seconds. Clamped at the bridge's configured ceiling (§4.8). |
| `issued_at` | `int` (optional) | Unix timestamp the shell believes the credential was issued. Informational. |
| `type` | `string` (optional) | Body-side override of the wire `type`. The bridge prefers body-side. |
| `context` | `string` (optional) | Body-side override of the wire `context`. The bridge prefers body-side. |

The remaining schema-specific fields:

### 5.1 `ephemeral-auth`

```json
{ "username": "...", "password": "...", "email": "...", "ttl": 300 }
```

For dynamic test credentials, ephemeral DB users, OAuth flow scratch logins.

### 5.2 `db-connection`

```json
{ "engine": "postgres", "host": "...", "port": 5432, "user": "...", "pass": "...", "ttl": 300 }
```

For full database connection contexts. The menu-bar UI MAY render a copy-as-DSN action.

### 5.3 `api-token`

```json
{ "token": "...", "scope": ["read:repo", "write:org"], "ttl": 600 }
```

For OAuth bearer tokens, GitHub PATs, etc.

### 5.4 `cloud-session`

```json
{ "provider": "aws", "accessKeyId": "...", "secretAccessKey": "...", "sessionToken": "...", "region": "...", "ttl": 3600 }
```

For STS/AssumeRole credentials. The menu-bar UI MAY render copy-as-`aws configure` actions.

### 5.5 `ssh-credential`

```json
{ "host": "...", "user": "...", "privateKey": "...", "passphrase": "...", "ttl": 1800 }
```

Pinned to OpenSSH-format private keys.

### 5.6 `kubeconfig-context`

```json
{ "cluster": "...", "server": "...", "caCert": "...", "user": "...", "clientCert": "...", "clientKey": "...", "token": "...", "ttl": 3600 }
```

For ephemeral kubeconfig contexts (e.g. `gcloud container clusters get-credentials` output).

### 5.7 `totp-seed`

```json
{ "label": "...", "issuer": "...", "secret": "...", "algorithm": "SHA1", "digits": 6, "period": 30, "ttl": 60 }
```

Short-lived TOTP seeds (e.g. for one-shot 2FA bootstrapping).

### 5.8 `mtls-cert`

```json
{ "cert": "...", "key": "...", "caCert": "...", "ttl": 600 }
```

Client mTLS certificate + private key bundle.

### 5.9 `plaintext`

```json
{ "label": "...", "value": "...", "masked": true, "ttl": 600 }
```

Generic single-value payload — the catch-all for "credential-shaped thing the user wants in the menu bar for ten minutes." `masked: true` tells the UI to render dots until the user clicks.

---

## 6. Client Reference

A reference TypeScript client lives at `enclave-bridge-client` (npm: `@digitaldefiance/enclave-bridge-client`). The client surface:

```ts
import { EnclaveBridgeClient } from '@digitaldefiance/enclave-bridge-client';

const client = new EnclaveBridgeClient();
await client.connect();                // connects to discovered socket
await client.linkRegister();           // performs §4.5 handshake
await client.linkDeliver({              // not yet shipped; planned helper
  type: 'plaintext',
  context: 'demo',
  body: { label: 'Hello', value: 'world', ttl: 600 },
});
client.linkUnregister();
await client.disconnect();
```

For `bsh`, the `bsh-inject` builtin in the `bsh/brightlink` module wraps the same flow:

```bsh
zmodload bsh/brightlink
printf '{"username":"alice","password":"hunter2","ttl":600}' \
  | bsh-inject --type ephemeral-auth --context http://example.com
```

---

## 7. Test Vectors

The repository at [github.com/BrightChain/bsh](https://github.com/BrightChain/bsh) under `test-harness/` ships:

- A spec-derived mock bridge (`mock-brightnexus`) that any client implementation can drive.
- A spec-derived mock shell (`mock-bsh-client`) that any bridge implementation can drive.
- Known-answer vectors for `K_session` derivation, the canonical transcript, and DD-ECIES encrypt/decrypt.
- Real-bridge integration tests that drive a running BrightNexus.app.
- Real-shell integration tests that drive a real bsh binary against the mock bridge.

A conformant implementation MUST pass the same vectors. CI matrix runs are scripted under `test-harness/scripts/`.

---

## 8. Security Considerations

1. **Trust boundary.** A user who runs an attacker's binary on their machine has already lost. BrightLink does not defend against that. It defends against credentials living longer than they should and against credentials reaching things that don't need to see them.
2. **Local-socket adversaries.** `AF_UNIX` socket permissions confine reach to the local user. `K_session` never leaves the bridge or shell processes; an attacker who can read `/proc/<pid>/mem` can already read everything.
3. **TOFU on the SEP key.** First-install pinning is a real boundary, not a perfect one. A user who runs a malicious BrightNexus build before ever running a real one is in the lying-bridge attack window. A future v1.x MAY add out-of-band SEP-key publication via Apple's developer notarization records.
4. **Side channels.** AES-GCM via Apple's CryptoKit and OpenSSL is constant-time on the platforms in scope. The bridge's reads of `EphemeralStore` may not be — implementations SHOULD prefer constant-time comparison when reading credentials by context. (The reference Swift implementation does not, currently; tracked as a known limitation.)

---

## 9. Compatibility

- **EBP/1.** BrightLink layers cleanly on top of EBP/1. An EBP/1 client that doesn't speak BrightLink ignores the extra `brightlinkProtocolVersion` field in `VERSION`.
- **Operating systems.** The reference bridge (BrightNexus) is macOS / Apple Silicon. Compatible bridges on other platforms (TPM-backed Linux, Windows DPAPI) are envisioned but not normative in BrightLink.
- **Languages.** The wire is JSON over Unix socket — any language with crypto primitives (AES-GCM, HKDF-SHA256, secp256k1 ECDH, P-256 ECDSA) can implement either side.

---

## 10–15. Reserved

Sections 10–15 are reserved for future drafts (LINK_PUSH, geo, audit). They will land alongside their respective implementations.

---

## Acknowledgements

Built on top of EBP/1 (Enclave Bridge Protocol). Anchors trust in Apple's Secure Enclave (P-256, SEP-resident key, hardware-backed signing). Uses DD-ECIES Basic mode (cipher suite `0x21`) over secp256k1 for the registration envelope. Counter and AEAD constructions follow standard practice for AES-GCM with length-prefixed AAD; nothing novel is claimed there.
