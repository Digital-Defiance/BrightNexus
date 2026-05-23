# BrightNexus

<p align="center">
  <img height="75" alt="brightnexus" src="https://github.com/user-attachments/assets/462ecf30-d91f-469e-a82d-1bcc17ad0e6b" />
</p>


<p align="center">
  <strong>Apple Secure Enclave bridge + BrightLink credential agent for the BrightChain stack</strong>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#paths-and-configuration">Paths</a> •
  <a href="#protocol">Protocol</a> •
  <a href="#development">Development</a>
</p>

<p align="center">
  <a href="https://brightnexus.brightdate.org">brightnexus.brightdate.org</a> · <a href="ENCLAVE_BRIDGE_SPEC.md">EBP/1 spec</a> · <a href="https://github.com/Digital-Defiance/bsh/blob/main/docs/rfc-brightlink.md">BrightLink RFC</a>
</p>

> **Renamed from Enclave Bridge.** This project was previously known as **Enclave Bridge**. It still implements the [Enclave Bridge Protocol (EBP/1)](https://github.brightchain.org/docs/papers/enclave-bridge-protocol/) — that wire surface is unchanged — and now also acts as the **BrightLink agent** under the [BrightLink Protocol specification](https://github.brightchain.org/docs/papers/brightlink/). See the [migration notes](#migration-from-enclave-bridge) below.
>
>

---

## Overview

**BrightNexus** is a macOS status-bar application (SwiftUI, Apple Silicon) that:

1. Bridges Node.js applications to Apple's **Secure Enclave** (P-256 hardware signing) and to a host-resident **secp256k1** ECIES key, exposed over a Unix domain socket via the Enclave Bridge Protocol (EBP/1). This is the original Enclave Bridge functionality, preserved bit-for-bit.
2. Hosts the **BrightLink** agent surface defined in the [BrightLink Protocol RFC](https://github.brightchain.org/docs/papers/brightlink/), receiving `LINK_DELIVER` Shell→Agent traffic from `bsh` (or any BrightLink-aware CLI tool) and surfacing the resulting credentials in a menu-bar dropdown and a Dashboard "Credentials" view.

BrightNexus is part of the [BrightChain](https://github.brightchain.org) project. Its bundle ID is `org.digitaldefiance.brightchain.BrightNexus`.

## Features

- 🔐 **Apple Secure Enclave Integration** — Hardware-backed P-256 signing keys.
- 🔑 **secp256k1 ECIES** — secp256k1 + AES-256-GCM (12-byte IV, 16-byte tag) + HKDF-SHA256, byte-compatible with [`@digitaldefiance/node-ecies-lib`](https://www.npmjs.com/package/@digitaldefiance/node-ecies-lib) v4 (DD-ECIES Basic mode).
- 🔌 **Unix-socket IPC** — local-only, owner-only (mode 0600).
- 📊 **Status-bar UI** — connection count, request count, key fingerprints, and a **Credentials** submenu listing every active BrightLink payload with click-to-copy and live TTL countdowns.
- 🖥️ **Dashboard Credentials view** — list-style sibling of the menu-bar dropdown, with Clear All toolbar action.
- 🔑 **Optional TOTP 2FA** — RFC 6238, scannable provisioning URIs.
- 🛰️ **BrightLink agent role** — `LINK_REGISTER` (RFC §4.5), `LINK_DELIVER` (§4.6), and the full `LINK_GEO_*` surface (§9) are implemented. `LINK_PUSH` (§10) and `LINK_AUDIT_EMIT` (§11) are reserved.

## Requirements

### macOS app

- macOS 13.0 (Ventura) or later
- Apple Silicon (M1/M2/M3/M4) — Secure Enclave required
- Xcode 15.0 or later (for building)

### Node.js client

- Node.js 18.0 or later
- macOS with the BrightNexus app running

## Architecture

```
┌──────────────────────┐    Unix socket               ┌────────────────────────────┐
│  bsh shell or any    │  ~/.brightchain/brightnexus/ │  BrightNexus (SwiftUI)     │
│  BrightLink-aware CLI tool   │  brightnexus.sock            │                            │
│                      │                              │  BridgeProtocolHandler     │
│ ┌──────────────────┐ │  EBP/1 + BrightLink JSON.    │  ├─ ECIES (secp256k1)      │
│ │ bsh-inject       │ │  ──────────────────────────► │  ├─ SecureEnclaveKeyMgr    │
│ │                  │ │                              │  ├─ LINK_REGISTER (§4.5)   │
│ └──────────────────┘ │                              │  └─ LINK_DELIVER  (§4.6) ─┐│
└──────────────────────┘                              │                          ││
                                                      │           │              ││
                                                      │           ▼              ││
                                                      │  ┌──────────────────┐    ││
                                                      │  │ Apple SEP        │    ││
                                                      │  │ (P-256 hardware) │    ││
                                                      │  └──────────────────┘    ││
                                                      │                          ││
                                                      │  ┌──────────────────┐    ││
                                                      │  │ EphemeralStore  ◄┼────┘│
                                                      │  │ + menu-bar UI    │     │
                                                      │  │ + Dashboard view │     │
                                                      │  └──────────────────┘     │
                                                      └────────────────────────────┘
```

`LINK_DELIVER` is JSON on the EBP/1 socket — `{cmd, counter, type, context, iv, ciphertext, authTag}`. Length-prefixed AAD binds direction, counter, type, and context into the GCM authentication tag (RFC §4.6.2).

## Installation

### Building from source

```bash
git clone https://github.com/Digital-Defiance/BrightNexus.git
cd BrightNexus
open BrightNexus.xcodeproj
```

In Xcode: select the **BrightNexus** scheme, then build (⌘B) or run (⌘R).

### Installing the Node.js client

```bash
npm install @digitaldefiance/enclave-bridge-client
```

The TypeScript client speaks both EBP/1 and BrightLink.

### Sanity-checking the socket

With the app running:

```bash
printf '%s' '{"cmd":"HEARTBEAT"}' \
  | nc -U ~/.brightchain/brightnexus/brightnexus.sock
# {"ok":true,"timestamp":"2026-05-21T17:02:11Z","service":"enclave-bridge"}
```

A successful `HEARTBEAT` confirms the socket is bound and the protocol handler is dispatching.

```bash
printf '%s' '{"cmd":"VERSION"}' \
  | nc -U ~/.brightchain/brightnexus/brightnexus.sock
# {"app":"brightnexus","brightlinkProtocolVersion":1,...}
```

A successful `VERSION` reply confirms BrightLink support.

## Paths and configuration

BrightNexus stores its state under a single per-user directory tree, mode `0700` throughout:

```
~/.brightchain/                                  vendor namespace (umbrella)
~/.brightchain/brightnexus/                      this app's state
~/.brightchain/brightnexus/brightnexus.sock      primary EBP/1 + BrightLink socket
~/.brightchain/brightnexus/ecies-privkey.bin     secp256k1 private key (mode 0600)
~/.brightchain/brightnexus/totp-config.json      TOTP secrets (mode 0600)
```

BrightLink is greenfield — there are no legacy paths to migrate from and no compatibility sockets. If you previously ran the original "Enclave Bridge" app, its state files at `~/.enclave/` are not consulted; you can delete them at your convenience.

### Discovery order for clients

1. `${BRIGHTNEXUS_SOCKET}` — environment override (reserved name).
2. `${HOME}/.brightchain/brightnexus/brightnexus.sock` — canonical.

There are no further fallbacks. A BrightLink-aware client that finds neither path treats the bridge as unavailable.

## Protocol

### EBP/1 (current and stable)

| Command | Description |
|---|---|
| `HEARTBEAT` | Liveness probe |
| `VERSION` / `INFO` | App version, build, platform, uptime, `app: "brightnexus"`, `brightlinkProtocolVersion: 1` |
| `STATUS` | Peer-key flag, enclave availability |
| `METRICS` | Uptime + reserved counters |
| `GET_PUBLIC_KEY` | Bridge's secp256k1 public key (ECIES) |
| `GET_ENCLAVE_PUBLIC_KEY` | SEP P-256 public key |
| `SET_PEER_PUBLIC_KEY` | Cache a peer's public key on this connection |
| `LIST_KEYS` | Enumerate keys with TOTP status |
| `ENCLAVE_SIGN` | ECDSA-SHA256 over P-256 in SEP |
| `ENCLAVE_DECRYPT` | ECIES decrypt with the bridge secp256k1 key |
| `ENCLAVE_GENERATE_KEY` | Reserved (not implemented) |
| `ENCLAVE_ROTATE_KEY` | Reserved (not implemented) |
| `ENABLE_TOTP` | Enable per-key TOTP, return provisioning URI |
| `EXPORT_KEY` | Export public key, gated by TOTP if enabled |

Full specification: [Enclave Bridge Protocol (EBP/1)](ENCLAVE_BRIDGE_SPEC.md).

### BrightLink

The BrightLink surface implements `LINK_REGISTER`, `LINK_DELIVER`, and the full `LINK_GEO_*` query surface (status, proximity, zone, get, refresh). `LINK_PUSH` and `LINK_AUDIT_EMIT` remain reserved and respond with the stable `"<COMMAND> not implemented in this build"` suffix so callers can distinguish a BrightLink-aware bridge that hasn't shipped them yet from an older EBP/1-only bridge that returns `"Unknown command"`.

| Command | Status | Purpose |
|---|---|---|
| `LINK_REGISTER` | implemented | Establish a BrightLink session — bilateral HKDF over secp256k1 ECIES, 238-byte canonical transcript signed by SEP P-256, TOFU pin (RFC §4.5). |
| `LINK_DELIVER` | implemented | Shell → Agent credential delivery. Decrypts under `K_session`, validates direction tag and replay window, drops the payload into `EphemeralStore` for menu-bar / Dashboard display (RFC §4.6). |
| `LINK_PUSH` | reserved | Agent → Shell long-lived push subscription channel. |
| `LINK_GEO_STATUS` | implemented | Engine alive + fix freshness, no scope gate. |
| `LINK_GEO_PROXIMITY` | implemented | Yes/no for one named zone (`geo:proximity`). |
| `LINK_GEO_ZONE` | implemented | Current zone identifier and dwell (`geo:zone`). |
| `LINK_GEO_GET` | implemented | Full position in WGS84, BrightSpace, or both (`geo:precise`). |
| `LINK_GEO_REFRESH` | implemented | Trigger a fresh fix (`geo:status`). |
| `LINK_AUDIT_EMIT` | reserved | Shell → bridge audit-event emit. |

Full v1 specification: [BrightLink Protocol RFC](https://github.com/Digital-Defiance/bsh/blob/main/docs/rfc-brightlink.md).

## Development

### Building from source

```bash
git clone https://github.com/Digital-Defiance/BrightNexus.git
cd BrightNexus
open BrightNexus.xcodeproj
# Build: ⌘B  Run: ⌘R  Test: ⌘U
```

### Project structure

```
BrightNexus/
├── BrightNexus/                       SwiftUI app sources
│   ├── BrightNexusApp.swift           App entry + status-bar Credentials submenu
│   ├── ContentView.swift              Main UI (Dashboard, Credentials, Connections, Keys)
│   ├── AppState.swift                 Observable state (incl. published `credentials`)
│   ├── SocketServer.swift             Unix-socket server (single canonical socket)
│   ├── BridgeProtocolHandler.swift    EBP/1 + BrightLink dispatch (REGISTER, DELIVER)
│   ├── BrightLinkSession.swift        Bilateral HKDF + 238-byte canonical transcript
│   ├── BrightLinkPayload.swift        §5 payload schemas decoder
│   ├── DeliverRateLimiter.swift       §4.4 failure-only rate limiter
│   ├── EphemeralStore.swift           Thread-safe credential store with TTL sweeper
│   ├── ECIES.swift                    secp256k1 + AES-256-GCM
│   ├── ECIESKeyManager.swift          On-disk secp256k1 key
│   ├── SecureEnclaveKeyManager.swift  Apple SEP P-256 key (process-cached)
│   ├── TOTPManager.swift              RFC 6238 TOTP
│   ├── BrightNexusPolicy.swift        Peer-attestation mode + TTL ceiling
│   ├── Paths.swift                    Canonical filesystem layout
│   └── Persistence.swift              Core Data scaffolding
├── BrightNexusTests/                  Swift unit tests
├── BrightNexusUITests/                Swift UI tests
├── ENCLAVE_BRIDGE_SPEC.md             EBP/1 specification (preserved)
└── README.md                          You are here
```

### Build dependencies

- [`secp256k1.swift`](https://github.com/GigaBitcoin/secp256k1.swift) (Swift Package Manager) — wraps libsecp256k1 for ECDH and key formats.
- Apple `CryptoKit` — Secure Enclave, AES-GCM, HKDF, HMAC-SHA1 (TOTP).

No third-party Node packages live in this repo. The Node client lives at [`@digitaldefiance/enclave-bridge-client`](https://github.com/Digital-Defiance/enclave-bridge-client).

## Migration from Enclave Bridge

BrightLink is greenfield — there's no migration path because there were no users on a previous version. If you have an old "Enclave Bridge" app installed, the cleanest move is:

1. **Quit and uninstall the old app.** Drag it out of `/Applications` and to the Trash.
2. **Delete `~/.enclave/`** if it exists. Nothing in v1 reads from there.
3. **Launch BrightNexus.** A fresh secp256k1 identity is generated on first use.

The on-disk key file format is the same as the old Enclave Bridge implementation (raw 32-byte secp256k1 private key, mode 0600), but the path has changed and there's no automatic migration. If for some reason you need to preserve a specific secp256k1 identity from a previous install, copy `~/.enclave/ecies-privkey.bin` to `~/.brightchain/brightnexus/ecies-privkey.bin` manually before first launch — but be aware this isn't a supported flow.

## Security model

- **Secure Enclave keys never leave the hardware.** The P-256 private key is created with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and `.privateKeyUsage`.
- **The secp256k1 private key is at rest under POSIX `0600`** in `~/.brightchain/brightnexus/`. For defense-in-depth (encrypted with a user password before being addressed to the bridge), use the [`SecureEnclaveKeyring`](https://github.com/Digital-Defiance/brightchain-api-lib) consumer.
- **Local socket only.** No network listeners.
- **Per-message ephemeral keys** for ECIES; forward secrecy is provided.
- **Optional TOTP 2FA** for `EXPORT_KEY`.

For the BrightLink threat model see [RFC §14](https://github.com/Digital-Defiance/bsh/blob/main/docs/rfc-brightlink.md#14-security-considerations).

## Troubleshooting

### Socket connection failed

1. Confirm BrightNexus is running (look for the lock-shield icon in your menu bar).
2. Check the socket: `ls -la ~/.brightchain/brightnexus/brightnexus.sock`.

### Secure Enclave not available

- Apple Silicon (M-series) is required. The Secure Enclave is not exposed on Intel Macs running this app.
- Running inside a VM is not supported.

### Build errors

- Ensure Xcode 15+ is installed.
- Clean build folder (⌘⇧K) and delete DerivedData: `rm -rf ~/Library/Developer/Xcode/DerivedData`.

## Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Make focused, well-described commits.
4. Open a pull request against `main`.

## License

MIT — see [LICENSE](LICENSE).

## Related

- [bsh (BrightShell)](https://github.com/Digital-Defiance/bsh) — the shell whose `bsh-inject` builtin delivers BrightLink credentials.
- [`@digitaldefiance/enclave-bridge-client`](https://github.com/Digital-Defiance/enclave-bridge-client) — TypeScript client.
- [`@digitaldefiance/node-ecies-lib`](https://www.npmjs.com/package/@digitaldefiance/node-ecies-lib) — ECIES wire format used over EBP/1.
- [BrightChain](https://github.com/Digital-Defiance/BrightChain) — the platform consuming this bridge.

---

<p align="center">Made with ❤️ by <a href="https://github.com/Digital-Defiance">Digital Defiance</a></p>
