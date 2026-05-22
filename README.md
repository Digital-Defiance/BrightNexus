# BrightNexus

<p align="center">
  <img height="75" alt="brightnexus" src="https://github.com/user-attachments/assets/462ecf30-d91f-469e-a82d-1bcc17ad0e6b" />
</p>


<p align="center">
  <strong>Apple Secure Enclave bridge + SDI agent for the BrightChain stack</strong>
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
  <a href="https://brightnexus.brightdate.org">brightnexus.brightdate.org</a> · <a href="ENCLAVE_BRIDGE_SPEC.md">EBP/1 spec</a> · <a href="https://github.com/Digital-Defiance/bsh/blob/main/docs/rfc-sdi-osc7777-enclave-bridge.md">SDI-EB v3 RFC</a>
</p>

> **Renamed from Enclave Bridge.** This project was previously known as **Enclave Bridge**. It still implements the [Enclave Bridge Protocol (EBP/1)](https://github.brightchain.org/docs/papers/enclave-bridge-protocol/) — that wire surface is unchanged — and it now also acts as the **SDI agent** under the [SDI-EB v3 specification](https://github.brightchain.org/docs/papers/sdi-enclave-bridge/), absorbing the role previously filled by the standalone `bsh-encrypted-credentials-management/SDIAgent` daemon. See the [migration notes](#migration-from-enclave-bridge) below.

---

## Overview

**BrightNexus** is a macOS status-bar application (SwiftUI, Apple Silicon) that:

1. Bridges Node.js applications to Apple's **Secure Enclave** (P-256 hardware signing) and to a host-resident **secp256k1** ECIES key, exposed over a Unix domain socket via the Enclave Bridge Protocol (EBP/1). This is the original Enclave Bridge functionality, preserved bit-for-bit.
2. Hosts the **SDI (Secure Semantic Data Injection)** agent surface defined in the [SDI-EB v3 RFC](https://github.brightchain.org/docs/papers/sdi-enclave-bridge/), receiving `SDI_INGEST` Shell→Agent traffic from `bsh` and surfacing the resulting credentials in a menu-bar dropdown and a Dashboard "Credentials" view. The shell — not the terminal emulator — is the OSC 7777 capture point in v3 (RFC §4.6.1).

BrightNexus is part of the [BrightChain](https://github.brightchain.org) project. Its bundle ID is `org.digitaldefiance.brightchain.BrightNexus`.

## Features

- 🔐 **Apple Secure Enclave Integration** — Hardware-backed P-256 signing keys.
- 🔑 **secp256k1 ECIES** — secp256k1 + AES-256-GCM (12-byte IV, 16-byte tag) + HKDF-SHA256, byte-compatible with [`@digitaldefiance/node-ecies-lib`](https://www.npmjs.com/package/@digitaldefiance/node-ecies-lib) v4 (DD-ECIES Basic mode).
- 🔌 **Unix-socket IPC** — local-only, owner-only (mode 0600).
- 📊 **Status-bar UI** — connection count, request count, key fingerprints, and a **Credentials** submenu listing every active SDI payload with click-to-copy and live TTL countdowns.
- 🖥️ **Dashboard Credentials view** — list-style sibling of the menu-bar dropdown, with Clear All toolbar action.
- 🔑 **Optional TOTP 2FA** — RFC 6238, scannable provisioning URIs.
- 🛰️ **SDI agent role** — `SDI_REGISTER` (RFC §4.5), `SDI_INGEST` (§4.9), and `SDI_PUSH` (§4.7 subscribe) are implemented. Geo (`SDI_GEO_*`) and audit (`SDI_AUDIT_EMIT`) ship in subsequent passes.

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
│  bsh shell (or any   │  ~/.brightchain/brightnexus/ │  BrightNexus (SwiftUI)     │
│  v3-aware client)    │  brightnexus.sock            │                            │
│                      │                              │  BridgeProtocolHandler     │
│ ┌──────────────────┐ │  EBP/1 + SDI-EB v3 JSON      │  ├─ ECIES (secp256k1)      │
│ │ bsh-inject       │ │  ──────────────────────────► │  ├─ SecureEnclaveKeyMgr    │
│ │ (Path A: direct) │ │                              │  ├─ SDI_REGISTER (§4.5)    │
│ └──────────────────┘ │                              │  ├─ SDI_INGEST  (§4.9) ──┐ │
│ ┌──────────────────┐ │                              │  └─ SDI_PUSH    (§4.7)   │ │
│ │ PTY-proxy stream │ │                              │                          │ │
│ │ filter           │ │                              │           │              │ │
│ │ (Path B: scrape) │ │                              │           ▼              │ │
│ └──────────────────┘ │                              │  ┌──────────────────┐    │ │
└──────────────────────┘                              │  │ Apple SEP        │    │ │
                                                      │  │ (P-256 hardware) │    │ │
                                                      │  └──────────────────┘    │ │
                                                      │                          │ │
                                                      │  ┌──────────────────┐    │ │
                                                      │  │ EphemeralStore  ◄┼────┘ │
                                                      │  │ + menu-bar UI    │      │
                                                      │  │ + Dashboard view │      │
                                                      │  └──────────────────┘      │
                                                      └────────────────────────────┘
```

Both ingestion paths (Path A `bsh-inject` direct delivery; Path B PTY-proxy stream filter that scrapes OSC 7777 from subprocess stdout) feed the same `SDI_INGEST` endpoint with a shared per-direction monotonic counter (RFC §4.6.4).

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

The TypeScript client's package name is unchanged; the wire surface it speaks is unchanged. A `brightnexus-client` shim package may follow as v3 SDI commands ship.

### Sanity-checking the socket

With the app running:

```bash
printf '%s' '{"cmd":"HEARTBEAT"}' \
  | nc -U ~/.brightchain/brightnexus/brightnexus.sock
# {"ok":true,"timestamp":"2026-05-21T17:02:11Z","service":"enclave-bridge"}
```

A successful `HEARTBEAT` confirms the socket is bound and the protocol handler is dispatching.

## Paths and configuration

BrightNexus stores its state under a single per-user directory tree, mode `0700` throughout:

```
~/.brightchain/                                  vendor namespace (umbrella)
~/.brightchain/brightnexus/                      this app's state
~/.brightchain/brightnexus/brightnexus.sock      primary EBP/1 + SDI socket
~/.brightchain/brightnexus/ecies-privkey.bin     secp256k1 private key (mode 0600)
~/.brightchain/brightnexus/totp-config.json      TOTP secrets (mode 0600)
~/.brightchain/brightnexus/brightnexus.geo.path  pointer to live geo socket (v3)
~/.brightchain/brightnexus/brightnexus-<rand>.geo.sock  geo query socket (v3)
```

SDI-EB v3 is greenfield — there are no legacy paths to migrate from and no compatibility sockets. If you previously ran the original "Enclave Bridge" app or the standalone "SDI Agent" daemon, their state files at `~/.enclave/` are not consulted; you can delete them at your convenience.

### Discovery order for clients

1. `${BRIGHTNEXUS_SOCKET}` — environment override (reserved name).
2. `${HOME}/.brightchain/brightnexus/brightnexus.sock` — canonical.

There are no further fallbacks. A v3-aware client that finds neither path treats the bridge as unavailable.

## Protocol

### EBP/1 (current and stable)

| Command | Description |
|---|---|
| `HEARTBEAT` | Liveness probe |
| `VERSION` / `INFO` | App version, build, platform, uptime, `app: "brightnexus"` |
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

### SDI-EB v3

The SDI surface implements three commands today and reserves the rest. v3-aware clients can detect the reserved-but-not-yet-shipped commands by their stable `"<COMMAND> not implemented in this build"` error string, distinguishing a v3 BrightNexus from an older EBP/1-only bridge that returns `"Unknown command"`.

| Command | Status | Purpose |
|---|---|---|
| `SDI_REGISTER` | implemented | Establish a v3 SDI session — bilateral HKDF over secp256k1 ECIES, 234-byte canonical transcript signed by SEP P-256, TOFU pin (RFC §4.5). |
| `SDI_INGEST` | implemented | Shell → Agent OSC 7777 ingestion. Decrypts under `K_session`, validates direction tag and replay window, drops the payload into `EphemeralStore` for menu-bar / Dashboard display (RFC §4.9). |
| `SDI_PUSH` | subscribe implemented; emit reserved | Agent → Shell long-lived push subscription channel (RFC §4.7). The bridge accepts subscribe/unsubscribe today; outbound push events ship with the geo work. |
| `SDI_GEO_GET` / `SDI_GEO_STATUS` / `SDI_GEO_REFRESH` | reserved | Geo-context queries (RFC §8.1–8.3). |
| `SDI_GEO_AUDIT` | reserved | Audit log query (RFC §8.4). |
| `SDI_AUDIT_EMIT` | reserved | Shell → bridge audit-event emit (RFC §8.5). |

Full v3 specification: [SDI-EB v3 RFC](https://github.com/Digital-Defiance/bsh/blob/main/docs/rfc-sdi-osc7777-enclave-bridge.md).

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
│   ├── BrightNexusApp.swift           App entry point + status-bar Credentials submenu
│   ├── ContentView.swift              Main UI (Dashboard, Credentials, Connections, Keys)
│   ├── AppState.swift                 Observable state (incl. published `credentials`)
│   ├── SocketServer.swift             Unix-socket server (single canonical socket)
│   ├── BridgeProtocolHandler.swift    EBP/1 + SDI-EB v3 dispatch (REGISTER, INGEST)
│   ├── SdiSession.swift               Bilateral HKDF + 234-byte canonical transcript
│   ├── Osc7777Frame.swift             OSC 7777 v3 codec (parser + AAD builder)
│   ├── SDIPayload.swift               §5 payload schemas decoder
│   ├── EphemeralStore.swift           Thread-safe credential store with TTL sweeper
│   ├── ECIES.swift                    secp256k1 + AES-256-GCM
│   ├── ECIESKeyManager.swift          On-disk secp256k1 key
│   ├── SecureEnclaveKeyManager.swift  Apple SEP P-256 key (process-cached)
│   ├── TOTPManager.swift              RFC 6238 TOTP
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

SDI-EB v3 is greenfield — there's no migration path because there were no users on a previous version. If you have an old "Enclave Bridge" app or "SDI Agent" daemon installed, the cleanest move is:

1. **Quit and uninstall the old apps.** Drag them out of `/Applications` and to the Trash.
2. **Delete `~/.enclave/`** if it exists. Nothing in v3 reads from there.
3. **Launch BrightNexus.** A fresh secp256k1 identity is generated on first use.
4. **The Mac App Store listing is retired.** If you installed via TestFlight or Mac App Store, delete `Enclave Bridge.app` from `/Applications`.

The on-disk key file format is the same as the old Enclave Bridge implementation (raw 32-byte secp256k1 private key, mode 0600), but the path has changed and there's no automatic migration. If for some reason you need to preserve a specific secp256k1 identity from a previous install, copy `~/.enclave/ecies-privkey.bin` to `~/.brightchain/brightnexus/ecies-privkey.bin` manually before first launch — but be aware this isn't a supported flow.

## Security model

- **Secure Enclave keys never leave the hardware.** The P-256 private key is created with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and `.privateKeyUsage`.
- **The secp256k1 private key is at rest under POSIX `0600`** in `~/.brightchain/brightnexus/`. For defense-in-depth (encrypted with a user password before being addressed to the bridge), use the [`SecureEnclaveKeyring`](https://github.com/Digital-Defiance/brightchain-api-lib) consumer.
- **Local socket only.** No network listeners.
- **Per-message ephemeral keys** for ECIES; forward secrecy is provided.
- **Optional TOTP 2FA** for `EXPORT_KEY`.

For the v3 SDI surface threat model see [RFC §9 and §11](https://github.com/Digital-Defiance/bsh/blob/main/docs/rfc-sdi-osc7777-enclave-bridge.md).

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

- [bsh (BrightShell)](https://github.com/Digital-Defiance/bsh) — the shell that emits OSC 7777 SDI sequences.
- [`@digitaldefiance/enclave-bridge-client`](https://github.com/Digital-Defiance/enclave-bridge-client) — TypeScript client.
- [`@digitaldefiance/node-ecies-lib`](https://www.npmjs.com/package/@digitaldefiance/node-ecies-lib) — ECIES wire format used over EBP/1.
- [BrightChain](https://github.com/Digital-Defiance/BrightChain) — the platform consuming this bridge.

---

<p align="center">Made with ❤️ by <a href="https://github.com/Digital-Defiance">Digital Defiance</a></p>
