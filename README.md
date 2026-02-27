# Enclave Bridge

<p align="center">
  <img src="EnclaveBridge.svg" alt="Enclave Bridge Logo" width="128" height="128">
</p>

<p align="center">
  <strong>A secure bridge between Node.js and Apple's Secure Enclave</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#api-reference">API</a> •
  <a href="#development">Development</a>
</p>

### Available on the [Apple App Store](https://apps.apple.com/us/app/enclave-bridge/id6758280835?mt=12)

---

## Overview

**Enclave Bridge** is a macOS status bar application (SwiftUI, Apple Silicon only) that acts as a secure bridge between Node.js applications and the Apple Silicon Secure Enclave. It exposes Secure Enclave cryptographic operations (key generation, signing, decryption) to Node.js via a Unix file socket, using ECIES encryption (secp256k1) compatible with the [@digitaldefiance/node-ecies-lib](https://www.npmjs.com/package/@digitaldefiance/node-ecies-lib) protocol and designed specifically for use with [@digitaldefiance/enclave-bridge-client](https://www.npmjs.com/package/@digitaldefiance/enclave-bridge-client) which is now located here [https://github.com/Digital-Defiance/enclave-bridge-client](https://github.com/Digital-Defiance/enclave-bridge-client).

## Features

- 🔐 **Secure Enclave Integration** - Hardware-backed P-256 keys stored in Apple's Secure Enclave
- 🔑 **ECIES Encryption** - secp256k1 ECIES with AES-256-GCM, fully compatible with `node-ecies-lib`
- 🔌 **Unix Socket IPC** - Fast, secure local communication between Node.js and native macOS
- 📱 **Status Bar App** - Lightweight SwiftUI app running in the menu bar
- 📊 **Real-time Monitoring** - View active connections, key status, and statistics
- 🛡️ **Zero Trust** - All communication encrypted end-to-end with ECIES

- 🔑 **Optional TOTP 2FA** - Per-key two-factor authentication using TOTP (RFC 6238, compatible with Google Authenticator, Authy, etc.)

<img width="1440" height="900" alt="Screenshot 2026-01-25 at 5 26 47 PM" src="https://github.com/user-attachments/assets/3344b75e-4dac-471f-b731-746f3c0cb4e1" />

## Requirements

### macOS App
- macOS 13.0+ (Ventura or later)
- Apple Silicon (M1/M2/M3/M4) - Secure Enclave required
- Xcode 15.0+ (for building)

### Node.js Client
- Node.js 18.0+
- macOS with Enclave app running

## Architecture

```
┌─────────────────────┐     Unix Socket      ┌─────────────────────┐
│                     │   (/tmp/enclave-     │                     │
│   Node.js App       │◄────────────────────►│   Enclave           │
│                     │    bridge.sock)      │   (SwiftUI App)     │
│  ┌───────────────┐  │                      │  ┌───────────────┐  │
│  │ enclave-      │  │   ECIES Encrypted    │  │ ECIES         │  │
│  │ bridge-client │  │◄────────────────────►│  │ (secp256k1)   │  │
│  └───────────────┘  │   JSON Messages      │  └───────────────┘  │
│                     │                      │         │           │
│  ┌───────────────┐  │                      │         ▼           │
│  │ node-ecies-   │  │                      │  ┌───────────────┐  │
│  │ lib           │  │                      │  │ Secure        │  │
│  └───────────────┘  │                      │  │ Enclave       │  │
│                     │                      │  │ (P-256 Keys)  │  │
└─────────────────────┘                      │  └───────────────┘  │
                                             └─────────────────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| **Enclave/** | SwiftUI macOS status bar application |
| **enclave-bridge-client/** | TypeScript/Node.js client library |
| **EnclaveTests/** | Swift unit tests |
| **EnclaveUITests/** | Swift UI automation tests |

## Installation

### Building the macOS App

1. Clone the repository:
   ```bash
   git clone https://github.com/Digital-Defiance/enclave-bridge.git
   cd enclave
   ```

2. Open in Xcode:
   ```bash
   open Enclave.xcodeproj
   ```

3. Build and run (⌘R) or archive for distribution

### Installing the Node.js Client

```bash
npm install @digitaldefiance/enclave-bridge-client
```

Or with yarn:
```bash
yarn add @digitaldefiance/enclave-bridge-client
```

## Quick Start

### 1. Start the Enclave Bridge App

Launch the Enclave Bridge app from your Applications folder or run from Xcode. The app will appear in your menu bar and automatically start the socket server.

### 2. Connect from Node.js

```typescript
import { EnclaveClient } from '@digitaldefiance/enclave-bridge-client';

async function main() {
  // Create and connect client
  const client = new EnclaveClient();
  await client.connect();

  try {
    // Get the secp256k1 public key for ECIES encryption
    const publicKey = await client.getPublicKey();
    console.log('ECIES Public Key:', publicKey.hex);

    // Get the Secure Enclave P-256 public key
    const enclaveKey = await client.getEnclavePublicKey();
    console.log('Enclave Public Key:', enclaveKey.hex);

    // Sign data with Secure Enclave
    const signature = await client.enclaveSign(Buffer.from('Hello, Secure Enclave!'));
    console.log('Signature:', signature.hex);

    // Decrypt ECIES-encrypted data
    const decrypted = await client.decrypt(encryptedBuffer);
    console.log('Decrypted:', decrypted.text);
  } finally {
    await client.disconnect();
  }
}

main().catch(console.error);
```

## API Reference
## TOTP 2FA Support

Enclave Bridge now supports optional per-key TOTP two-factor authentication:

- Enable TOTP for any key via API (returns provisioning URI for authenticator apps)
- Require TOTP code for key export or sensitive actions (if enabled)
- Fully documented in [ENCLAVE_BRIDGE_SPEC.md](ENCLAVE_BRIDGE_SPEC.md)

### Example Usage

1. **Enable TOTP for a key:**
  - Send `ENABLE_TOTP` command with keyId, account, and issuer
  - Receive provisioning URI (scan with Google Authenticator, Authy, etc.)
2. **Export key with TOTP:**
  - Send `EXPORT_KEY` with keyId and TOTP code
  - If TOTP is required and invalid/missing, error is returned

See [ENCLAVE_BRIDGE_SPEC.md](ENCLAVE_BRIDGE_SPEC.md) for full request/response formats.

## End-to-End Testing

E2E tests for TOTP 2FA and all bridge features are included in the enclave-bridge-client repo:

- Run: `npx tsx tests/e2e/enclave-bridge.e2e.ts` from the enclave-bridge-client directory
- Tests cover TOTP enable, provisioning URI, key export with valid/invalid TOTP, and error handling

### Protocol Commands

The bridge uses JSON messages encrypted with ECIES. All communication flows through a handshake process:

| Command | Description |
|---------|-------------|
| `HEARTBEAT` | Liveness check; returns ok + timestamp |
| `VERSION` / `INFO` | App version, build, platform, uptime |
| `STATUS` | Health: peer key set flag, enclave availability |
| `METRICS` | Basic metrics (uptime; counters TBD) |
| `GET_PUBLIC_KEY` | Get the ECIES secp256k1 public key |
| `GET_ENCLAVE_PUBLIC_KEY` | Get the Secure Enclave P-256 public key |
| `SET_PEER_PUBLIC_KEY` | Exchange public keys for encryption |
| `LIST_KEYS` | Enumerate known ECIES/enclave keys |
| `ENCLAVE_SIGN` | Sign data with Secure Enclave P-256 key |
| `ENCLAVE_DECRYPT` | Decrypt data using ECIES |
| `ENCLAVE_GENERATE_KEY` | Generate a new Secure Enclave key (not yet implemented) |
| `ENCLAVE_ROTATE_KEY` | Rotate Secure Enclave key (not supported on current platform) |

#### TODOs
- Implement Secure Enclave key rotation once key retrieval/replacement is supported on the target platform.
- Add real request counters to `METRICS` output.
- `ENCLAVE_GENERATE_KEY`: Currently keys are auto-generated on first use; this command would only be needed for multi-key support.

### Client Methods

```typescript
// Connection
await client.connect();
await client.disconnect();
client.isConnected;  // boolean
client.connectionState;  // 'disconnected' | 'connecting' | 'connected' | 'error'

// Key Operations
await client.getPublicKey();        // Get ECIES public key
await client.getEnclavePublicKey(); // Get Secure Enclave public key

// Cryptographic Operations
await client.enclaveSign(data);     // Sign with Secure Enclave
await client.decrypt(ciphertext);    // Decrypt ECIES data

// Utilities
await client.ping();                 // Health check
```

See the [enclave-bridge-client README](enclave-bridge-client/README.md) for complete API documentation.

## ECIES Protocol Details

Enclave Bridge implements ECIES (Elliptic Curve Integrated Encryption Scheme) with the following parameters:

- **Curve:** secp256k1
- **Symmetric Encryption:** AES-256-GCM
- **Key Derivation:** HKDF (SHA-256, info: 'ecies-v2-key-derivation')
- **Public Keys:** Uncompressed format (0x04 prefix, 65 bytes)

### Message Format

```
[preamble] | version (1) | cipherSuite (1) | type (1) | ephemeralPubKey (65) | iv (16) | authTag (16) | [length (8)] | ciphertext
```

| Field | Bytes | Description |
|-------|-------|-------------|
| version | 1 | Always 0x01 |
| cipherSuite | 1 | 0x01 = secp256k1 + AES-256-GCM + SHA-256 |
| type | 1 | 0x01 = basic, 0x02 = withLength |
| ephemeralPubKey | 65 | Uncompressed secp256k1 public key |
| iv | 16 | Random initialization vector |
| authTag | 16 | GCM authentication tag |
| length | 8 | (Optional) Big-endian length for 'withLength' type |
| ciphertext | varies | Encrypted data |

See [ENCLAVE_BRIDGE_SPEC.md](ENCLAVE_BRIDGE_SPEC.md) for complete protocol specification.

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/Digital-Defiance/enclave-bridge.git
cd enclave

# Install Node.js dependencies
npm install

# Build TypeScript client
cd enclave-bridge-client
npm install
npm run build

# Open Xcode project
open ../Enclave.xcodeproj
```

### Running Tests

**Swift Tests:**
```bash
# In Xcode: ⌘U to run all tests
# Or via command line:
xcodebuild test -project Enclave.xcodeproj -scheme Enclave -destination 'platform=macOS'
```

**TypeScript Client Tests:**
```bash
cd enclave-bridge-client
npm test              # Run all tests
npm run test:unit     # Unit tests only
npm run test:e2e      # End-to-end tests (requires running app)
```

### Project Structure

```
enclave/
├── Enclave/                    # SwiftUI macOS app
│   ├── EnclaveApp.swift        # App entry point
│   ├── ContentView.swift       # Main UI
│   ├── AppState.swift          # Observable state management
│   ├── SocketServer.swift      # Unix socket server
│   ├── ECIES.swift             # ECIES implementation
│   ├── ECIESKeyManager.swift   # secp256k1 key management
│   ├── SecureEnclaveKeyManager.swift  # Secure Enclave integration
│   └── BridgeProtocolHandler.swift    # Protocol handling
├── EnclaveTests/               # Swift unit tests
├── EnclaveUITests/             # Swift UI tests
├── enclave-bridge-client/      # TypeScript client library
│   ├── src/                    # Source code
│   ├── tests/                  # Unit & integration tests
│   └── README.md               # Client documentation
├── scripts/                    # Build & utility scripts
├── ENCLAVE_BRIDGE_SPEC.md      # Protocol specification
└── README.md                   # This file
```

## Security Considerations

- **Secure Enclave keys never leave the hardware** - Private keys are generated and stored in the Secure Enclave
- **All IPC is encrypted** - Communication uses ECIES encryption even over the local socket
- **No network access** - The app only communicates via local Unix sockets
- **Per-session ephemeral keys** - Each ECIES message uses a fresh ephemeral keypair

## Troubleshooting

### Socket Connection Failed

1. Ensure Enclave Bridge app is running (check menu bar)
2. Check socket exists: `ls -la /tmp/enclave-bridge.sock`
3. Verify permissions on the socket file

### Secure Enclave Not Available

- Secure Enclave requires Apple Silicon (M1+) or T2 chip
- Running in a VM is not supported
- Check System Preferences > Security & Privacy for any restrictions

### Build Errors

- Ensure Xcode 15+ is installed
- Clean build folder: ⌘⇧K in Xcode
- Delete DerivedData: `rm -rf ~/Library/Developer/Xcode/DerivedData`

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [@digitaldefiance/node-ecies-lib](https://www.npmjs.com/package/@digitaldefiance/node-ecies-lib) - ECIES implementation for Node.js
- [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit) - Apple's cryptographic framework

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/Digital-Defiance">Digital Defiance</a>
</p>
