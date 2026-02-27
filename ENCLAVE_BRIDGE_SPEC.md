## TOTP 2FA API Extensions

### Enable TOTP for a Key

**Command:** `ENABLE_TOTP`

**Request:**
```
{
   "cmd": "ENABLE_TOTP",
   "keyId": "ecies-secp256k1", // or "secure-enclave-p256"
   "account": "user@example.com",
   "issuer": "EnclaveBridge"
}
```

**Response:**
```
{
   "provisioningURI": "otpauth://totp/EnclaveBridge:user@example.com?..."
}
```

### Export Key with TOTP

**Command:** `EXPORT_KEY`

**Request:**
```
{
   "cmd": "EXPORT_KEY",
   "keyId": "ecies-secp256k1", // or "secure-enclave-p256"
   "totpCode": "123456" // Only required if TOTP is enabled for this key
}
```

**Response:**
```
{
   "publicKey": "...base64..."
}
```

If TOTP is required and invalid or missing:
```
{
   "error": "TOTP code required or invalid for this key"
}
```

### List Keys (with TOTP status)

**Command:** `LIST_KEYS`

**Response:**
```
{
   "keys": [
      {
         "id": "ecies-secp256k1",
         "type": "secp256k1",
         "publicKeyFingerprint": "...",
         "isSecureEnclave": false,
         "totpEnabled": true,
         "totpProvisioningURI": "otpauth://totp/..."
      },
      ...
   ]
}
```
## node-ecies-lib: Unique Implementation Details

- **Strict secp256k1 Key Handling:**
   - Always uses uncompressed public keys (0x04 prefix, 65 bytes).
   - Private keys are 32 bytes.
   - Key normalization is enforced before cryptographic operations.

- **Header Structure:**
   - Version (1 byte): Always 0x01.
   - CipherSuite (1 byte): 0x01 for secp256k1 + AES-256-GCM + SHA-256.
   - Type (1 byte): 0x01 (basic) or 0x02 (withLength).
   - Ephemeral Public Key (65 bytes): Always included, uncompressed.
   - IV (16 bytes): Random per message.
   - AuthTag (16 bytes): GCM tag.
   - Length (8 bytes, only for 'withLength' type): Big-endian.
   - Encrypted Data: Ciphertext.

- **AAD (Additional Authenticated Data):**
   - Concatenation of: preamble (if any), version, cipherSuite, type, ephemeralPublicKey.

- **Encryption/Decryption Flow:**
   - Ephemeral keypair generated for each message.
   - ECDH shared secret computed with recipient’s public key.
   - HKDF (SHA-256, info string 'ecies-v2-key-derivation', no salt) derives symmetric key.
   - AES-256-GCM encrypts data, using random IV and AAD.
   - Decryption strictly validates all header fields and sizes.

- **Error Handling:**
   - Throws on invalid key lengths, header mismatches, or decryption/authentication failures.
   - Validates all fields before cryptographic operations.

- **Public Key Exchange:**
   - Both sides must serialize/deserialize secp256k1 keys in the same uncompressed format.
   - Public key advertisement is required before encrypted communication.

- **Compatibility:**
   - All cryptographic operations and message formats must match these details for interoperability with node-ecies-lib.
# Enclave Bridge: Swift Secure Enclave Bridge for NodeJS

## Project Overview
Enclave Bridge is a macOS status bar application (SwiftUI, Apple Silicon only) that acts as a secure bridge between NodeJS and the Apple Silicon Secure Enclave. It exposes Secure Enclave cryptographic operations (key generation, signing, decryption) to NodeJS via a Unix file socket, using ECIES encryption (secp256k1) compatible with the @digitaldefiance/node-ecies-lib protocol.

## Protocol & Compatibility
- **Transport:** Unix file socket (local IPC)
- **Encryption:** ECIES (secp256k1) with AES-256-GCM, HKDF key derivation, matching node-ecies-lib binary format
- **Key Exchange:** Both sides must advertise and exchange public keys at startup
- **Message Format:**
  - [optional preamble] | version (1 byte) | cipherSuite (1) | type (1) | ephemeralPublicKey (65) | iv (16) | authTag (16) | [length (8, if withLength)] | encryptedData
  - Ephemeral public key is always included, uncompressed (0x04 prefix)
  - AAD: preamble, version, cipherSuite, type, ephemeralPublicKey
  - Two main encryption types: "basic" and "withLength" (latter includes 8-byte length prefix)

## API Commands
1. **HEARTBEAT**
   - Request: `{ "cmd": "HEARTBEAT" }`
   - Response: `{ "ok": true, "timestamp": "<ISO8601 timestamp>", "service": "enclave-bridge" }`
2. **VERSION / INFO**
   - Request: `{ "cmd": "VERSION" }`
   - Response: `{ "appVersion": "<version>", "build": "<build>", "platform": "macOS", "uptimeSeconds": <int> }`
3. **STATUS**
   - Request: `{ "cmd": "STATUS" }`
   - Response: `{ "ok": true, "peerPublicKeySet": <bool>, "enclaveKeyAvailable": <bool> }`
4. **METRICS**
   - Request: `{ "cmd": "METRICS" }`
   - Response: `{ "service": "enclave-bridge", "uptimeSeconds": <int>, "requestCounters": {} }` (counters TBD)
5. **GET_PUBLIC_KEY**
   - Request: `{ "cmd": "GET_PUBLIC_KEY" }` (unencrypted or special case)
   - Response: `{ "publicKey": <hex/base64 secp256k1 public key> }`
6. **GET_ENCLAVE_PUBLIC_KEY**
   - Request: `{ "cmd": "GET_ENCLAVE_PUBLIC_KEY" }`
   - Response: `{ "publicKey": <hex/base64 P-256 public key> }`
7. **SET_PEER_PUBLIC_KEY**
   - Request: `{ "cmd": "SET_PEER_PUBLIC_KEY", "publicKey": <peer key> }`
   - Response: `{ "ok": true }`
8. **LIST_KEYS**
   - Request: `{ "cmd": "LIST_KEYS" }`
   - Response: `{ "ecies": [{ "id": "ecies-default", "publicKey": <base64> }], "enclave": [{ "id": "enclave-default", "publicKey": <base64> }] }`
9. **ENCLAVE_SIGN**
   - Request: `{ "cmd": "ENCLAVE_SIGN", "data": <data> }`
   - Response: `{ "signature": <signature> }`
10. **ENCLAVE_DECRYPT**
   - Request: `{ "cmd": "ENCLAVE_DECRYPT", "data": <ciphertext> }`
   - Response: `{ "plaintext": <decrypted> }`
11. **ENCLAVE_GENERATE_KEY**
   - Request: `{ "cmd": "ENCLAVE_GENERATE_KEY" }`
   - Response: `{ "error": "ENCLAVE_GENERATE_KEY not implemented" }` (currently stub)
12. **ENCLAVE_ROTATE_KEY**
   - Request: `{ "cmd": "ENCLAVE_ROTATE_KEY" }`
   - Response: `{ "error": "ENCLAVE_ROTATE_KEY not supported on this platform" }` (pending Secure Enclave support)
- **Error Handling:** All errors returned as `{ "error": "message" }` (encrypted if possible)

## Implementation Notes
- Use CryptoKit or appropriate Swift libraries for secp256k1 and AES-256-GCM
- Secure Enclave operations must use Apple Silicon hardware-backed keys
- NodeJS side uses @digitaldefiance/node-ecies-lib; binary compatibility is critical
- Status bar app must show resident icon and allow quit/status from menu


## node-ecies-lib ECIES Implementation Details (Research)

- **Key Type:** secp256k1 (uncompressed, 0x04 prefix, 65 bytes for public keys)
- **Symmetric Encryption:** AES-256-GCM
- **Key Derivation:** HKDF (SHA-256), with info string 'ecies-v2-key-derivation', no salt
- **Ephemeral Key:** Each message uses a new ephemeral secp256k1 keypair; ephemeral public key is included in the message header
- **Message Format (Single Recipient):**
   - `[optional preamble] | version (1 byte) | cipherSuite (1) | type (1) | ephemeralPublicKey (65) | iv (16) | authTag (16) | [length (8, if withLength)] | encryptedData`
   - `version` is always 1 (0x01)
   - `cipherSuite` is 0x01 for secp256k1 + AES-256-GCM + SHA-256
   - `type` is 0x01 (basic) or 0x02 (withLength)
   - `ephemeralPublicKey` is always present, uncompressed
   - `iv` is 16 bytes, random per message
   - `authTag` is 16 bytes (GCM tag)
   - `length` is present only for 'withLength' type (8 bytes, big-endian)
   - `encryptedData` is the ciphertext
- **AAD (Additional Authenticated Data):**
   - Concatenation of: preamble, version, cipherSuite, type, ephemeralPublicKey
- **Encryption Flow:**
   1. Generate ephemeral secp256k1 keypair
   2. Compute ECDH shared secret with recipient's public key
   3. Derive symmetric key using HKDF
   4. Encrypt data with AES-256-GCM, using random IV and AAD
   5. Output header and ciphertext as above
- **Decryption Flow:**
   1. Parse header, extract ephemeral public key, IV, authTag, and ciphertext
   2. Compute ECDH shared secret with own private key and ephemeral public key
   3. Derive symmetric key using HKDF
   4. Decrypt with AES-256-GCM, using extracted IV, authTag, and AAD
- **Error Handling:**
   - Strict validation of header sizes, key formats, and tag/IV lengths
   - Errors are thrown for invalid keys, mismatched lengths, or decryption failures
- **Public Key Exchange:**
   - Both sides must serialize/deserialize secp256k1 keys in the same format (uncompressed, 0x04 prefix)
   - Public key advertisement is required before encrypted communication

All cryptographic operations in the Swift bridge must match these details exactly for interoperability.

## TODOs
1. Research ECIES format in node-ecies-lib (done)
2. Plan Swift Secure Enclave bridge API (done)
3. Implement file socket server in Swift
4. Implement ECIES (secp256k1) in Swift, matching node-ecies-lib
5. Integrate Secure Enclave operations (keygen, sign, decrypt)
6. Create SwiftUI status bar app shell
7. Test end-to-end with NodeJS client using @digitaldefiance/node-ecies-lib
8. Implement Secure Enclave key generation/rotation flows once platform APIs allow stable retrieval/replacement
9. Add real request counters and surface them via METRICS
10. Implement ENCLAVE_GENERATE_KEY and ENCLAVE_ROTATE_KEY handlers end-to-end

---
This document contains all research and design decisions to date. Resume from here to continue implementation.