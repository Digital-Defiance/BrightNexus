// ECIES.swift
// BrightNexus
//
// Implements ECIES (secp256k1 + AES-256-GCM) compatible with node-ecies-lib v4.0
// (DD-ECIES Basic mode, type byte 0x21). 12-byte IV, 16-byte tag, HKDF-SHA256
// with info "ecies-v2-key-derivation".

import Foundation
import CryptoKit
import P256K


// Real secp256k1 keypair using secp256k1.swift (KeyAgreement API for ECDH)
struct Secp256k1KeyPair {
    let privateKey: P256K.KeyAgreement.PrivateKey
    let publicKey: Data  // uncompressed, 0x04 prefix, 65 bytes
}


class ECIES {
    // Generate ephemeral secp256k1 keypair using secp256k1.swift (KeyAgreement API)
    static func generateEphemeralKeyPair() -> Secp256k1KeyPair {
        let priv = try! P256K.KeyAgreement.PrivateKey()
        let pub = priv.publicKey.dataRepresentation // 65 bytes, 0x04 prefix
        return Secp256k1KeyPair(privateKey: priv, publicKey: pub)
    }

    // Compute ECDH shared secret using secp256k1.swift
    // Accepts: privateKey as P256K.KeyAgreement.PrivateKey, peerPublicKey as Data (compressed or uncompressed)
    // Returns: 32-byte x-coordinate of the shared point (matching node-ecies-lib behavior)
    static func computeSharedSecret(privateKey: P256K.KeyAgreement.PrivateKey, peerPublicKey: Data) -> Data {
        // Accepts: privateKey (P256K.KeyAgreement.PrivateKey), peerPublicKey (33 or 65 bytes)
        let pubKey: P256K.KeyAgreement.PublicKey?
        if peerPublicKey.count == 33 && (peerPublicKey[0] == 0x02 || peerPublicKey[0] == 0x03) {
            pubKey = try? P256K.KeyAgreement.PublicKey(dataRepresentation: peerPublicKey, format: .compressed)
        } else if peerPublicKey.count == 65 && peerPublicKey[0] == 0x04 {
            pubKey = try? P256K.KeyAgreement.PublicKey(dataRepresentation: peerPublicKey, format: .uncompressed)
        } else {
            return Data() // Invalid format
        }
        guard let peerPub = pubKey else { return Data() }
        guard let sharedSecret = try? privateKey.sharedSecretFromKeyAgreement(with: peerPub) else { return Data() }
        // The library returns 33 bytes (compressed point with 02/03 prefix)
        // node-ecies-lib uses only the x-coordinate (32 bytes, strips the prefix)
        let secretBytes = Data(sharedSecret.bytes)
        if secretBytes.count == 33 && (secretBytes[0] == 0x02 || secretBytes[0] == 0x03) {
            return secretBytes.dropFirst() // Return just the 32-byte x-coordinate
        }
        return secretBytes
    }

    // Derive symmetric key using HKDF-SHA256
    static func deriveSymmetricKey(sharedSecret: Data) -> CryptoKit.SymmetricKey {
        let info = "ecies-v2-key-derivation".data(using: .utf8)!
        return CryptoKit.HKDF<CryptoKit.SHA256>.deriveKey(inputKeyMaterial: CryptoKit.SymmetricKey(data: sharedSecret), salt: Data(), info: info, outputByteCount: 32)
    }

    // Encrypt data using AES-256-GCM
    static func encrypt(plaintext: Data, symmetricKey: SymmetricKey, iv: Data, aad: Data) -> (ciphertext: Data, tag: Data)? {
        guard let sealedBox = try? AES.GCM.seal(plaintext, using: symmetricKey, nonce: AES.GCM.Nonce(data: iv), authenticating: aad) else {
            return nil
        }
        return (sealedBox.ciphertext, sealedBox.tag)
    }

    // Decrypt data using AES-256-GCM
    static func decrypt(ciphertext: Data, tag: Data, symmetricKey: SymmetricKey, iv: Data, aad: Data) -> Data? {
        let sealedBox = try? AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ciphertext, tag: tag)
        return sealedBox.flatMap { try? AES.GCM.open($0, using: symmetricKey, authenticating: aad) }
    }

    // MARK: - DD-ECIES Basic-mode envelope helpers
    //
    // These produce/consume the canonical wire format pinned by RFC §4.5.0:
    //
    //   version(1) | cipherSuite(1) | type(1) | ephPubCompressed(33) |
    //   iv(12)     | tag(16)        | ciphertext(N)
    //
    // Used by LINK_REGISTER to encrypt `bridgeShare` back to the client's
    // ephemeral public key, and (in future passes) by any other path that
    // needs to address an outbound payload to a specific secp256k1 peer.

    /// Encrypt `plaintext` to `recipientPubUncompressed` (65-byte 0x04-prefixed)
    /// as a DD-ECIES Basic-mode envelope. Returns the full wire bytes.
    /// `iv` MUST be exactly 12 bytes per DD-ECIES §9.2.
    static func encryptBasicEnvelope(
        plaintext: Data,
        recipientPubUncompressed: Data
    ) throws -> Data {
        guard recipientPubUncompressed.count == 65,
              recipientPubUncompressed.first == 0x04 else {
            throw NSError(
                domain: "ECIES",
                code: -10,
                userInfo: [NSLocalizedDescriptionKey:
                            "recipient public key must be 65-byte uncompressed (0x04 prefix)"]
            )
        }

        // Generate ephemeral keypair.
        let eph = generateEphemeralKeyPair()
        // Compress ephemeral public key for the wire (33 bytes per RFC §4.5.0 / DD-ECIES §5.2).
        // The KeyAgreement.PublicKey.dataRepresentation in current
        // secp256k1.swift returns the compressed form by default, but we
        // normalize defensively in case a future library version changes.
        let ephPubCompressed: Data
        do {
            ephPubCompressed = try ECIESKeyManager.toCompressed(eph.publicKey)
        } catch {
            throw NSError(
                domain: "ECIES",
                code: -11,
                userInfo: [NSLocalizedDescriptionKey:
                            "Failed to compress ephemeral public key: \(error.localizedDescription)"]
            )
        }
        guard ephPubCompressed.count == 33 else {
            throw NSError(
                domain: "ECIES",
                code: -11,
                userInfo: [NSLocalizedDescriptionKey:
                            "compressed ephemeral pub not 33 bytes (\(ephPubCompressed.count))"]
            )
        }

        // ECDH against the recipient.
        let shared = computeSharedSecret(
            privateKey: eph.privateKey,
            peerPublicKey: recipientPubUncompressed
        )
        guard !shared.isEmpty else {
            throw NSError(
                domain: "ECIES",
                code: -12,
                userInfo: [NSLocalizedDescriptionKey: "ECDH failed"]
            )
        }

        let aesKey = deriveSymmetricKey(sharedSecret: shared)

        // 12-byte IV (RFC §5.2 / DD-ECIES §9.2).
        var iv = Data(count: 12)
        let rc = iv.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 12, $0.baseAddress!)
        }
        guard rc == errSecSuccess else {
            throw NSError(
                domain: "ECIES",
                code: -13,
                userInfo: [NSLocalizedDescriptionKey: "Failed to generate IV"]
            )
        }

        // AAD per DD-ECIES §10.2.5: version || cipherSuite || type || ephPub.
        let version: UInt8 = 0x01
        let cipherSuite: UInt8 = 0x01
        let encType: UInt8 = 0x21 // Basic mode
        var aad = Data()
        aad.append(version); aad.append(cipherSuite); aad.append(encType)
        aad.append(ephPubCompressed)

        guard let (ciphertext, tag) = encrypt(
            plaintext: plaintext,
            symmetricKey: aesKey,
            iv: iv,
            aad: aad
        ) else {
            throw NSError(
                domain: "ECIES",
                code: -14,
                userInfo: [NSLocalizedDescriptionKey: "AES-GCM encrypt failed"]
            )
        }

        var out = Data(capacity: 1 + 1 + 1 + 33 + 12 + 16 + ciphertext.count)
        out.append(version); out.append(cipherSuite); out.append(encType)
        out.append(ephPubCompressed)
        out.append(iv)
        out.append(tag)
        out.append(ciphertext)
        return out
    }

    /// Compress a secp256k1 public key into the 33-byte compressed form
    /// (`0x02|0x03 || x`). Accepts:
    ///   - 65 bytes with `0x04` prefix (uncompressed: `0x04 || x || y`)
    ///   - 64 bytes (raw: `x || y`, no prefix)
    ///   - 33 bytes already-compressed (returned as-is)
    /// Returns empty Data if input is malformed.
    ///
    /// Compression rule: prefix is 0x02 if y is even, 0x03 if y is odd.
    /// y's parity is the parity of its last byte (since y is a 256-bit
    /// big-endian integer).
    ///
    /// Kept for backward compatibility with any future caller. Prefer
    /// `ECIESKeyManager.toCompressed(_:)` which throws on malformed input
    /// rather than silently returning empty Data.
    static func compressSecp256k1PublicKey(_ uncompressed: Data) -> Data {
        return (try? ECIESKeyManager.toCompressed(uncompressed)) ?? Data()
    }
}
