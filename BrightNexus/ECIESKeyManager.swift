// ECIESKeyManager.swift
// BrightNexus
//
// Handles secp256k1 key generation, storage, and public key export for ECIES protocol.
// The persistent secp256k1 private key is stored at the canonical BrightNexus path
// (see `Paths.swift`); legacy state at `~/.enclave/ecies-privkey.bin` is migrated by
// `BrightNexusPaths.bootstrap()` at app startup.

import Foundation
import Security
import P256K
import Darwin

class ECIESKeyManager {
    /// Reserved Keychain access-group / application-tag value. Currently unused (the private
    /// key is held in a flat file under `~/.brightchain/brightnexus/`); reserved for a future
    /// Keychain-backed implementation.
    static let keyTag = "org.digitaldefiance.brightchain.brightnexus.ecieskey"

    /// Path to the on-disk secp256k1 private key (raw 32 bytes, mode 0600).
    static var privKeyFile: String {
        BrightNexusPaths.eciesPrivKey.path
    }

    /// Returns the secp256k1 public key in canonical 65-byte uncompressed
    /// form (`0x04 || x || y`).
    ///
    /// EBP/1 §4.5 specifies `GET_PUBLIC_KEY` returns 65-byte uncompressed.
    /// `P256K.KeyAgreement.PublicKey.dataRepresentation` honors whatever
    /// format the key was internally constructed with — which is compressed
    /// by default in current `secp256k1.swift`. We round-trip through
    /// `P256K.Signing.PublicKey`, which exposes `uncompressedRepresentation`
    /// (Asymmetric.swift:168), to canonicalize.
    static func getOrCreateSecp256k1PublicKey() throws -> Data {
        let privKey = try getOrCreateSecp256k1PrivateKeyObject()
        let raw = privKey.publicKey.dataRepresentation
        return try Self.toUncompressed(raw)
    }

    /// Normalize secp256k1 public-key bytes into the 65-byte uncompressed
    /// form. Accepts the three RFC §4.5.0 / DD-ECIES §5.3 input shapes:
    ///   - 33-byte compressed (0x02|0x03 prefix)
    ///   - 65-byte uncompressed (0x04 prefix) — returned as-is
    ///   - 64-byte raw (no prefix) — wrapped with 0x04 prefix
    static func toUncompressed(_ bytes: Data) throws -> Data {
        if bytes.count == 65 && bytes.first == 0x04 {
            return bytes
        }
        if bytes.count == 64 {
            var out = Data(capacity: 65)
            out.append(0x04)
            out.append(bytes)
            return out
        }
        if bytes.count == 33 && (bytes.first == 0x02 || bytes.first == 0x03) {
            // Round-trip via Signing.PublicKey to leverage
            // `uncompressedRepresentation` (Asymmetric.swift:168).
            let signingPub = try P256K.Signing.PublicKey(
                dataRepresentation: bytes,
                format: .compressed
            )
            return signingPub.uncompressedRepresentation
        }
        throw NSError(
            domain: "ECIESKeyManager", code: -7,
            userInfo: [NSLocalizedDescriptionKey:
                        "Cannot normalize public key of length \(bytes.count) prefix=\(bytes.first.map { String($0) } ?? "n/a")"]
        )
    }

    /// Compress a secp256k1 public key into 33-byte form (`0x02|0x03 || x`).
    /// Accepts the same three input shapes as `toUncompressed`. Used by the
    /// LINK_REGISTER response-envelope encryption path, where the ephemeral
    /// public key inside the ECIES wire format must be 33-byte compressed
    /// per DD-ECIES §5.2.
    static func toCompressed(_ bytes: Data) throws -> Data {
        if bytes.count == 33 && (bytes.first == 0x02 || bytes.first == 0x03) {
            return bytes
        }
        // Build a Signing.PublicKey then ask for its compressed form by
        // constructing in compressed mode. Signing.PublicKey doesn't expose
        // a `compressedRepresentation` property — but the underlying
        // baseKey honors the format of the constructor. We compress by
        // hand using x and the parity of y's last byte.
        let uncompressed = try toUncompressed(bytes)
        // uncompressed = 0x04 || x(32) || y(32)
        let x = uncompressed.subdata(in: 1..<33)
        let yLastByte = uncompressed[64]
        let prefix: UInt8 = (yLastByte & 0x01) == 0 ? 0x02 : 0x03
        var out = Data(capacity: 33)
        out.append(prefix)
        out.append(x)
        return out
    }

    /// Returns the secp256k1 private key (raw 32 bytes).
    static func getOrCreateSecp256k1PrivateKey() throws -> Data {
        let fm = FileManager.default
        let path = privKeyFile
        if fm.fileExists(atPath: path) {
            return try Data(contentsOf: URL(fileURLWithPath: path))
        }
        // Generate new 32-byte random private key.
        var priv = Data(count: 32)
        let result = priv.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!)
        }
        if result != errSecSuccess {
            throw NSError(domain: "ECIESKeyManager", code: -2,
                          userInfo: [NSLocalizedDescriptionKey:
                                        "Failed to generate random secp256k1 private key"])
        }
        try priv.write(to: URL(fileURLWithPath: path), options: .atomic)
        chmod(path, 0o600)
        return priv
    }

    /// Returns the secp256k1 private key as a `P256K.KeyAgreement.PrivateKey` object.
    static func getOrCreateSecp256k1PrivateKeyObject() throws -> P256K.KeyAgreement.PrivateKey {
        let privData = try getOrCreateSecp256k1PrivateKey()
        guard privData.count == 32 else {
            throw NSError(domain: "ECIESKeyManager", code: -5,
                          userInfo: [NSLocalizedDescriptionKey:
                                        "Private key data is not 32 bytes"])
        }
        return try P256K.KeyAgreement.PrivateKey(dataRepresentation: [UInt8](privData))
    }
}
