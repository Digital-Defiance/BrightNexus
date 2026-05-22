// BridgeIdentity.swift
// BrightNexus
//
// Cross-platform abstraction for the bridge's persistent signing identity
// (RFC §6.1). The identity signs:
//   - The §4.5 LINK_REGISTER transcript that every client TOFU-pins.
//   - The §7.2 geo-acl.json document and the §8 geo-zones.json document.
//   - Any future BridgeLink v1.x signed-config files.
//
// Three implementations are normative; macOS Apple Silicon ships
// `SepBridgeIdentity` (Secure Enclave-resident P-256 key). The Linux
// port (a future wave) will land `Tpm2BridgeIdentity` and
// `FileBridgeIdentity`. The protocol surface is identical across all
// three so the rest of the bridge code path doesn't care which is in use.

import CryptoKit
import Foundation

/// Kinds of `BridgeIdentity` implementations (RFC §6.1). Surfaced through
/// the §4.5 transcript and the bridge's startup log so clients can refuse
/// to register against software-backed bridges.
enum BridgeIdentityKind: String, Codable {
    case sep  = "SepBridgeIdentity"   // macOS Apple Silicon — Secure Enclave
    case tpm2 = "Tpm2BridgeIdentity"  // Linux with TPM2
    case file = "FileBridgeIdentity"  // any POSIX (software fallback)
}

/// The cross-platform signing-identity surface. RFC §6.1.
protocol BridgeIdentity {
    /// Stable id derived from the public key. Format: `"p256:<base64-prefix-16>"`.
    var keyId: String { get }

    /// 65-byte uncompressed P-256 public key (X9.63 form: `0x04 || x(32) || y(32)`).
    func publicKey() throws -> Data

    /// SHA-256-then-ECDSA-sign the data; returns DER-encoded signature.
    /// Matches Apple CryptoKit's `priv.signature(for:)` semantics so the
    /// transcript signature path is identical to the legacy code.
    func sign(data: Data) throws -> Data

    /// Which `BridgeIdentity` implementation this is. Logged at startup.
    var kind: BridgeIdentityKind { get }
}

/// Compute the §6.1 key id from a 65-byte uncompressed P-256 public key.
/// Format: `"p256:" + base64url(SHA-256(pub))[0..16]` (16-byte prefix,
/// base64url-encoded, no padding).
func computeBridgeKeyId(publicKey65: Data) throws -> String {
    guard publicKey65.count == 65, publicKey65[0] == 0x04 else {
        throw BridgeIdentityError.invalidPublicKeyShape(
            "bridge identity public key must be 65 bytes uncompressed (got \(publicKey65.count))"
        )
    }
    let digest = SHA256.hash(data: publicKey65)
    let prefix16 = Data(Array(digest.prefix(16)))
    let b64url = prefix16.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return "p256:\(b64url)"
}

enum BridgeIdentityError: Error, CustomStringConvertible {
    case invalidPublicKeyShape(String)
    case sepUnavailable(String)
    case signFailed(String)

    var description: String {
        switch self {
        case .invalidPublicKeyShape(let m): return "invalid public key shape: \(m)"
        case .sepUnavailable(let m):        return "SEP unavailable: \(m)"
        case .signFailed(let m):            return "sign failed: \(m)"
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// SepBridgeIdentity — the macOS Apple Silicon implementation.
//
// Wraps the existing `SecureEnclaveKeyManager` so the §4.5 transcript
// signing path is unchanged. The new responsibilities (signing
// `geo-acl.json` and `geo-zones.json`) flow through the same SEP key.
// ────────────────────────────────────────────────────────────────────────────

final class SepBridgeIdentity: BridgeIdentity {
    private let cachedKeyId: String
    private let cachedPublicKey: Data

    init() throws {
        // SecureEnclaveKeyManager creates the key on first call and caches
        // it for the process lifetime. We grab the public key once at
        // init so `publicKey()` and `keyId` are constant-time afterwards.
        let pub = try SecureEnclaveKeyManager.getPublicKeyData()
        self.cachedPublicKey = pub
        self.cachedKeyId = try computeBridgeKeyId(publicKey65: pub)
    }

    var keyId: String { cachedKeyId }

    func publicKey() throws -> Data { cachedPublicKey }

    func sign(data: Data) throws -> Data {
        do {
            return try SecureEnclaveKeyManager.sign(data: data)
        } catch {
            throw BridgeIdentityError.signFailed(error.localizedDescription)
        }
    }

    var kind: BridgeIdentityKind { .sep }
}
