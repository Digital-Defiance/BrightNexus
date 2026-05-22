// SecureEnclaveKeyManager.swift
// BrightNexus
//
// Handles Apple Secure Enclave (SEP) P-256 key generation, storage, and signing.
// "Secure Enclave" here refers to Apple's hardware coprocessor on Apple Silicon —
// the term is preserved verbatim to match the platform's terminology.
//
// ## Key lifetime — important
//
// CryptoKit's `SecureEnclave.P256.Signing.PrivateKey` does NOT have a public
// initializer that loads a key by keychain tag. The only way to get a usable
// instance is to either (a) generate a fresh key, or (b) hold on to the
// instance returned by the original `init`. There is no `init(secKey:)` on
// the deployed CryptoKit SDK.
//
// To keep the bridge's identity stable across requests within a process
// lifetime — which LINK_REGISTER (RFC §4.5.3) absolutely requires, since it
// signs a transcript that the client will verify against an earlier
// `GET_ENCLAVE_PUBLIC_KEY` response — we cache the generated `PrivateKey`
// instance in a process-local static. The key dies on app quit, which is
// what the RFC §6.2 "Reload behaviour" note already describes:
//
//   > the server is expected to keep the same key for the application's
//   > lifetime; future revisions may use lower-level SecKey APIs to support
//   > reload across restarts.
//
// Note: the SEP itself persists the key across restarts (it's tagged in the
// keychain via `compactRepresentable: true`'s underlying SecKey). What we
// can't do today is *load* the persisted SEP key back into a CryptoKit
// PrivateKey on a fresh process. So on every cold start, the key handle
// changes — which is fine for our use case because clients TOFU-pin the
// SEP public key on first registration and detect changes (RFC §4.5.5).

import Foundation
import CryptoKit

class SecureEnclaveKeyManager {
    /// Application tag used when querying the keychain for the SEP key entry.
    /// Reserved for a future implementation that uses the lower-level
    /// `SecKey` APIs to support cross-restart reload. Currently informational.
    static let keyTag = "org.digitaldefiance.brightchain.brightnexus.secureenclavekey"

    /// Process-local cache of the SEP private-key handle. Generated lazily on
    /// first access and held for the lifetime of the bridge process.
    private static var cachedKey: SecureEnclave.P256.Signing.PrivateKey?
    private static let cacheLock = NSLock()

    /// Returns the SEP private key, generating one on first call. Subsequent
    /// calls within the same process return the same handle.
    static func getOrCreatePrivateKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        if let cached = cachedKey {
            return cached
        }
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        )!
        let priv = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: true,
            accessControl: access,
            authenticationContext: nil
        )
        cachedKey = priv
        return priv
    }

    /// Returns the SEP public key as 65-byte uncompressed X9.63
    /// (`0x04 || x || y`). EBP/1 §4.6.
    static func getPublicKeyData() throws -> Data {
        let priv = try getOrCreatePrivateKey()
        return priv.publicKey.x963Representation
    }

    /// Signs `data` with the SEP key. Apple CryptoKit's
    /// `priv.signature(for:)` SHA-256-hashes internally before signing,
    /// matching EBP/1 §4.9. Returns DER-encoded ECDSA signature.
    static func sign(data: Data) throws -> Data {
        let priv = try getOrCreatePrivateKey()
        let signature = try priv.signature(for: data)
        return signature.derRepresentation
    }
}
