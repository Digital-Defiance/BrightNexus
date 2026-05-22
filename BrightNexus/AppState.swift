// AppState.swift
// BrightNexus
//
// Observable state for the app — tracks connections and keys.

import Foundation
import Combine
import CryptoKit

/// Represents an active client connection.
struct ClientConnection: Identifiable, Equatable {
    let id: UUID
    let connectedAt: Date
    let fileDescriptor: Int32
    var lastActivity: Date
    var requestCount: Int

    static func == (lhs: ClientConnection, rhs: ClientConnection) -> Bool {
        lhs.id == rhs.id
    }
}

/// Represents a cryptographic key (metadata only, not the actual key).
struct KeyInfo: Identifiable {
    let id: String  // Stable identifier
    let type: KeyType
    let createdAt: Date
    let publicKeyFingerprint: String
    let isSecureEnclave: Bool
    let totpSecret: String?
    let totpProvisioningURI: String?

    enum KeyType: String, Equatable {
        case secp256k1 = "secp256k1"
        case secureEnclave = "Secure Enclave (P-256)"
    }
}

/// Central app state — published to SwiftUI views.
@MainActor
class AppState: ObservableObject {

    // MARK: - TOTP (RFC 6238)

    /// Validate TOTP code for a key (returns true if valid or not required).
    func validateTOTP(forKeyId keyId: String, code: String?) -> Bool {
        let key = keys.first(where: { $0.id == keyId })
        guard let totpSecret = key?.totpSecret else {
            return true // No TOTP required
        }
        guard let code = code else { return false }
        return TOTPManager.validateTOTP(secret: totpSecret, code: code)
    }

    /// Enable TOTP for a key, returns provisioning URI.
    func enableTOTP(forKeyId keyId: String, account: String, issuer: String) -> String? {
        let secret = TOTPManager.generateSecret()
        let uri = TOTPManager.provisioningURI(secret: secret, account: account, issuer: issuer)

        let totpConfigPath = BrightNexusPaths.totpConfig.path
        var totpConfig: [String: [String: String]] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: totpConfigPath)),
           let dict = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] {
            totpConfig = dict
        }
        totpConfig[keyId] = ["secret": secret, "uri": uri]
        if let data = try? JSONSerialization.data(withJSONObject: totpConfig, options: .prettyPrinted) {
            do {
                try data.write(to: URL(fileURLWithPath: totpConfigPath), options: .atomic)
                _ = chmod(totpConfigPath, 0o600)
            } catch {
                NSLog("[BrightNexus] WARN: failed to write TOTP config to %@: %@",
                      totpConfigPath, error.localizedDescription)
                return nil
            }
        }
        refreshKeys()
        return uri
    }

    static let shared = AppState()

    @Published var connections: [ClientConnection] = []
    @Published var keys: [KeyInfo] = []
    @Published var isServerRunning: Bool = false
    @Published var socketPath: String = ""
    @Published var totalRequestsHandled: Int = 0
    /// Active credential entries from `LINK_DELIVER` (RFC §4.9). Updated on the
    /// main thread by `EphemeralStore.onChange`. The menu bar and Dashboard
    /// "Credentials" view both read this.
    @Published var credentials: [EphemeralStore.Entry] = []
    /// Geo decision audit log (RFC §7.7). Populated by `LinkGeoEngine` via
    /// `MainActorAuditLog`. Bounded to ~1000 most-recent entries.
    @Published var auditLog: [GeoAuditEntry] = []

    /// Single shared ephemeral credential store. Lives for the app's lifetime;
    /// holds nothing across launches by design.
    let ephemeralStore = EphemeralStore()

    private init() {
        loadKeys()
        // Mirror store changes into the published `credentials` array so
        // SwiftUI views and the AppDelegate Combine subscription can react.
        ephemeralStore.onChange = { [weak self] in
            // Already on main thread — `notifyChange` dispatches there.
            self?.credentials = self?.ephemeralStore.activeEntries() ?? []
        }
    }

    // MARK: - Connection Management

    func addConnection(id: UUID, fileDescriptor: Int32) {
        let connection = ClientConnection(
            id: id,
            connectedAt: Date(),
            fileDescriptor: fileDescriptor,
            lastActivity: Date(),
            requestCount: 0
        )
        connections.append(connection)
        objectWillChange.send()
    }

    func removeConnection(id: UUID) {
        connections.removeAll { $0.id == id }
        objectWillChange.send()
    }

    func removeConnection(fileDescriptor: Int32) {
        connections.removeAll { $0.fileDescriptor == fileDescriptor }
        objectWillChange.send()
    }

    func updateConnectionActivity(id: UUID) {
        // Always increment total requests, even if connection was already removed.
        totalRequestsHandled += 1

        if let index = connections.firstIndex(where: { $0.id == id }) {
            connections[index].lastActivity = Date()
            connections[index].requestCount += 1
        }
        objectWillChange.send()
    }

    // MARK: - Key Management

    func loadKeys() {
        var loadedKeys: [KeyInfo] = []

        // Load TOTP config from canonical path.
        let totpConfigPath = BrightNexusPaths.totpConfig.path
        var totpConfig: [String: [String: String]] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: totpConfigPath)),
           let dict = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] {
            totpConfig = dict
        }

        // Load secp256k1 ECIES key info.
        if let pubKeyData = try? ECIESKeyManager.getOrCreateSecp256k1PublicKey() {
            let fingerprint = computeFingerprint(pubKeyData)
            let totp = totpConfig["ecies-secp256k1"]
            let keyInfo = KeyInfo(
                id: "ecies-secp256k1",
                type: .secp256k1,
                createdAt: getKeyCreationDate(for: "ecies") ?? Date(),
                publicKeyFingerprint: fingerprint,
                isSecureEnclave: false,
                totpSecret: totp?["secret"],
                totpProvisioningURI: totp?["uri"]
            )
            loadedKeys.append(keyInfo)
        }

        // Load Secure Enclave (Apple SEP P-256) key info.
        if let pubKeyData = try? SecureEnclaveKeyManager.getPublicKeyData() {
            let fingerprint = computeFingerprint(pubKeyData)
            let totp = totpConfig["secure-enclave-p256"]
            let keyInfo = KeyInfo(
                id: "secure-enclave-p256",
                type: .secureEnclave,
                createdAt: getKeyCreationDate(for: "enclave") ?? Date(),
                publicKeyFingerprint: fingerprint,
                isSecureEnclave: true,
                totpSecret: totp?["secret"],
                totpProvisioningURI: totp?["uri"]
            )
            loadedKeys.append(keyInfo)
        }

        keys = loadedKeys
    }

    func refreshKeys() {
        loadKeys()
    }

    // MARK: - Helpers

    private func computeFingerprint(_ data: Data) -> String {
        // SHA-256 fingerprint, show first 8 bytes as hex.
        let hash = SHA256.hash(data: data)
        let fingerprint = hash.prefix(8).map { String(format: "%02x", $0) }.joined(separator: ":")
        return fingerprint.uppercased()
    }

    private func getKeyCreationDate(for keyType: String) -> Date? {
        let keyPath: String
        switch keyType {
        case "ecies":
            keyPath = BrightNexusPaths.eciesPrivKey.path
        default:
            return nil
        }

        if let attrs = try? FileManager.default.attributesOfItem(atPath: keyPath),
           let creationDate = attrs[.creationDate] as? Date {
            return creationDate
        }
        return nil
    }
}
