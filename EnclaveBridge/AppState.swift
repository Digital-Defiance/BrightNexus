// AppState.swift
// Enclave Bridge
//
// Observable state for the app - tracks connections and keys

import Foundation
import Combine
import CryptoKit

/// Represents an active client connection
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

/// Represents a cryptographic key (metadata only, not the actual key)
struct KeyInfo: Identifiable {
    let id: String  // Fingerprint or identifier
    let type: KeyType
    let createdAt: Date
    let publicKeyFingerprint: String
    let isSecureEnclave: Bool
    let totpSecret: String? // Optional TOTP secret
    let totpProvisioningURI: String? // Optional provisioning URI
    
    enum KeyType: String {
        case secp256k1 = "secp256k1"
        case secureEnclave = "Secure Enclave (P-256)"
    }
}

/// Central app state - published to SwiftUI views
@MainActor
class AppState: ObservableObject {
            // Validate TOTP code for a key (returns true if valid or not required)
            func validateTOTP(forKeyId keyId: String, code: String?) -> Bool {
                let key = keys.first(where: { $0.id == keyId })
                guard let totpSecret = key?.totpSecret else {
                    return true // No TOTP required
                }
                guard let code = code else { return false }
                return TOTPManager.validateTOTP(secret: totpSecret, code: code)
            }
        // Enable TOTP for a key, returns provisioning URI
        func enableTOTP(forKeyId keyId: String, account: String, issuer: String) -> String? {
            let secret = TOTPManager.generateSecret()
            let uri = TOTPManager.provisioningURI(secret: secret, account: account, issuer: issuer)
            // Save to config file
            let totpConfigPath = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".enclave/totp-config.json").path
            var totpConfig: [String: [String: String]] = [:]
            if let data = try? Data(contentsOf: URL(fileURLWithPath: totpConfigPath)),
               let dict = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] {
                totpConfig = dict
            }
            totpConfig[keyId] = ["secret": secret, "uri": uri]
            if let data = try? JSONSerialization.data(withJSONObject: totpConfig, options: .prettyPrinted) {
                try? data.write(to: URL(fileURLWithPath: totpConfigPath))
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
    
    private init() {
        loadKeys()
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
        // Always increment total requests, even if connection was already removed
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

        // Example: Load TOTP config from disk (replace with real persistence)
        let totpConfigPath = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".enclave/totp-config.json").path
        var totpConfig: [String: [String: String]] = [:]
        if let data = try? Data(contentsOf: URL(fileURLWithPath: totpConfigPath)),
           let dict = try? JSONSerialization.jsonObject(with: data) as? [String: [String: String]] {
            totpConfig = dict
        }

        // Load secp256k1 ECIES key info
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

        // Load Secure Enclave key info
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
        // SHA-256 fingerprint, show first 8 bytes as hex
        let hash = SHA256.hash(data: data)
        let fingerprint = hash.prefix(8).map { String(format: "%02x", $0) }.joined(separator: ":")
        return fingerprint.uppercased()
    }
    
    private func getKeyCreationDate(for keyType: String) -> Date? {
        // Try to get file modification date for the key file
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let keyPath: String
        switch keyType {
        case "ecies":
            keyPath = home + "/.enclave/ecies-privkey.bin"
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
