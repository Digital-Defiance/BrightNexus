import Foundation
import CryptoKit

class BridgeProtocolHandler {
    private var peerPublicKey: Data?
    private static let startTime = Date()

    // ECIES encryption helper (node-ecies-lib compatible)
    static func eciesEncrypt(plaintext: Data, peerPublicKey: Data) -> Data? {
        // Generate ephemeral keypair
        let eph = ECIES.generateEphemeralKeyPair()
        // Compute shared secret
        let sharedSecret = ECIES.computeSharedSecret(privateKey: eph.privateKey, peerPublicKey: peerPublicKey)
        let symKey = ECIES.deriveSymmetricKey(sharedSecret: sharedSecret)
        // Random IV
        var iv = Data(count: 16)
        _ = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        // Compose AAD: version, cipherSuite, type, ephemeralPub
        let version: UInt8 = 0x01
        let cipherSuite: UInt8 = 0x01
        let encType: UInt8 = 0x01 // basic
        let aad = Data([version, cipherSuite, encType]) + eph.publicKey
        // Encrypt
        guard let (ciphertext, tag) = ECIES.encrypt(plaintext: plaintext, symmetricKey: symKey, iv: iv, aad: aad) else {
            return nil
        }
        // Format: version | cipherSuite | type | ephemeralPub | iv | tag | ciphertext
        var out = Data([version, cipherSuite, encType])
        out.append(eph.publicKey)
        out.append(iv)
        out.append(tag)
        out.append(ciphertext)
        return out
    }

    // Handle incoming data and return response
    func handleMessage(_ data: Data) -> Data {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let cmd = json["cmd"] as? String else {
            return BridgeProtocolHandler.errorResponse("Invalid request format")
        }
        switch cmd {
        case "ENABLE_TOTP":
            guard let keyId = json["keyId"] as? String,
                  let account = json["account"] as? String,
                  let issuer = json["issuer"] as? String else {
                return BridgeProtocolHandler.errorResponse("Missing keyId, account, or issuer")
            }
            if let uri = AppState.shared.enableTOTP(forKeyId: keyId, account: account, issuer: issuer) {
                return BridgeProtocolHandler.jsonResponse(["provisioningURI": uri])
            } else {
                return BridgeProtocolHandler.errorResponse("Failed to enable TOTP for key")
            }
        case "EXPORT_KEY":
            guard let keyId = json["keyId"] as? String else {
                return BridgeProtocolHandler.errorResponse("Missing keyId")
            }
            let totpCode = json["totpCode"] as? String
            // Validate TOTP if required
            let valid = AppState.shared.validateTOTP(forKeyId: keyId, code: totpCode)
            if !valid {
                return BridgeProtocolHandler.errorResponse("TOTP code required or invalid for this key")
            }
            // Export key material (example: public key only)
            if keyId == "ecies-secp256k1" {
                do {
                    let pubKey = try ECIESKeyManager.getOrCreateSecp256k1PublicKey()
                    return BridgeProtocolHandler.jsonResponse(["publicKey": pubKey.base64EncodedString()])
                } catch {
                    return BridgeProtocolHandler.errorResponse("Failed to export ECIES public key: \(error.localizedDescription)")
                }
            } else if keyId == "secure-enclave-p256" {
                do {
                    let pubKey = try SecureEnclaveKeyManager.getPublicKeyData()
                    return BridgeProtocolHandler.jsonResponse(["publicKey": pubKey.base64EncodedString()])
                } catch {
                    return BridgeProtocolHandler.errorResponse("Failed to export Secure Enclave public key: \(error.localizedDescription)")
                }
            } else {
                return BridgeProtocolHandler.errorResponse("Unknown keyId")
            }
        case "HEARTBEAT":
            // Simple heartbeat to check if bridge is alive
            let timestamp = ISO8601DateFormatter().string(from: Date())
            return BridgeProtocolHandler.jsonResponse([
                "ok": true,
                "timestamp": timestamp,
                "service": "enclave-bridge"
            ])
        case "VERSION", "INFO":
            let dict: [String: Any] = [
                "appVersion": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
                "build": Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown",
                "platform": "macOS",
                "uptimeSeconds": Int(Date().timeIntervalSince(Self.startTime))
            ]
            return BridgeProtocolHandler.jsonResponse(dict)
        case "STATUS":
            let enclaveAvailable: Bool
            do {
                _ = try SecureEnclaveKeyManager.getPublicKeyData()
                enclaveAvailable = true
            } catch {
                enclaveAvailable = false
            }
            let dict: [String: Any] = [
                "ok": true,
                "peerPublicKeySet": peerPublicKey != nil,
                "enclaveKeyAvailable": enclaveAvailable
            ]
            return BridgeProtocolHandler.jsonResponse(dict)
        case "METRICS":
            let dict: [String: Any] = [
                "uptimeSeconds": Int(Date().timeIntervalSince(Self.startTime)),
                "service": "enclave-bridge",
                "requestCounters": [:]  // TODO: hook into real counters once available
            ]
            return BridgeProtocolHandler.jsonResponse(dict)
        case "GET_PUBLIC_KEY":
            // Return the secp256k1 public key for ECIES protocol
            do {
                let pubKey = try ECIESKeyManager.getOrCreateSecp256k1PublicKey()
                return BridgeProtocolHandler.jsonResponse(["publicKey": pubKey.base64EncodedString()])
            } catch {
                return BridgeProtocolHandler.errorResponse("Failed to get ECIES public key: \(error.localizedDescription)")
            }
        case "GET_ENCLAVE_PUBLIC_KEY":
            // Only reveal Secure Enclave public key if explicitly requested
            do {
                let pubKey = try SecureEnclaveKeyManager.getPublicKeyData()
                return BridgeProtocolHandler.jsonResponse(["publicKey": pubKey.base64EncodedString()])
            } catch {
                return BridgeProtocolHandler.errorResponse("Failed to get enclave public key: \(error.localizedDescription)")
            }
        case "SET_PEER_PUBLIC_KEY":
            if let keyStr = json["publicKey"] as? String, let keyData = Data(base64Encoded: keyStr) {
                peerPublicKey = keyData
                return BridgeProtocolHandler.jsonResponse(["ok": true])
            } else {
                return BridgeProtocolHandler.errorResponse("Missing or invalid publicKey")
            }
        case "LIST_KEYS":
            // Report available key identifiers and TOTP status
            let keys = AppState.shared.keys.map { key in
                [
                    "id": key.id,
                    "type": key.type.rawValue,
                    "publicKeyFingerprint": key.publicKeyFingerprint,
                    "isSecureEnclave": key.isSecureEnclave,
                    "totpEnabled": key.totpSecret != nil,
                    "totpProvisioningURI": key.totpProvisioningURI ?? ""
                ]
            }
            return BridgeProtocolHandler.jsonResponse(["keys": keys])
        case "ENCLAVE_SIGN":
            guard let dataStr = json["data"] as? String, let dataToSign = Data(base64Encoded: dataStr) else {
                return BridgeProtocolHandler.errorResponse("Missing or invalid data to sign")
            }
            do {
                let signature = try SecureEnclaveKeyManager.sign(data: dataToSign)
                return BridgeProtocolHandler.jsonResponse(["signature": signature.base64EncodedString()])
            } catch {
                return BridgeProtocolHandler.errorResponse("Signing failed: \(error.localizedDescription)")
            }
        case "ENCLAVE_DECRYPT":
            guard let dataStr = json["data"] as? String, let encryptedData = Data(base64Encoded: dataStr) else {
                return BridgeProtocolHandler.errorResponse("Missing or invalid data to decrypt")
            }
            // node-ecies-lib format (IV is 12 bytes, not 16):
            // version(1) + cipherSuite(1) + type(1) + ephemeralPub(33) + iv(12) + tag(16) = 64 bytes minimum for basic
            // Encryption type values: Basic=33(0x21), WithLength=66(0x42), Multiple=99(0x63)
            let ivSize = 12
            let tagSize = 16
            let minHeaderCompressed = 1+1+1+33+ivSize+tagSize  // 64 bytes
            guard encryptedData.count > minHeaderCompressed else {
                return BridgeProtocolHandler.errorResponse("Encrypted data too short")
            }
            var offset = 0
            let version = encryptedData[offset]
            offset += 1
            let cipherSuite = encryptedData[offset]
            offset += 1
            let encType = encryptedData[offset]
            offset += 1
            // Try to detect compressed (33 bytes) or uncompressed (65 bytes) ephemeral public key
            let remaining = encryptedData.count - offset
            let ephemeralPubLen: Int
            if remaining >= 65, encryptedData[offset] == 0x04 {
                ephemeralPubLen = 65
            } else if remaining >= 33, encryptedData[offset] == 0x02 || encryptedData[offset] == 0x03 {
                ephemeralPubLen = 33
            } else {
                return BridgeProtocolHandler.errorResponse("Invalid ephemeral public key format")
            }
            let ephemeralPub = encryptedData.subdata(in: offset..<(offset+ephemeralPubLen))
            offset += ephemeralPubLen
            let iv = encryptedData.subdata(in: offset..<(offset+ivSize))
            offset += ivSize
            let tag = encryptedData.subdata(in: offset..<(offset+tagSize))
            offset += tagSize
            var ciphertext: Data
            // WithLength type = 66 (0x42)
            if encType == 66 {
                guard encryptedData.count >= offset+8 else {
                    return BridgeProtocolHandler.errorResponse("Missing length field")
                }
                let lengthData = encryptedData.subdata(in: offset..<(offset+8))
                offset += 8
                let length = lengthData.withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
                guard encryptedData.count >= offset+Int(length) else {
                    return BridgeProtocolHandler.errorResponse("Ciphertext length mismatch")
                }
                ciphertext = encryptedData.subdata(in: offset..<(offset+Int(length)))
            } else {
                ciphertext = encryptedData.suffix(from: offset)
            }
            // Compose AAD: preamble (none) + version + cipherSuite + type + ephemeralPub
            let aad = Data([version, cipherSuite, encType]) + ephemeralPub
            // Use persistent secp256k1 private key for ECDH
            do {
                let privKey = try ECIESKeyManager.getOrCreateSecp256k1PrivateKeyObject()
                let sharedSecret = ECIES.computeSharedSecret(privateKey: privKey, peerPublicKey: ephemeralPub)
                if sharedSecret.isEmpty {
                    return BridgeProtocolHandler.errorResponse("ECDH failed: empty shared secret")
                }
                let symKey = ECIES.deriveSymmetricKey(sharedSecret: sharedSecret)
                guard let plaintext = ECIES.decrypt(ciphertext: ciphertext, tag: tag, symmetricKey: symKey, iv: iv, aad: aad) else {
                    return BridgeProtocolHandler.errorResponse("Decryption failed")
                }
                return BridgeProtocolHandler.jsonResponse(["plaintext": plaintext.base64EncodedString()])
            } catch {
                return BridgeProtocolHandler.errorResponse("ECDH failed: \(error.localizedDescription)")
            }
        case "ENCLAVE_GENERATE_KEY":
            // TODO: Generate new Secure Enclave key (handled automatically on first use)
            return BridgeProtocolHandler.errorResponse("ENCLAVE_GENERATE_KEY not implemented")
        case "ENCLAVE_ROTATE_KEY":
            // TODO: Implement rotation when Secure Enclave key retrieval/replacement is supported on target platform
            return BridgeProtocolHandler.errorResponse("ENCLAVE_ROTATE_KEY not supported on this platform")
        default:
            return BridgeProtocolHandler.errorResponse("Unknown command: \(cmd)")
        }
    }

    static func jsonResponse(_ dict: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: dict)) ?? Data()
    }
    static func errorResponse(_ message: String) -> Data {
        jsonResponse(["error": message])
    }
}
