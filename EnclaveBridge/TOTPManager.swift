// TOTPManager.swift
// Handles TOTP secret generation, validation, and provisioning URI

import Foundation
import CryptoKit

class TOTPManager {
    static func generateSecret() -> String {
        // Generate a random 20-byte base32 secret
        var bytes = [UInt8](repeating: 0, count: 20)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return base32Encode(bytes)
    }

    static func base32Encode(_ bytes: [UInt8]) -> String {
        // RFC 4648 base32 encoding
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var encoded = ""
        var buffer = 0
        var bitsLeft = 0
        for byte in bytes {
            buffer = (buffer << 8) | Int(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                let index = (buffer >> (bitsLeft - 5)) & 0x1F
                encoded.append(alphabet[index])
                bitsLeft -= 5
            }
        }
        if bitsLeft > 0 {
            let index = (buffer << (5 - bitsLeft)) & 0x1F
            encoded.append(alphabet[index])
        }
        return encoded
    }

    static func provisioningURI(secret: String, account: String, issuer: String) -> String {
        let label = "\(issuer):\(account)"
        let params = "secret=\(secret)&issuer=\(issuer)&algorithm=SHA1&digits=6&period=30"
        return "otpauth://totp/\(label)?\(params)"
    }

    static func validateTOTP(secret: String, code: String, time: Date = Date()) -> Bool {
        // Validate a 6-digit TOTP code for the given secret and time
        guard code.count == 6, let codeInt = Int(code) else { return false }
        let counter = Int(time.timeIntervalSince1970 / 30)
        for offset in -1...1 { // allow +/- 30s window
            if generateTOTP(secret: secret, counter: counter + offset) == codeInt {
                return true
            }
        }
        return false
    }

    static func generateTOTP(secret: String, counter: Int) -> Int {
        // Decode base32 secret
        guard let key = base32Decode(secret) else { return -1 }
        var ctr = UInt64(counter).bigEndian
        let ctrData = Data(bytes: &ctr, count: MemoryLayout<UInt64>.size)
        let hash = Array(HMAC<Insecure.SHA1>.authenticationCode(for: ctrData, using: SymmetricKey(data: key)))
        let offset = Int(hash[hash.count - 1] & 0x0F)
        let truncatedHash = Array(hash[offset..<(offset+4)])
        var code = truncatedHash.reduce(0) { ($0 << 8) | UInt32($1) }
        code &= 0x7FFFFFFF
        code = code % 1000000
        return Int(code)
    }

    static func base32Decode(_ str: String) -> Data? {
        // RFC 4648 base32 decoding
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        var buffer = 0
        var bitsLeft = 0
        var bytes = [UInt8]()
        for char in str.uppercased() {
            guard let index = alphabet.firstIndex(of: char) else { continue }
            buffer = (buffer << 5) | alphabet.distance(from: alphabet.startIndex, to: index)
            bitsLeft += 5
            if bitsLeft >= 8 {
                let byte = UInt8((buffer >> (bitsLeft - 8)) & 0xFF)
                bytes.append(byte)
                bitsLeft -= 8
            }
        }
        return Data(bytes)
    }
}
