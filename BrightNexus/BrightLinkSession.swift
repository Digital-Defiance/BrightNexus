// BrightLinkSession.swift
// BrightNexus
//
// BrightLink session machinery (RFC §4.5).
//
// This file is the Swift counterpart of the test-harness's `mock-brightnexus`
// BrightLink surface. Every constant, byte order, and field offset here is taken
// from the spec and pinned against the harness's known-answer vectors.
//
// The harness's `tests/unit/link-session-key.test.ts` defines the canonical
// `K_session` for a fixed set of inputs; this file's `deriveSessionKey`
// MUST produce the same 32 bytes for the same inputs. If it ever diverges,
// the cross-language interop test suite catches it.
//
// Spec citations:
//   - HKDF info string:                 RFC §4.5.2
//   - bilateral HKDF input layout:      RFC §4.5.2
//   - canonical transcript layout:      RFC §4.5.3 (238 bytes total)
//   - registration handshake errors:    RFC §4.5.6
//   - session expiry:                   RFC §4.1
//   - replay window:                    RFC §4.6.3 (used by future LINK_DELIVER
//                                                    parser; not in this file)

import Foundation
import CryptoKit

enum BrightLinkSession {

    // MARK: - Constants

    /// HKDF info string used for the BrightLink session-key derivation.
    /// CRITICAL: this is "brightlink-session-key-v1" verbatim — the
    /// new BrightLink Protocol v1 string. A typo here breaks all v1
    /// traffic with no useful diagnostic.
    static let sessionKeyHkdfInfo = "brightlink-session-key-v1"

    /// Maximum granted TTL: 8 hours (RFC §4.1).
    static let maxTtlSeconds: Int = 8 * 3600

    /// Future-skew tolerance for `issuedAtBd` validation (RFC §4.5.1).
    static let registrationFutureSkewToleranceSeconds: TimeInterval = 60

    /// Length of the session identifier in bytes. Encoded as 32 lowercase
    /// hex chars on the LINK_DELIVER wire (RFC §4.5.3 / §4.6).
    static let sessionIdLength = 16

    /// Length of `clientShare` and `bridgeShare` (RFC §4.5.1, §4.5.2).
    static let shareLength = 32

    /// Length of `clientNonce` (RFC §4.5).
    static let clientNonceLength = 16

    /// Length of the derived session key (AES-256-GCM key size).
    static let sessionKeyLength = 32

    /// Literal NUL-terminated header for the canonical transcript (RFC §4.5.3).
    static let transcriptHeader: Data = {
        var d = Data("BrightLink v1 transcript".utf8)
        d.append(0x00)
        return d
    }()

    /// Total canonical-transcript byte length. Validated by `buildTranscript`.
    /// 25 (header) + 20 + 69 + 36 + 20 + 36 + 12 + 12 + 8 = 238.
    static let transcriptTotalLength = 238

    // MARK: - LINK_DELIVER (RFC §4.9) constants

    /// AES-GCM nonce length on the wire.
    static let gcmIvLength = 12
    /// AES-GCM auth-tag length.
    static let gcmTagLength = 16
    /// Replay-protection window. RFC §4.6.4. Receivers accept counters
    /// strictly greater than `lastAccepted`, up to `lastAccepted + replayWindow`.
    static let replayWindow: UInt64 = 1000

    /// Direction-tag values for the §4.6.3 length-prefixed AAD.
    enum Direction: UInt8 {
        case shellToAgent = 0x01
        case agentToShell = 0x02
    }

    /// Build the AES-256-GCM AAD for a `LINK_DELIVER` packet, RFC §4.6.3:
    ///
    ///   AAD = LE32(1) ‖ dir_tag(1)
    ///      ‖ LE32(len(counter_bytes)) ‖ counter_bytes(8 BE)
    ///      ‖ LE32(len(type_bytes))    ‖ type_bytes
    ///      ‖ LE32(len(context_bytes)) ‖ context_bytes
    ///
    /// The leading `LE32(1)` is the length prefix of the single-byte
    /// `dir_tag` field. Don't drop it — its presence keeps the AAD scheme
    /// uniformly length-prefixed.
    static func buildDeliverAad(
        direction: Direction,
        counter: UInt64,
        type: String,
        contextBytes: Data
    ) -> Data {
        var aad = Data()
        appendLE32(&aad, 1)
        aad.append(direction.rawValue)
        appendLE32(&aad, 8)
        appendU64BEPub(&aad, counter)
        let typeBytes = Data(type.utf8)
        appendLE32(&aad, UInt32(typeBytes.count))
        aad.append(typeBytes)
        appendLE32(&aad, UInt32(contextBytes.count))
        aad.append(contextBytes)
        return aad
    }

    /// Public LE32 helper for use by buildDeliverAad. Same encoding as
    /// the private appendLE32 below; exposed so the function above can
    /// be called from outside the type. Swift doesn't let `private`
    /// helpers be called from `static` members of the same enum if they're
    /// both `private` and the static is at the top level — splitting it.
    private static func appendU64BEPub(_ out: inout Data, _ v: UInt64) {
        appendU64BE(&out, v)
    }

    // MARK: - Session record

    /// In-memory record of a single registered session. Owned by the
    /// `BridgeProtocolHandler` for the connection that registered it.
    /// Destroyed (key material zeroed) on connection close, on explicit
    /// re-registration, or when expiry passes during a check.
    final class Record {
        /// 16-byte session identifier (the wire-level key).
        let sessionId: Data
        /// 32-byte derived session key. Use `withSessionKey { ... }` to
        /// access; do not log or persist.
        private(set) var sessionKey: SymmetricKey
        let bridgeIssuedAtUnix: Int
        let ttlSeconds: Int
        var expiresAtUnix: Int { bridgeIssuedAtUnix + ttlSeconds }
        let agentName: String
        let agentVersion: String
        let agentPlatform: String
        /// Outbound (Agent → Shell) counter — increments before each push.
        var outboundCounter: UInt64 = 0
        /// Highest accepted inbound (Shell → Agent) counter.
        var lastInboundCounter: UInt64 = 0

        init(
            sessionId: Data,
            sessionKey: SymmetricKey,
            bridgeIssuedAtUnix: Int,
            ttlSeconds: Int,
            agentName: String,
            agentVersion: String,
            agentPlatform: String
        ) {
            self.sessionId = sessionId
            self.sessionKey = sessionKey
            self.bridgeIssuedAtUnix = bridgeIssuedAtUnix
            self.ttlSeconds = ttlSeconds
            self.agentName = agentName
            self.agentVersion = agentVersion
            self.agentPlatform = agentPlatform
        }

        /// Best-effort wipe of the session key. Note: CryptoKit doesn't expose
        /// the underlying bytes for in-place zeroing, so we replace the key
        /// with a zero-filled one. The original bytes may persist in memory
        /// until ARC collects them; full memory hygiene requires the C-level
        /// `mlock`/`memset_explicit` dance which is out of scope for this file.
        func wipe() {
            sessionKey = SymmetricKey(data: Data(repeating: 0, count: BrightLinkSession.sessionKeyLength))
        }
    }

    // MARK: - HKDF for K_session

    /// Compute K_session per RFC §4.5.2:
    ///
    ///   IKM   = clientShare ‖ bridgeShare       (64 bytes)
    ///   salt  = clientNonce ‖ sessionId          (32 bytes)
    ///   info  = "brightlink-session-key-v1"     (25 bytes UTF-8)
    ///   K     = HKDF-SHA256(IKM, salt, info, 32)
    ///
    /// Inputs are byte-checked; mis-sized inputs throw.
    static func deriveSessionKey(
        clientShare: Data,
        bridgeShare: Data,
        clientNonce: Data,
        sessionId: Data
    ) throws -> SymmetricKey {
        guard clientShare.count == shareLength else {
            throw BrightLinkError.invalidLength(
                "clientShare must be \(shareLength) bytes, got \(clientShare.count)"
            )
        }
        guard bridgeShare.count == shareLength else {
            throw BrightLinkError.invalidLength(
                "bridgeShare must be \(shareLength) bytes, got \(bridgeShare.count)"
            )
        }
        guard clientNonce.count == clientNonceLength else {
            throw BrightLinkError.invalidLength(
                "clientNonce must be \(clientNonceLength) bytes, got \(clientNonce.count)"
            )
        }
        guard sessionId.count == sessionIdLength else {
            throw BrightLinkError.invalidLength(
                "sessionId must be \(sessionIdLength) bytes, got \(sessionId.count)"
            )
        }

        var ikm = Data(capacity: 2 * shareLength)
        ikm.append(clientShare)
        ikm.append(bridgeShare)

        var salt = Data(capacity: clientNonceLength + sessionIdLength)
        salt.append(clientNonce)
        salt.append(sessionId)

        let info = Data(sessionKeyHkdfInfo.utf8)

        // HKDF<SHA256> produces a SymmetricKey directly via the convenience.
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: salt,
            info: info,
            outputByteCount: sessionKeyLength
        )
        return key
    }

    // MARK: - Canonical transcript

    /// Build the 238-byte canonical transcript per RFC §4.5.3.
    ///
    ///   "BrightLink v1 transcript\0"                              25 bytes
    ///   LE32(len(clientNonce))   ‖ clientNonce                  4 + 16
    ///   LE32(len(clientPub))     ‖ clientPub                    4 + 65
    ///   LE32(len(clientShare))   ‖ clientShare                  4 + 32
    ///   LE32(len(sessionId))     ‖ sessionId                    4 + 16
    ///   LE32(len(bridgeShare))   ‖ bridgeShare                  4 + 32
    ///   LE32(8)                  ‖ u64_be(round(issuedAtBd*86400))   4 + 8
    ///   LE32(8)                  ‖ u64_be(bridgeIssuedAtUnix)        4 + 8
    ///   LE32(4)                  ‖ u32_be(ttlSeconds)                4 + 4
    ///
    /// `clientPub` is the 65-byte uncompressed secp256k1 ephemeral key
    /// from the §4.5.1 envelope plaintext, NOT the ephemeral key inside
    /// the ECIES envelope itself.
    static func buildTranscript(
        clientNonce: Data,
        clientPub: Data,
        clientShare: Data,
        sessionId: Data,
        bridgeShare: Data,
        issuedAtBd: Double,
        bridgeIssuedAtUnix: Int,
        ttlSeconds: Int
    ) throws -> Data {
        guard clientNonce.count == clientNonceLength else {
            throw BrightLinkError.invalidLength("clientNonce must be \(clientNonceLength) bytes")
        }
        guard clientPub.count == 65 else {
            throw BrightLinkError.invalidLength("clientPub must be 65 bytes (uncompressed secp256k1)")
        }
        guard clientShare.count == shareLength else {
            throw BrightLinkError.invalidLength("clientShare must be \(shareLength) bytes")
        }
        guard sessionId.count == sessionIdLength else {
            throw BrightLinkError.invalidLength("sessionId must be \(sessionIdLength) bytes")
        }
        guard bridgeShare.count == shareLength else {
            throw BrightLinkError.invalidLength("bridgeShare must be \(shareLength) bytes")
        }
        guard issuedAtBd.isFinite else {
            throw BrightLinkError.invalidLength("issuedAtBd must be finite")
        }
        guard bridgeIssuedAtUnix >= 0 else {
            throw BrightLinkError.invalidLength("bridgeIssuedAtUnix must be non-negative")
        }
        guard ttlSeconds >= 0 && ttlSeconds <= Int(UInt32.max) else {
            throw BrightLinkError.invalidLength("ttlSeconds must fit in u32")
        }

        // RFC §4.5.3: round (issuedAtBd*86400) to nearest second.
        let issuedAtUnixRounded = Int((issuedAtBd * 86400.0).rounded())
        guard issuedAtUnixRounded >= 0 else {
            throw BrightLinkError.invalidLength("issuedAtBd resolves to negative Unix seconds")
        }

        var t = Data(capacity: transcriptTotalLength)
        t.append(transcriptHeader) // 25 bytes
        appendLengthPrefixed(&t, clientNonce)
        appendLengthPrefixed(&t, clientPub)
        appendLengthPrefixed(&t, clientShare)
        appendLengthPrefixed(&t, sessionId)
        appendLengthPrefixed(&t, bridgeShare)
        // u64 big-endian for both issued-at fields.
        appendLE32(&t, 8)
        appendU64BE(&t, UInt64(issuedAtUnixRounded))
        appendLE32(&t, 8)
        appendU64BE(&t, UInt64(bridgeIssuedAtUnix))
        // u32 big-endian for TTL.
        appendLE32(&t, 4)
        appendU32BE(&t, UInt32(ttlSeconds))

        guard t.count == transcriptTotalLength else {
            throw BrightLinkError.internalError(
                "transcript length \(t.count) != expected \(transcriptTotalLength)"
            )
        }
        return t
    }

    // MARK: - Registration request schema (RFC §4.5.1)

    /// Decoded `LINK_REGISTER` envelope plaintext — see RFC §4.5.1.
    struct RegisterPlaintext {
        let v: Int
        let clientPub: Data
        let clientShare: Data
        let issuedAtBd: Double
        let ttlSeconds: Int
        let agentName: String
        let agentVersion: String
        let agentPlatform: String
    }

    /// Parse the §4.5.1 envelope plaintext from raw JSON bytes.
    static func parseRegisterPlaintext(_ bytes: Data) throws -> RegisterPlaintext {
        guard let json = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
            throw BrightLinkError.invalidPlaintext
        }
        guard let v = json["v"] as? Int else { throw BrightLinkError.invalidPlaintext }

        guard
            let clientPubB64 = json["clientPub"] as? String,
            let clientPub = Data(base64Encoded: clientPubB64),
            clientPub.count == 65,
            clientPub.first == 0x04
        else {
            throw BrightLinkError.invalidPlaintext
        }
        guard
            let clientShareB64 = json["clientShare"] as? String,
            let clientShare = Data(base64Encoded: clientShareB64),
            clientShare.count == shareLength
        else {
            throw BrightLinkError.invalidPlaintext
        }
        guard let issuedAtBd = (json["issuedAtBd"] as? NSNumber)?.doubleValue,
              issuedAtBd.isFinite else {
            throw BrightLinkError.invalidPlaintext
        }
        guard let ttlSeconds = json["ttlSeconds"] as? Int else {
            throw BrightLinkError.invalidPlaintext
        }

        // Agent block — required structurally per RFC §4.5.1, but each field
        // defaults to "unknown" if missing/non-string. Max 64 chars per field.
        var agentName = "unknown"
        var agentVersion = "unknown"
        var agentPlatform = "unknown"
        if let agent = json["agent"] as? [String: Any] {
            if let n = agent["name"] as? String { agentName = String(n.prefix(64)) }
            if let vstr = agent["version"] as? String { agentVersion = String(vstr.prefix(64)) }
            if let p = agent["platform"] as? String { agentPlatform = String(p.prefix(64)) }
        }

        return RegisterPlaintext(
            v: v,
            clientPub: clientPub,
            clientShare: clientShare,
            issuedAtBd: issuedAtBd,
            ttlSeconds: ttlSeconds,
            agentName: agentName,
            agentVersion: agentVersion,
            agentPlatform: agentPlatform
        )
    }

    // MARK: - Errors

    enum BrightLinkError: Error, CustomStringConvertible {
        case invalidLength(String)
        case invalidPlaintext
        case staleRegistration
        case decryptionFailed
        case unsupportedVersion
        case missingClientNonce
        case missingEnvelope
        case internalError(String)

        var description: String {
            switch self {
            case .invalidLength(let msg): return "Invalid length: \(msg)"
            case .invalidPlaintext: return "Invalid envelope plaintext"
            case .staleRegistration: return "Stale registration"
            case .decryptionFailed: return "Decryption failed"
            case .unsupportedVersion: return "Unsupported BrightLink protocol version"
            case .missingClientNonce: return "Missing clientNonce"
            case .missingEnvelope: return "Missing envelope"
            case .internalError(let msg): return "internal: \(msg)"
            }
        }
    }

    // MARK: - Byte-layout helpers

    private static func appendLengthPrefixed(_ out: inout Data, _ bytes: Data) {
        appendLE32(&out, UInt32(bytes.count))
        out.append(bytes)
    }

    /// Appends a 4-byte little-endian unsigned integer.
    /// LE32 is the prefix convention from RFC §4.6.2 (length-prefixed AAD)
    /// and §4.5.3 (transcript field length prefixes).
    private static func appendLE32(_ out: inout Data, _ value: UInt32) {
        var v = value.littleEndian
        withUnsafeBytes(of: &v) { out.append(contentsOf: $0) }
    }

    /// Appends an 8-byte big-endian unsigned integer.
    /// u64_be is used for transcript timestamps (RFC §4.5.3) and LINK_DELIVER
    /// counters (RFC §4.6).
    private static func appendU64BE(_ out: inout Data, _ value: UInt64) {
        var v = value.bigEndian
        withUnsafeBytes(of: &v) { out.append(contentsOf: $0) }
    }

    /// Appends a 4-byte big-endian unsigned integer.
    private static func appendU32BE(_ out: inout Data, _ value: UInt32) {
        var v = value.bigEndian
        withUnsafeBytes(of: &v) { out.append(contentsOf: $0) }
    }
}
