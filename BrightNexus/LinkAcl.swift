// LinkAcl.swift
// BrightNexus
//
// Per-caller geo allowlist (RFC §7.2). Ported from
// test-harness/src/mock-brightnexus/acl.ts.
//
// The ACL is a list of entries that map a canonical caller identity tuple
// `(attestationClass, issuerId, subjectId)` (plus path+hash for the
// `unsigned` class) to per-scope policy values (always / prompt / deny).
//
// Persistence:
//   ~/.brightchain/brightnexus/geo-acl.json     — canonical-JSON document
//   ~/.brightchain/brightnexus/geo-acl.sig      — detached ECDSA-P256 sig
//
// Tamper detection on load: signature mismatch OR bridgeKeyId mismatch
// reverts every entry to all-prompt and re-signs with the current bridge
// identity.

import Foundation
import Security

// MARK: - Public types

/// Geo scope ladder (RFC §7.1). Ranks: status=0, proximity=1, zone=2,
/// precise=3, trajectory=4. Unsigned binaries are capped at proximity.
enum LinkGeoScope: String, Codable, CaseIterable {
    case status     = "status"
    case proximity  = "proximity"
    case zone       = "zone"
    case precise    = "precise"
    case trajectory = "trajectory"

    var rank: Int {
        switch self {
        case .status:     return 0
        case .proximity:  return 1
        case .zone:       return 2
        case .precise:    return 3
        case .trajectory: return 4
        }
    }
}

/// The maximum scope rank that may be granted to an `unsigned` binary
/// (RFC §7.1). Anything above this returns SCOPE_UNAVAILABLE_UNSIGNED.
let LINK_GEO_UNSIGNED_MAX_SCOPE: LinkGeoScope = .proximity

/// Per-scope policy. Same shape as the TS spec.
enum LinkGeoPolicy: String, Codable {
    case always = "always"
    case prompt = "prompt"
    case deny   = "deny"
}

/// One ACL entry — one caller's policy. RFC §7.2.
struct LinkAclEntry: Codable, Equatable {
    var id: String
    var displayName: String
    var attestationClass: AttestationClass
    var issuerId: String?
    var subjectId: String?
    var expectedPath: String?
    /// SHA-256 of the binary as `"sha256:<hex>"`. Only meaningful for
    /// unsigned binaries; nil otherwise.
    var fallbackHash: String?
    var scopes: [LinkGeoScope: LinkGeoPolicy]
    var addedAtBd: Double
    var lastUsedBd: Double
    /// nil = never expires.
    var expiresAtBd: Double?
    var purpose: String?
    /// For session-scoped grants only.
    var sshSessionId: String?
}

/// The full ACL document.
struct LinkAclDocument: Codable, Equatable {
    var version: Int
    var bridgeKeyId: String
    var entries: [LinkAclEntry]
}

/// Result of an ACL lookup against an attestation + scope.
enum AclLookupResult {
    case allow(LinkAclEntry)
    case deny(LinkAclEntry, reason: String)
    case prompt(LinkAclEntry?)
    case denyCap(reason: String)
}

// MARK: - Defaults

/// The §7.1 default scope grants for new ACL entries — every scope starts
/// as `prompt`.
func linkAclDefaultPromptScopes() -> [LinkGeoScope: LinkGeoPolicy] {
    var scopes: [LinkGeoScope: LinkGeoPolicy] = [:]
    for s in LinkGeoScope.allCases { scopes[s] = .prompt }
    return scopes
}

/// Build a fresh ACL document with no entries, pinned to the supplied id.
func linkAclEmpty(bridgeKeyId: String) -> LinkAclDocument {
    return LinkAclDocument(version: 1, bridgeKeyId: bridgeKeyId, entries: [])
}

// MARK: - LinkAcl

/// In-memory ACL with detached-signature tracking. Mutations re-sign.
final class LinkAcl {
    private var doc: LinkAclDocument
    private var signature: Data?
    private let identity: BridgeIdentity

    /// Posted (on the main queue) after every mutation that changes the
    /// in-memory ACL. The Allowlist Settings tab listens for this and
    /// re-renders. Carries no userInfo — observers re-read the full list.
    static let didChangeNotification = Notification.Name("LinkAcl.didChange")

    init(identity: BridgeIdentity, initial: LinkAclDocument? = nil) {
        self.identity = identity
        self.doc = initial ?? linkAclEmpty(bridgeKeyId: identity.keyId)
        self.resign()
    }

    func list() -> [LinkAclEntry] { doc.entries }

    func bridgeKeyId() -> String { doc.bridgeKeyId }

    /// Add or replace by id. Re-signs.
    func upsert(_ entry: LinkAclEntry) {
        if let idx = doc.entries.firstIndex(where: { $0.id == entry.id }) {
            doc.entries[idx] = entry
        } else {
            doc.entries.append(entry)
        }
        resign()
        Self.publishChange()
    }

    /// Remove an entry by id. Re-signs.
    func remove(id: String) {
        doc.entries.removeAll(where: { $0.id == id })
        resign()
        Self.publishChange()
    }

    /// Post the change notification on the main queue. Cheap so it's safe
    /// to call from any thread; the post hop lets SwiftUI views observe
    /// without main-actor escapes.
    private static func publishChange() {
        if Thread.isMainThread {
            NotificationCenter.default.post(name: Self.didChangeNotification, object: nil)
        } else {
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: Self.didChangeNotification, object: nil)
            }
        }
    }

    /// Look up an attestation against the ACL for the requested scope.
    /// RFC §7.4.
    func lookup(attestation: PeerAttestation, scope: LinkGeoScope, nowBd: Double) -> AclLookupResult {
        // §7.1 cap: unsigned binaries cannot receive geo:zone or higher.
        if attestation.attestationClass == .unsigned && scope.rank > LINK_GEO_UNSIGNED_MAX_SCOPE.rank {
            return .denyCap(reason: "unsigned-binary-cap")
        }

        guard let entry = findMatchingEntry(attestation: attestation) else {
            return .prompt(nil)
        }

        // Auto-expire entries past `expiresAtBd`.
        if let exp = entry.expiresAtBd, nowBd > exp {
            return .prompt(nil)
        }

        let policy = entry.scopes[scope] ?? .prompt
        switch policy {
        case .always: return .allow(entry)
        case .deny:   return .deny(entry, reason: "policy")
        case .prompt: return .prompt(entry)
        }
    }

    /// Find the first entry whose identity tuple matches the attestation.
    func findMatchingEntry(attestation: PeerAttestation) -> LinkAclEntry? {
        for entry in doc.entries {
            if entry.attestationClass != attestation.attestationClass { continue }
            if entry.attestationClass == .unsigned {
                // Unsigned: match on (path, hash). Both must match.
                if entry.expectedPath != attestation.executablePath { continue }
                guard let storedHash = entry.fallbackHash,
                      let actualHash = attestation.executableHash else { continue }
                let expectedHex = storedHash.hasPrefix("sha256:")
                    ? String(storedHash.dropFirst("sha256:".count))
                    : storedHash
                if expectedHex.lowercased() != actualHash.linkAclHexString { continue }
                return entry
            }
            // Signed: match on (issuerId, subjectId).
            if entry.issuerId != attestation.issuerId { continue }
            if entry.subjectId != attestation.subjectId { continue }
            return entry
        }
        return nil
    }

    /// Mark `lastUsedBd` after a successful access. Re-signs.
    func recordUse(entryId: String, nowBd: Double) {
        guard let idx = doc.entries.firstIndex(where: { $0.id == entryId }) else { return }
        doc.entries[idx].lastUsedBd = nowBd
        resign()
    }

    /// Canonical-JSON-encoded form of the document, byte-stable for signing.
    func getCanonicalJson() -> Data {
        // Build a canonical-JSON-friendly tree from the document (sorted
        // keys, only primitive scalars). Force unwrap on success because we
        // construct the tree ourselves.
        return try! linkAclCanonicalJsonBytes(documentToTree(doc))
    }

    /// Detached signature over the canonical-JSON encoding.
    func getSignature() -> Data {
        return signature ?? Data()
    }

    /// Verify the in-memory document against the in-memory signature.
    func verify() -> Bool {
        guard let sig = signature else { return false }
        return linkAclEcdsaP256Verify(
            publicKey65: (try? identity.publicKey()) ?? Data(),
            data: getCanonicalJson(),
            signatureDer: sig
        )
    }

    /// Load an ACL from canonical-JSON bytes + a detached signature. On
    /// tamper detection (sig mismatch or wrong bridgeKeyId), every entry
    /// is reverted to all-prompt scopes and the doc is re-signed with
    /// the current identity. Returns whether tampering was detected.
    @discardableResult
    func loadFromBytes(canonicalJson: Data, signature: Data) -> Bool {
        // Try to parse.
        let parsed: LinkAclDocument? = (try? JSONDecoder().decode(LinkAclDocument.self, from: canonicalJson))

        let pub = (try? identity.publicKey()) ?? Data()
        let sigOk = linkAclEcdsaP256Verify(publicKey65: pub, data: canonicalJson, signatureDer: signature)
        let keyIdOk = (parsed?.bridgeKeyId == identity.keyId)

        if parsed == nil || !sigOk || !keyIdOk {
            var rebuilt = parsed ?? linkAclEmpty(bridgeKeyId: identity.keyId)
            rebuilt.bridgeKeyId = identity.keyId
            rebuilt.entries = rebuilt.entries.map { e -> LinkAclEntry in
                var copy = e
                copy.scopes = linkAclDefaultPromptScopes()
                return copy
            }
            self.doc = rebuilt
            resign()
            return true
        }

        self.doc = parsed!
        self.signature = signature
        return false
    }

    /// Atomically write `geo-acl.json` + `geo-acl.sig` (mode 0600).
    func saveToDisk() throws {
        let aclURL = BrightNexusPaths.geoAcl
        let sigURL = BrightNexusPaths.geoAclSig
        let canonical = getCanonicalJson()
        let sig = getSignature()
        try canonical.write(to: aclURL, options: .atomic)
        _ = chmod(aclURL.path, 0o600)
        try sig.write(to: sigURL, options: .atomic)
        _ = chmod(sigURL.path, 0o600)
    }

    /// Load from `geo-acl.json` + `geo-acl.sig`. If either is missing,
    /// returns a fresh empty ACL (not tampered). If both present but
    /// fail verification, returns the reverted-to-prompt doc with
    /// `tampered = true`.
    static func loadFromDisk(identity: BridgeIdentity) -> (acl: LinkAcl, tampered: Bool) {
        let aclURL = BrightNexusPaths.geoAcl
        let sigURL = BrightNexusPaths.geoAclSig
        let fm = FileManager.default
        guard fm.fileExists(atPath: aclURL.path),
              fm.fileExists(atPath: sigURL.path) else {
            // Fresh — create empty in-memory ACL. Save now so the next
            // boot has the on-disk file.
            let acl = LinkAcl(identity: identity)
            try? acl.saveToDisk()
            return (acl, false)
        }
        guard let canonical = try? Data(contentsOf: aclURL),
              let sig = try? Data(contentsOf: sigURL) else {
            let acl = LinkAcl(identity: identity)
            try? acl.saveToDisk()
            return (acl, false)
        }
        let acl = LinkAcl(identity: identity)
        let tampered = acl.loadFromBytes(canonicalJson: canonical, signature: sig)
        if tampered {
            // Persist the reverted-to-prompt copy so the next boot is
            // self-consistent.
            try? acl.saveToDisk()
        }
        return (acl, tampered)
    }

    // MARK: - Internals

    private func resign() {
        let canonical = getCanonicalJson()
        do {
            self.signature = try identity.sign(data: canonical)
        } catch {
            self.signature = Data()
        }
    }
}

// MARK: - Document → tree (for canonical JSON)

private func documentToTree(_ doc: LinkAclDocument) -> [String: Any] {
    return [
        "version":     doc.version,
        "bridgeKeyId": doc.bridgeKeyId,
        "entries":     doc.entries.map { entryToTree($0) },
    ]
}

private func entryToTree(_ e: LinkAclEntry) -> [String: Any] {
    var scopes: [String: String] = [:]
    for (k, v) in e.scopes { scopes[k.rawValue] = v.rawValue }
    var out: [String: Any] = [
        "id":               e.id,
        "displayName":      e.displayName,
        "attestationClass": e.attestationClass.rawValue,
        "issuerId":         e.issuerId as Any? ?? NSNull(),
        "subjectId":        e.subjectId as Any? ?? NSNull(),
        "expectedPath":     e.expectedPath as Any? ?? NSNull(),
        "fallbackHash":     e.fallbackHash as Any? ?? NSNull(),
        "scopes":           scopes,
        "addedAtBd":        e.addedAtBd,
        "lastUsedBd":       e.lastUsedBd,
        "expiresAtBd":      e.expiresAtBd as Any? ?? NSNull(),
    ]
    if let p = e.purpose { out["purpose"] = p }
    if let s = e.sshSessionId { out["sshSessionId"] = s }
    return out
}

// MARK: - Canonical JSON (RFC 8785 JCS subset)

/// RFC 8785 JCS encoding restricted to the shapes the ACL/zones modules
/// produce: objects with sorted keys, arrays in source order, primitive
/// scalars (string, number, bool, null). No NaN / Infinity.
func linkAclCanonicalJsonBytes(_ value: Any) throws -> Data {
    let s = try linkAclCanonicalJsonString(value)
    return Data(s.utf8)
}

private func linkAclCanonicalJsonString(_ value: Any) throws -> String {
    if value is NSNull { return "null" }
    if let b = value as? Bool { return b ? "true" : "false" }
    // NSNumber needs to come before Int/Double — JSONSerialization gives
    // NSNumber for booleans too, so check Bool above first.
    if let n = value as? NSNumber {
        // Distinguish bool-as-NSNumber.
        if CFGetTypeID(n) == CFBooleanGetTypeID() {
            return n.boolValue ? "true" : "false"
        }
        return canonicalNumberString(n)
    }
    if let i = value as? Int     { return String(i) }
    if let d = value as? Double  {
        if !d.isFinite { throw LinkAclError.canonicalNonFiniteNumber }
        return canonicalNumberString(NSNumber(value: d))
    }
    if let s = value as? String  { return canonicalEncodeString(s) }
    if let arr = value as? [Any] {
        var parts: [String] = []
        parts.reserveCapacity(arr.count)
        for v in arr { parts.append(try linkAclCanonicalJsonString(v)) }
        return "[" + parts.joined(separator: ",") + "]"
    }
    if let obj = value as? [String: Any] {
        let keys = obj.keys.sorted()
        var parts: [String] = []
        parts.reserveCapacity(keys.count)
        for k in keys {
            let v = obj[k]!
            parts.append(canonicalEncodeString(k) + ":" + (try linkAclCanonicalJsonString(v)))
        }
        return "{" + parts.joined(separator: ",") + "}"
    }
    throw LinkAclError.canonicalUnsupportedType("\(type(of: value))")
}

private func canonicalNumberString(_ n: NSNumber) -> String {
    // Use JSONSerialization for a single-value array to leverage Apple's
    // shortest-round-trip float formatting, then strip the brackets. This
    // matches Node's JSON.stringify number output for finite values.
    if let data = try? JSONSerialization.data(withJSONObject: [n], options: .fragmentsAllowed),
       let str = String(data: data, encoding: .utf8) {
        // str = "[<number>]"
        var inner = str
        if inner.hasPrefix("["), inner.hasSuffix("]") {
            inner = String(inner.dropFirst().dropLast())
        }
        return inner
    }
    // Fallback — should not happen for finite NSNumber.
    return n.stringValue
}

private func canonicalEncodeString(_ s: String) -> String {
    // Use JSONSerialization to get JSON-escaped UTF-8.
    if let data = try? JSONSerialization.data(withJSONObject: [s], options: .fragmentsAllowed),
       let str = String(data: data, encoding: .utf8) {
        var inner = str
        if inner.hasPrefix("["), inner.hasSuffix("]") {
            inner = String(inner.dropFirst().dropLast())
        }
        return inner
    }
    return "\"\(s)\""
}

enum LinkAclError: Error, CustomStringConvertible {
    case canonicalNonFiniteNumber
    case canonicalUnsupportedType(String)
    var description: String {
        switch self {
        case .canonicalNonFiniteNumber:           return "canonical JSON forbids NaN / Infinity"
        case .canonicalUnsupportedType(let t):    return "canonical JSON does not support \(t)"
        }
    }
}

// MARK: - ECDSA P-256 verify

/// Verify a DER-encoded ECDSA-P256 signature over `data` using a 65-byte
/// uncompressed P-256 public key (X9.63). Hash is SHA-256.
func linkAclEcdsaP256Verify(publicKey65: Data, data: Data, signatureDer: Data) -> Bool {
    guard publicKey65.count == 65, publicKey65[0] == 0x04 else { return false }

    let attrs: [String: Any] = [
        kSecAttrKeyType as String:       kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String:      kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256,
    ]
    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(publicKey65 as CFData, attrs as CFDictionary, &error) else {
        return false
    }
    let ok = SecKeyVerifySignature(
        secKey,
        .ecdsaSignatureMessageX962SHA256,
        data as CFData,
        signatureDer as CFData,
        &error
    )
    return ok
}

// MARK: - Hex helper

private extension Data {
    var linkAclHexString: String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}
