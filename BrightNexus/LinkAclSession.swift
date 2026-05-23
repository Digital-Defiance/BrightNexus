// LinkAclSession.swift
// BrightNexus
//
// SSH-session-bound ACL (RFC §7.3) — `~/.brightchain/brightnexus/geo-acl-session.json`.
//
// Distinct from LinkAcl in three ways:
//
//   1. Transient. Wiped on bridge restart (so a long-lived SSH session
//      that survives the bridge restart will get re-prompted next time).
//   2. Per-entry GC. When the sshd_pid encoded in the entry's
//      sshSessionId is no longer alive, the entry is removed.
//   3. No bridge-key pin and no detached signature. Session entries are
//      keyed to a specific SSH session that lives in process state, not
//      to the bridge's persistent identity, so the at-rest signing
//      machinery doesn't apply.
//
// Lookup precedence (RFC §7.4): the session ACL is consulted first,
// THEN the durable LinkAcl. A durable `policy=always` grant for a
// caller still applies inside an SSH session — the session ACL is
// *additive*, not a replacement.
//
// File mode: 0600. Same atomic-rename save pattern as LinkAcl.

import Foundation

// MARK: - Public types

/// One session ACL entry. Reuses the same per-scope policy shape as the
/// durable ACL but also carries the SSH session id we're bound to.
struct LinkAclSessionEntry: Codable, Equatable {
    var id: String
    var displayName: String
    var attestationClass: AttestationClass
    var issuerId: String?
    var subjectId: String?
    var expectedPath: String?
    var fallbackHash: String?
    var scopes: [LinkGeoScope: LinkGeoPolicy]
    var addedAtBd: Double
    var lastUsedBd: Double
    var sshSessionId: String
    var sshdPid: pid_t
    var sourceUser: String?
    var sourceHost: String?
}

/// The full document.
struct LinkAclSessionDocument: Codable, Equatable {
    var version: Int
    var entries: [LinkAclSessionEntry]

    init(version: Int = 1, entries: [LinkAclSessionEntry] = []) {
        self.version = version
        self.entries = entries
    }
}

// MARK: - In-memory ACL

final class LinkAclSession {

    /// Posted on the main queue after every mutation. Same convention as
    /// LinkAcl.didChangeNotification so the Settings UI can subscribe to
    /// both with the same handler.
    static let didChangeNotification = Notification.Name("LinkAclSession.didChange")

    private var doc: LinkAclSessionDocument

    init(initial: LinkAclSessionDocument? = nil) {
        self.doc = initial ?? LinkAclSessionDocument()
    }

    func list() -> [LinkAclSessionEntry] { doc.entries }

    /// Add or replace by id. Re-saves and publishes change.
    func upsert(_ entry: LinkAclSessionEntry) {
        if let idx = doc.entries.firstIndex(where: { $0.id == entry.id }) {
            doc.entries[idx] = entry
        } else {
            doc.entries.append(entry)
        }
        Self.publishChange()
    }

    /// Remove an entry by id. Re-saves and publishes change.
    func remove(id: String) {
        let before = doc.entries.count
        doc.entries.removeAll(where: { $0.id == id })
        if doc.entries.count != before {
            Self.publishChange()
        }
    }

    /// Look up an attestation against the session ACL for the requested
    /// scope. Returns the entry only if both the identity tuple AND the
    /// SSH session id match the peer's current session. RFC §7.4 step 1.
    func lookup(attestation: PeerAttestation,
                scope: LinkGeoScope,
                nowBd: Double) -> LinkAclSessionEntry? {
        guard let peerSession = attestation.sshSession?.sessionId else {
            return nil  // peer is not in an SSH session; session ACL doesn't apply
        }
        for entry in doc.entries {
            if entry.sshSessionId != peerSession { continue }
            if entry.attestationClass != attestation.attestationClass { continue }
            if entry.attestationClass == .unsigned {
                if entry.expectedPath != attestation.executablePath { continue }
                if entry.fallbackHash == nil || attestation.executableHash == nil { continue }
                let expected = entry.fallbackHash!.replacingOccurrences(of: "sha256:", with: "")
                let actual = attestation.executableHash!.map { String(format: "%02x", $0) }.joined()
                if expected != actual { continue }
            } else {
                if entry.issuerId != attestation.issuerId { continue }
                if entry.subjectId != attestation.subjectId { continue }
            }
            return entry
        }
        return nil
    }

    /// Mark `lastUsedBd` after a successful access.
    func recordUse(entryId: String, nowBd: Double) {
        guard let idx = doc.entries.firstIndex(where: { $0.id == entryId }) else { return }
        doc.entries[idx].lastUsedBd = nowBd
        // No publish for last-used touches; UI doesn't need to react.
    }

    // MARK: - GC

    /// Remove entries whose sshd_pid is no longer alive. RFC §7.3.
    /// Returns the number of entries removed.
    @discardableResult
    func gcDeadSessions() -> Int {
        let before = doc.entries.count
        doc.entries.removeAll { entry in
            !Self.isPidAlive(entry.sshdPid)
        }
        let removed = before - doc.entries.count
        if removed > 0 { Self.publishChange() }
        return removed
    }

    /// Wipe every entry. Called on bridge boot (RFC §7.3 last paragraph:
    /// "the file is wiped on bridge restart in any case").
    func wipe() {
        if doc.entries.isEmpty { return }
        doc.entries.removeAll()
        Self.publishChange()
    }

    // MARK: - Persistence

    func saveToDisk() throws {
        let url = BrightNexusPaths.geoAclSession
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        let data = try encoder.encode(doc)
        let tmpURL = url.appendingPathExtension("tmp")
        try data.write(to: tmpURL, options: [.atomic])
        // Tighten permissions before rename so there's no 0644 window.
        _ = chmod(tmpURL.path, 0o600)
        try FileManager.default.replaceItemAt(url, withItemAt: tmpURL)
    }

    /// Load from disk on bridge boot. Always returns a fresh empty
    /// document on success — the on-disk file is wiped (RFC §7.3) and
    /// the returned in-memory ACL starts empty regardless of what was
    /// persisted before. Left as a static factory so the engine boot
    /// path stays parallel to LinkAcl.loadFromDisk.
    static func loadFromDisk() -> LinkAclSession {
        // Per RFC §7.3 we always wipe on boot; the on-disk file from a
        // previous session is irrelevant.
        let acl = LinkAclSession()
        try? acl.saveToDisk()  // writes the empty doc, mode 0600
        return acl
    }

    // MARK: - Helpers

    private static func publishChange() {
        if Thread.isMainThread {
            NotificationCenter.default.post(name: Self.didChangeNotification, object: nil)
        } else {
            DispatchQueue.main.async {
                NotificationCenter.default.post(name: Self.didChangeNotification, object: nil)
            }
        }
    }

    /// kill(pid, 0) returns 0 if the process exists and we can signal
    /// it (or EPERM if we can't). Either way it's alive. ESRCH means
    /// dead.
    private static func isPidAlive(_ pid: pid_t) -> Bool {
        if pid <= 0 { return false }
        let rc = kill(pid, 0)
        if rc == 0 { return true }
        return errno == EPERM
    }
}
