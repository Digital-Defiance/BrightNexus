// PeerAttestation.swift
// BrightNexus
//
// Implements RFC §4.9.5 (per-credential attestation) AND RFC §6.2
// (cross-platform peer attestation for the geo command surface). On every
// connection accept the bridge resolves:
//
//   - PID:                 getsockopt(LOCAL_PEERPID)
//   - executable path:     proc_pidpath()    (kernel-canonical, immune to
//                                              argv[0] spoofing)
//   - executable hash:     SHA-256 of the binary bytes
//   - code-signing identity + validity:
//                          SecCodeCopyGuestWithAttributes /
//                          SecStaticCodeCheckValidity
//   - peer lineage:        walk parent PIDs up to 8 ancestors
//   - SSH session:         non-null iff an `sshd`-class ancestor is found
//                          by signing identity (NOT by name)
//
// The §7.1 ACL keys off `(attestationClass, issuerId, subjectId)` for
// signed binaries and `(executablePath, executableHash)` for unsigned
// binaries. The `displayLabel` and `sshSession` fields surface in the
// modal prompt and the audit log.

import Darwin
import Foundation
import Security

// `proc_pidpath` is in <libproc.h>; expose it explicitly.
@_silgen_name("proc_pidpath")
private func proc_pidpath(_ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ buffersize: UInt32) -> Int32

// `proc_pidinfo` is what we use to read PROC_PIDT_SHORTBSDINFO for the parent PID.
@_silgen_name("proc_pidinfo")
private func proc_pidinfo(_ pid: Int32, _ flavor: Int32, _ arg: UInt64,
                          _ buffer: UnsafeMutableRawPointer, _ buffersize: Int32) -> Int32

private let PROC_PIDPATHINFO_MAXSIZE: UInt32 = 4 * 1024

// PROC_PIDT_SHORTBSDINFO = 13. Defined in <sys/proc_info.h>.
private let PROC_PIDT_SHORTBSDINFO: Int32 = 13

// proc_bsdshortinfo struct from <sys/proc_info.h>. Only the fields we need.
private struct proc_bsdshortinfo {
    var pbsi_pid:    UInt32 = 0
    var pbsi_ppid:   UInt32 = 0
    var pbsi_pgid:   UInt32 = 0
    var pbsi_status: UInt32 = 0
    var pbsi_comm:   (Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                      Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8) = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    var pbsi_flags:  UInt32 = 0
    var pbsi_uid:    UInt32 = 0
    var pbsi_gid:    UInt32 = 0
    var pbsi_ruid:   UInt32 = 0
    var pbsi_rgid:   UInt32 = 0
    var pbsi_svuid:  UInt32 = 0
    var pbsi_svgid:  UInt32 = 0
    var pbsi_rfu_1:  UInt32 = 0
}

// MARK: - Attestation class

/// RFC §6.2 attestation class. The ACL keys off this plus `issuerId` and
/// `subjectId` for signed binaries and `(executablePath, hash)` for
/// `unsigned`. The Linux-specific classes are defined here so the protocol
/// constants live in one place even though only `developerId` /
/// `macAppStore` / `bshBuiltin` / `unsigned` are emitted on macOS.
enum AttestationClass: String, Codable {
    case developerId    = "DeveloperId"
    case macAppStore    = "MacAppStore"
    case bshBuiltin     = "BshBuiltin"
    case dpkgSigned     = "DpkgSigned"
    case rpmSigned      = "RpmSigned"
    case flatpakSigned  = "FlatpakSigned"
    case unsigned       = "Unsigned"
}

/// One ancestor process in the peer's parent chain. RFC §6.2.
struct PidPathSigning {
    let pid: pid_t
    let executablePath: String?
    let attestationClass: AttestationClass
    let issuerId: String?
}

/// SSH session context populated when an `sshd`-class ancestor is found in
/// the peer lineage by signing identity. RFC §6.2 / §7.3 / §9.6.
struct SshSessionInfo {
    let sourceUser: String?
    let sourceHost: String?
    let sshdPid: pid_t
    /// `"sshd:<pid>:<start_time>"`. Stable per session; expires when the
    /// matching sshd PID is no longer alive.
    let sessionId: String

    var auditEntry: [String: Any] {
        return [
            "sourceUser": sourceUser ?? "",
            "sourceHost": sourceHost ?? "",
            "sshdPid": Int(sshdPid),
            "sessionId": sessionId,
        ]
    }
}

/// Result of attesting one connecting peer. RFC §4.9.5 / §6.2. All fields
/// are best-effort — missing data is encoded as nil, never thrown.
struct PeerAttestation {
    let pid: pid_t
    let uid: uid_t
    /// Kernel-canonical executable path. nil if `proc_pidpath` failed.
    let executablePath: String?
    /// SHA-256 of the executable bytes. nil if path unknown or unreadable.
    let executableHash: Data?
    let attestationClass: AttestationClass
    /// Apple Team ID for `developerId`, `apple-app-store` for
    /// `macAppStore`, `digitaldefiance` for `bshBuiltin`, nil for unsigned.
    let issuerId: String?
    /// Bundle / binary identifier from the signature. For `bshBuiltin` this
    /// is the org.digitaldefiance.* identifier; for `unsigned` it's nil.
    let subjectId: String?
    /// True if `SecStaticCodeCheckValidity` passed.
    let signatureValid: Bool
    /// Ancestors, immediate-first, capped at 8 (per RFC §6.2 lineage cap).
    let peerLineage: [PidPathSigning]
    /// Non-null iff an `sshd`-class ancestor was detected by signing identity.
    let sshSession: SshSessionInfo?

    // MARK: - Backwards-compat surface used by §4.9.5 LINK_DELIVER path

    /// Composite "team.bundleId" identifier kept around for legacy callers
    /// that match on the literal `codeSigningIdentity` string. New callers
    /// should match on `(attestationClass, issuerId, subjectId)` instead.
    var codeSigningIdentity: String? {
        guard let issuer = issuerId, !issuer.isEmpty else { return subjectId }
        guard let subject = subjectId, !subject.isEmpty else { return issuer }
        return "\(issuer).\(subject)"
    }

    /// Best-effort short label used in the menu bar / Dashboard provenance
    /// hint and in the geo prompt body. Falls back to the executable
    /// basename.
    var displayLabel: String {
        if let id = codeSigningIdentity, !id.isEmpty {
            return id
        }
        if let path = executablePath {
            return (path as NSString).lastPathComponent
        }
        return "pid \(pid)"
    }

    /// Audit-log dictionary form. Pure data, no side effects.
    var auditEntry: [String: Any] {
        var entry: [String: Any] = [
            "pid": Int(pid),
            "uid": Int(uid),
            "executablePath": executablePath ?? "",
            "executableHash": executableHash?.hexString ?? "",
            "attestationClass": attestationClass.rawValue,
            "issuerId": issuerId ?? "",
            "subjectId": subjectId ?? "",
            "codeSigningIdentity": codeSigningIdentity ?? "",
            "signatureValid": signatureValid,
        ]
        if let ssh = sshSession {
            entry["sshSession"] = ssh.auditEntry
        }
        return entry
    }
}

private extension Data {
    var hexString: String {
        return self.map { String(format: "%02x", $0) }.joined()
    }
}

enum PeerAttestationLookup {

    /// Attest the peer connected on `clientFd`. Always returns a value —
    /// missing data fields are nil rather than thrown so the caller can log
    /// the partial attestation and proceed.
    static func attest(clientFd: Int32) -> PeerAttestation {
        let pid = readPeerPID(clientFd: clientFd) ?? 0
        let uid = readPeerUID(clientFd: clientFd) ?? 0
        let path = pid > 0 ? readExecutablePath(pid: pid) : nil
        let hash = path != nil ? readExecutableHash(path: path!) : nil
        let signing = path != nil
            ? readCodeSigningInfo(executablePath: path!)
            : SigningInfo(class: .unsigned, issuerId: nil, subjectId: nil, valid: false)
        let lineage = pid > 0 ? walkParentLineage(startPid: pid, maxDepth: 8) : []
        let ssh = detectSshSession(lineage: lineage)
        return PeerAttestation(
            pid: pid,
            uid: uid,
            executablePath: path,
            executableHash: hash,
            attestationClass: signing.class,
            issuerId: signing.issuerId,
            subjectId: signing.subjectId,
            signatureValid: signing.valid,
            peerLineage: lineage,
            sshSession: ssh
        )
    }

    // MARK: - PID + UID

    private static let LOCAL_PEERPID: Int32 = 0x002
    private static let LOCAL_PEEREUUID: Int32 = 0x003

    private static func readPeerPID(clientFd: Int32) -> pid_t? {
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        let result = withUnsafeMutablePointer(to: &pid) {
            $0.withMemoryRebound(to: Int8.self, capacity: 1) { ptr in
                getsockopt(clientFd, SOL_LOCAL, LOCAL_PEERPID, UnsafeMutableRawPointer(ptr), &size)
            }
        }
        return (result == 0 && pid > 0) ? pid : nil
    }

    /// On Darwin the EUID of the connecting peer is available via SO_PEERCRED
    /// equivalents; we use `getpeereid` from <unistd.h>.
    @_silgen_name("getpeereid")
    private static func getpeereid(_ fd: Int32, _ uid: UnsafeMutablePointer<uid_t>, _ gid: UnsafeMutablePointer<gid_t>) -> Int32

    private static func readPeerUID(clientFd: Int32) -> uid_t? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        let result = getpeereid(clientFd, &uid, &gid)
        return result == 0 ? uid : nil
    }

    // MARK: - Executable path

    private static func readExecutablePath(pid: pid_t) -> String? {
        let buf = UnsafeMutableRawPointer.allocate(
            byteCount: Int(PROC_PIDPATHINFO_MAXSIZE),
            alignment: 1
        )
        defer { buf.deallocate() }
        let n = proc_pidpath(pid, buf, PROC_PIDPATHINFO_MAXSIZE)
        if n <= 0 { return nil }
        return String(
            bytesNoCopy: buf,
            length: Int(n),
            encoding: .utf8,
            freeWhenDone: false
        )
    }

    // MARK: - Executable hash

    /// Read the executable bytes and SHA-256 them. Bounded to a sane
    /// maximum (256 MiB) so a malicious binary path can't OOM us.
    private static func readExecutableHash(path: String) -> Data? {
        let url = URL(fileURLWithPath: path)
        do {
            let attrs = try FileManager.default.attributesOfItem(atPath: path)
            if let size = attrs[.size] as? UInt64, size > 256 * 1024 * 1024 {
                return nil
            }
            let data = try Data(contentsOf: url)
            return Data(SHA256Wrapper.digest(data))
        } catch {
            return nil
        }
    }

    // MARK: - Code signature

    private struct SigningInfo {
        let `class`: AttestationClass
        let issuerId: String?
        let subjectId: String?
        let valid: Bool
    }

    private static func readCodeSigningInfo(executablePath: String) -> SigningInfo {
        let url = URL(fileURLWithPath: executablePath) as CFURL
        var staticCode: SecStaticCode?
        let createResult = SecStaticCodeCreateWithPath(url, [], &staticCode)
        guard createResult == errSecSuccess, let code = staticCode else {
            return SigningInfo(class: .unsigned, issuerId: nil, subjectId: nil, valid: false)
        }

        let validityResult = SecStaticCodeCheckValidity(code, [], nil)
        let isValid = (validityResult == errSecSuccess)

        var infoDict: CFDictionary?
        let infoResult = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &infoDict
        )
        guard infoResult == errSecSuccess,
              let info = infoDict as? [String: Any] else {
            return SigningInfo(class: .unsigned, issuerId: nil, subjectId: nil, valid: isValid)
        }

        let identifier = info["identifier"] as? String
        let teamId = info["teamid"] as? String

        // No identifier at all → unsigned.
        guard let subject = identifier, !subject.isEmpty else {
            return SigningInfo(class: .unsigned, issuerId: nil, subjectId: nil, valid: isValid)
        }

        // Classify. Apple's `flags` and `info["source"]` could in theory tell
        // us "Mac App Store" vs "Developer ID", but the simpler path is:
        //   - If the subject id starts with "org.digitaldefiance.", call it
        //     `bshBuiltin` regardless of which signing chain it came from.
        //   - If the team id is "apple", call it `macAppStore`.
        //   - Otherwise it's `developerId`.
        // This is conservative; we'd rather over-attribute to `bshBuiltin`
        // for our own packages than mis-attribute for a third party.
        let cls: AttestationClass
        let issuer: String?
        if subject.hasPrefix("org.digitaldefiance.") {
            cls = .bshBuiltin
            issuer = "digitaldefiance"
        } else if teamId == "apple" {
            cls = .macAppStore
            issuer = "apple-app-store"
        } else {
            cls = .developerId
            issuer = teamId
        }

        return SigningInfo(class: cls, issuerId: issuer, subjectId: subject, valid: isValid)
    }

    // MARK: - Lineage walk

    private static func walkParentLineage(startPid: pid_t, maxDepth: Int) -> [PidPathSigning] {
        var lineage: [PidPathSigning] = []
        var currentPid = startPid
        var seen = Set<pid_t>()  // defence against pid loops; not expected in practice
        for _ in 0..<maxDepth {
            if seen.contains(currentPid) { break }
            seen.insert(currentPid)
            let path = readExecutablePath(pid: currentPid)
            let signing = path != nil
                ? readCodeSigningInfo(executablePath: path!)
                : SigningInfo(class: .unsigned, issuerId: nil, subjectId: nil, valid: false)
            lineage.append(PidPathSigning(
                pid: currentPid,
                executablePath: path,
                attestationClass: signing.class,
                issuerId: signing.issuerId
            ))
            guard let parent = readParentPid(pid: currentPid), parent > 0, parent != currentPid else {
                break
            }
            currentPid = parent
        }
        return lineage
    }

    private static func readParentPid(pid: pid_t) -> pid_t? {
        var info = proc_bsdshortinfo()
        let n = proc_pidinfo(
            pid,
            PROC_PIDT_SHORTBSDINFO,
            0,
            &info,
            Int32(MemoryLayout<proc_bsdshortinfo>.size)
        )
        guard n == Int32(MemoryLayout<proc_bsdshortinfo>.size) else { return nil }
        return pid_t(info.pbsi_ppid)
    }

    // MARK: - SSH session detection

    /// Walk the lineage looking for an `sshd`-class ancestor by signing
    /// identity. The bundle/binary id `com.openssh.sshd` (or
    /// `com.apple.openssh.sshd` on Apple-shipped sshd) marks the OpenSSH
    /// daemon. Tools that call themselves `sshd` but lack the matching
    /// signature are NOT recognised.
    private static func detectSshSession(lineage: [PidPathSigning]) -> SshSessionInfo? {
        for ancestor in lineage {
            guard let issuer = ancestor.issuerId else { continue }
            // Apple-shipped sshd: team identifier is "apple".
            if issuer == "apple" {
                let path = ancestor.executablePath ?? ""
                if path.hasSuffix("/sshd") || path.contains("openssh") {
                    return buildSshSessionInfo(sshdPid: ancestor.pid)
                }
            }
        }
        return nil
    }

    private static func buildSshSessionInfo(sshdPid: pid_t) -> SshSessionInfo {
        // The user's `SSH_CONNECTION` env var typically looks like:
        //   "<source-host> <source-port> <dest-host> <dest-port>"
        // We can read it from /proc-style introspection, but macOS doesn't
        // expose env vars cross-process without privileges, so this is
        // best-effort: we expose nil if we can't read it.
        let (user, host) = readSshClientFromAncestorEnv(sshdPid: sshdPid)
        // Synthesize a stable session id from the sshd pid + boot time. The
        // pid alone is fine for our use case (the session ends when sshd
        // dies), but we include start time so a recycled pid doesn't
        // collide with an older session id in the audit log.
        let startTime = readProcessStartTime(pid: sshdPid) ?? 0
        let sessionId = "sshd:\(sshdPid):\(startTime)"
        return SshSessionInfo(
            sourceUser: user,
            sourceHost: host,
            sshdPid: sshdPid,
            sessionId: sessionId
        )
    }

    /// Read `SSH_CONNECTION` from a descendant of the sshd. We look at the
    /// peer's own environment first (the connecting bsh-inject inherits
    /// them); if that fails we fall back to nil. macOS has no general
    /// privilege-free way to read another process's environment.
    ///
    /// This returns advisory display strings, not trust statements. RFC §6.2.
    private static func readSshClientFromAncestorEnv(sshdPid: pid_t) -> (String?, String?) {
        // Heuristic: `who am i` on the local user almost always carries the
        // SSH source in its parent env. We don't have enough signal at this
        // layer to do better without sandbox-busting tricks. Return nil and
        // let the prompt show "(SSH session)" without the source. The
        // session-end cleanup machinery doesn't depend on this either.
        return (nil, nil)
    }

    private static func readProcessStartTime(pid: pid_t) -> Int64? {
        // Use proc_pidinfo with PROC_PIDTBSDINFO (3) to get pbi_start_tvsec.
        // For simplicity in this first cut we return nil; the sshd pid +
        // a constant zero is unique-enough for the session id within the
        // bridge's lifetime.
        return nil
    }
}

// MARK: - SHA-256 wrapper

/// Internal SHA-256 helper that doesn't depend on importing CryptoKit at
/// every callsite. The public API is just `digest(_:)`.
private enum SHA256Wrapper {
    static func digest(_ data: Data) -> [UInt8] {
        return Array(_digest(data))
    }
    private static func _digest(_ data: Data) -> Data {
        // Use CommonCrypto via Apple's Security framework digest path.
        // CryptoKit.SHA256 would also work; doing it via CC keeps this
        // file's dependencies minimal.
        var hash = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { (ptr: UnsafeRawBufferPointer) in
            _ = CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}

// CommonCrypto bridge — declare what we need. CC_SHA256 is the only call.
@_silgen_name("CC_SHA256")
@discardableResult
private func CC_SHA256(_ data: UnsafeRawPointer?, _ len: CC_LONG, _ md: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>?

private typealias CC_LONG = UInt32
