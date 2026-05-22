// PeerAttestation.swift
// BrightNexus
//
// Implements RFC §4.9.5 — peer attestation for `LINK_DELIVER` connections.
//
// On every connection accept the bridge resolves:
//   - PID:                 getsockopt(LOCAL_PEERPID)
//   - executable path:     proc_pidpath()
//   - code-signing identity + validity:
//                          SecCodeCopyGuestWithAttributes / SecStaticCodeCheckValidity
//
// Default policy is "log only": the bridge stores the attestation alongside
// each ingested credential (audit log + menu-bar provenance hint) but does
// NOT reject ingests from unsigned or unknown binaries. The user-flippable
// "enforce" mode is wired through `BrightNexusPolicy.peerAttestationMode`;
// this file only computes the attestation, not the policy decision.

import Foundation
import Darwin
import Security

// `proc_pidpath` is in <libproc.h>; expose it explicitly.
@_silgen_name("proc_pidpath")
private func proc_pidpath(_ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ buffersize: UInt32) -> Int32

private let PROC_PIDPATHINFO_MAXSIZE: UInt32 = 4 * 1024

/// Result of attesting one connecting peer. All fields are best-effort —
/// missing data is encoded as nil, never thrown.
struct PeerAttestation {
    /// Process id of the connecting peer.
    let pid: pid_t
    /// Resolved executable path. nil if `proc_pidpath` failed (e.g. process
    /// already exited between `accept()` and the lookup).
    let executablePath: String?
    /// "Designated requirement" — Apple's parsed code-signing identity.
    /// Includes the team identifier and the bundle/binary identifier.
    /// nil if the binary is unsigned or signature inspection failed.
    let codeSigningIdentity: String?
    /// True if `SecStaticCodeCheckValidity` passed. False if the signature
    /// was invalid or absent.
    let signatureValid: Bool

    /// Best-effort short label used in the menu bar / Dashboard provenance
    /// hint. Falls back to the executable basename.
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
        return [
            "pid": Int(pid),
            "executablePath": executablePath ?? "",
            "codeSigningIdentity": codeSigningIdentity ?? "",
            "signatureValid": signatureValid,
        ]
    }
}

enum PeerAttestationLookup {

    /// Attest the peer connected on `clientFd`. Always returns a value —
    /// missing data fields are nil rather than thrown so the caller can log
    /// the partial attestation and proceed.
    static func attest(clientFd: Int32) -> PeerAttestation {
        let pid = readPeerPID(clientFd: clientFd) ?? 0
        let path = pid > 0 ? readExecutablePath(pid: pid) : nil
        let (identity, valid) = path != nil
            ? readCodeSigningIdentity(executablePath: path!)
            : (nil, false)
        return PeerAttestation(
            pid: pid,
            executablePath: path,
            codeSigningIdentity: identity,
            signatureValid: valid
        )
    }

    // MARK: - PID

    /// `LOCAL_PEERPID` is defined in <sys/un.h> as 0x002. Surface it inline
    /// rather than importing the C header; the value is fixed across all
    /// macOS versions BrightNexus supports.
    private static let LOCAL_PEERPID: Int32 = 0x002

    private static func readPeerPID(clientFd: Int32) -> pid_t? {
        var pid: pid_t = 0
        var size = socklen_t(MemoryLayout<pid_t>.size)
        let result = withUnsafeMutablePointer(to: &pid) {
            $0.withMemoryRebound(to: Int8.self, capacity: 1) { ptr in
                getsockopt(clientFd, SOL_LOCAL, LOCAL_PEERPID, UnsafeMutableRawPointer(ptr), &size)
            }
        }
        if result == 0 && pid > 0 {
            return pid
        }
        return nil
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

    // MARK: - Code signature

    /// Returns (identity, valid). `identity` is the designated requirement's
    /// signing identifier (typically `<team>.<bundle-id>` or the binary's
    /// CDHash for unsigned/ad-hoc-signed binaries). Best-effort — failures
    /// produce `(nil, false)`.
    private static func readCodeSigningIdentity(executablePath: String) -> (String?, Bool) {
        let url = URL(fileURLWithPath: executablePath) as CFURL
        var staticCode: SecStaticCode?
        let createResult = SecStaticCodeCreateWithPath(url, [], &staticCode)
        guard createResult == errSecSuccess, let code = staticCode else {
            return (nil, false)
        }

        // Validity check first — sets the "valid signature" bit.
        let validityResult = SecStaticCodeCheckValidity(code, [], nil)
        let isValid = (validityResult == errSecSuccess)

        // Extract the signing identifier from the code's signing information.
        var infoDict: CFDictionary?
        let infoResult = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &infoDict
        )
        guard infoResult == errSecSuccess,
              let info = infoDict as? [String: Any] else {
            return (nil, isValid)
        }
        // `kSecCodeInfoIdentifier` (`identifier` key) is the bundle / binary
        // identifier from the signature; for App Store + Developer ID binaries
        // it's the bundle id. For unsigned binaries it's nil.
        if let identifier = info["identifier"] as? String, !identifier.isEmpty {
            return (identifier, isValid)
        }
        return (nil, isValid)
    }
}
