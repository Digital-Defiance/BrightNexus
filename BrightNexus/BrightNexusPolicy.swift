// BrightNexusPolicy.swift
// BrightNexus
//
// Centralised, user-configurable policy knobs for SDI behavior.
//
// All settings persist via UserDefaults and are read on every hit; the
// settings UI may write to them at any time. The bridge code paths read
// through the static `BrightNexusPolicy.current` accessor rather than
// caching, so a flip in the UI takes effect for the next request without
// restart.
//
// Defaults are deliberately permissive:
//   - Peer attestation:  log-only (every LINK_DELIVER records provenance,
//                        nothing is rejected).
//   - Per-credential TTL ceiling: 3600 seconds (1 hour, RFC §4.9.5).
//
// Users who want a hardened policy flip these in the BrightNexus Settings
// window.

import Foundation

enum PeerAttestationMode: String, CaseIterable {
    /// Record provenance in the audit log + UI; never reject. Default.
    case logOnly = "log-only"
    /// Reject ingests from binaries that fail signature validation, or
    /// fall outside the allowlist, or cannot be attested at all.
    case enforce = "enforce"
}

struct BrightNexusPolicy {

    // MARK: - Defaults keys (stable; do not rename)

    private enum Keys {
        static let peerAttestationMode = "sdi.peerAttestationMode"
        static let credentialTtlCeilingSeconds = "sdi.credentialTtlCeilingSeconds"
    }

    // MARK: - Default values

    /// Default per-credential TTL ceiling (RFC §4.9.5). 1 hour.
    static let defaultCredentialTtlCeilingSeconds: TimeInterval = 3600

    /// Hard floor on the configurable ceiling. Below this, the bridge
    /// would clamp legitimate short-lived workflow tokens (e.g. a 60s
    /// one-time code), which is more annoying than secure.
    static let credentialTtlCeilingFloorSeconds: TimeInterval = 60

    /// Hard ceiling on the configurable ceiling. Matches the §4.1
    /// session-TTL cap; it makes no sense for a credential to outlive
    /// its session.
    static let credentialTtlCeilingCeilingSeconds: TimeInterval = 8 * 3600

    // MARK: - Live readers

    static var peerAttestationMode: PeerAttestationMode {
        let raw = UserDefaults.standard.string(forKey: Keys.peerAttestationMode)
            ?? PeerAttestationMode.logOnly.rawValue
        return PeerAttestationMode(rawValue: raw) ?? .logOnly
    }

    /// Resolved per-credential TTL ceiling, with the floor / ceiling bounds
    /// applied. UI code SHOULD call this rather than reading raw defaults.
    static var credentialTtlCeilingSeconds: TimeInterval {
        let stored = UserDefaults.standard.object(forKey: Keys.credentialTtlCeilingSeconds) as? TimeInterval
        let raw = stored ?? defaultCredentialTtlCeilingSeconds
        return min(
            credentialTtlCeilingCeilingSeconds,
            max(credentialTtlCeilingFloorSeconds, raw)
        )
    }

    // MARK: - Live writers (used by the Settings window)

    static func setPeerAttestationMode(_ mode: PeerAttestationMode) {
        UserDefaults.standard.set(mode.rawValue, forKey: Keys.peerAttestationMode)
    }

    static func setCredentialTtlCeilingSeconds(_ seconds: TimeInterval) {
        // Clamp at write time too so a malformed value can never stick.
        let clamped = min(
            credentialTtlCeilingCeilingSeconds,
            max(credentialTtlCeilingFloorSeconds, seconds)
        )
        UserDefaults.standard.set(clamped, forKey: Keys.credentialTtlCeilingSeconds)
    }
}
