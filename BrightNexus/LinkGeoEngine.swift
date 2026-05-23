// LinkGeoEngine.swift
// BrightNexus
//
// Orchestrates the §7.4 ACL gate + §9 LINK_GEO_* command surface.
// Ports test-harness/src/mock-brightnexus/geoEngine.ts.
//
// Every LINK_GEO_* request flows through one of the public methods on
// this class:
//   1. Look up caller in ACL → allow / deny / prompt / denyCap.
//   2. If prompt: call coordinator → map outcome to allow / deny.
//   3. On allow_always / deny_always: upsert the ACL entry.
//   4. Record an audit-log entry on every decision.
//
// LINK_GEO_STATUS bypasses the ACL per RFC §9.1 — it carries no location
// data and is needed for graceful degradation.
//

import Foundation

// MARK: - Stable error strings (RFC §9.7)

enum LinkGeoErrors {
    static let SESSION_NOT_REGISTERED     = "geo: session not registered"
    static let SCOPE_DENIED_BY_POLICY     = "geo: scope denied by policy"
    static let SCOPE_UNAVAILABLE_UNSIGNED = "geo: scope unavailable for unsigned binary"
    static let PROMPT_TIMED_OUT           = "geo: user prompt timed out"
    static let USER_DENIED                = "geo: user denied"
    static let PROMPT_UNAVAILABLE         = "geo: prompt unavailable"
    static let THROTTLED                  = "geo: throttled"
    static let ENGINE_UNAVAILABLE         = "geo: engine unavailable"
    static let ZONE_NOT_FOUND             = "geo: zone not found"
    static let FORMAT_INVALID             = "geo: format invalid"
    static let REFRESH_TIMED_OUT          = "geo: refresh timed out"
}

// MARK: - GeoSourceProtocol

/// Errors a geo source can return from `requestRefresh`.
enum GeoSourceError: Error, CustomStringConvertible {
    case engineUnavailable(reason: String)
    case timeout
    case denied(reason: String)

    var description: String {
        switch self {
        case .engineUnavailable(let r): return "engine_unavailable: \(r)"
        case .timeout:                  return "timeout"
        case .denied(let r):            return "denied: \(r)"
        }
    }
}

/// The platform-pluggable geo source. Swap for CoreLocationGeoSource in
/// Wave 4i.
protocol GeoSourceProtocol: AnyObject {
    func currentFix() -> GeoFix?
    func requestRefresh(timeoutMs: Int) async throws -> GeoFix
    func subscribe(handler: @escaping (GeoFix) -> Void) -> () -> Void
    func status() -> GeoSourceStatus
}

/// Stub source that has no fix and can't refresh. Lets `LINK_GEO_STATUS`
/// work end-to-end (returns alive: false) and lets the prompt logic fire
/// so users see the modal even without a real fix.
final class NullGeoSource: GeoSourceProtocol {
    func currentFix() -> GeoFix? { nil }

    func requestRefresh(timeoutMs: Int) async throws -> GeoFix {
        throw GeoSourceError.engineUnavailable(reason: "NullGeoSource")
    }

    func subscribe(handler: @escaping (GeoFix) -> Void) -> () -> Void {
        return {}
    }

    func status() -> GeoSourceStatus {
        return GeoSourceStatus(
            kind: "NullGeoSource",
            alive: false,
            fix_age_seconds: nil,
            accuracy_m: nil
        )
    }
}

// MARK: - Audit sink

/// Audit-event kinds emitted by the geo engine. RFC §7.7.
enum GeoAuditDecision: String {
    case allowedByAcl        = "allowed_by_acl"
    case allowedByPrompt     = "allowed_by_prompt"
    case deniedByAcl         = "denied_by_acl"
    case deniedByPrompt      = "denied_by_prompt"
    case deniedUnsignedCap   = "denied_unsigned_cap"
    case promptTimeout       = "prompt_timeout"
    case throttled           = "throttled"
    case engineUnavailable   = "engine_unavailable"
}

/// One audit entry. RFC §7.7.
struct GeoAuditEntry {
    var brightdate: Double
    var command: String
    var scope: LinkGeoScope
    var decision: GeoAuditDecision
    var policyAtDecision: String?
    var attestation: PeerAttestation
    var responseSummary: [String: Any]

    /// Dictionary form for SwiftUI / JSON inspection.
    var asDictionary: [String: Any] {
        return [
            "brightdate":       brightdate,
            "command":          command,
            "scope":            scope.rawValue,
            "decision":         decision.rawValue,
            "policyAtDecision": policyAtDecision ?? NSNull(),
            "attestation":      attestation.auditEntry,
            "responseSummary":  responseSummary,
        ]
    }
}

/// The audit-log sink the engine writes through.
protocol GeoAuditSink: AnyObject {
    func recordGeoEvent(_ entry: GeoAuditEntry)
}

/// Default sink that pushes to `AppState.shared.auditLog` on the main
/// actor. Bounded to a sane size so the in-memory log doesn't grow
/// without limit.
final class MainActorAuditLog: GeoAuditSink {
    func recordGeoEvent(_ entry: GeoAuditEntry) {
        Task { @MainActor in
            AppState.shared.auditLog.append(entry)
            // Bound the in-memory log.
            if AppState.shared.auditLog.count > 1000 {
                AppState.shared.auditLog.removeFirst(
                    AppState.shared.auditLog.count - 1000
                )
            }
        }
    }
}

// MARK: - LinkGeoEngine

/// Coordinate format requested by `LINK_GEO_GET`. RFC §9.4.
enum CoordinateFormat: String {
    case wgs84       = "wgs84"
    case brightspace = "brightspace"
    case both        = "both"
}

/// Result wrapper. Either OK with data or a stable error string.
enum GeoResult<T> {
    case ok(T)
    case err(String)
}

private struct ZoneTrackerState {
    var zoneId: String?
    var enteredAtBd: Double
}

/// The orchestrator. `BridgeProtocolHandler` calls into one of the
/// public `async` methods per LINK_GEO_* command.
final class LinkGeoEngine {
    let acl: LinkAcl
    let aclSession: LinkAclSession
    let zones: LinkZoneEngine
    let prompt: LinkAclPromptCoordinator
    let source: GeoSourceProtocol
    let audit: GeoAuditSink
    let nowBd: () -> Double
    let promptTimeoutSeconds: Int

    private var zoneTracker = ZoneTrackerState(zoneId: nil, enteredAtBd: 0)
    private var zoneTransitionHandlers: [(String?, String?, Double) -> Void] = []
    private var sourceUnsubscribe: (() -> Void)?
    private var sessionGcTimer: Timer?

    init(
        acl: LinkAcl,
        aclSession: LinkAclSession,
        zones: LinkZoneEngine,
        prompt: LinkAclPromptCoordinator,
        source: GeoSourceProtocol?,
        audit: GeoAuditSink,
        nowBd: @escaping () -> Double,
        promptTimeoutSeconds: Int = 30
    ) {
        self.acl = acl
        self.aclSession = aclSession
        self.zones = zones
        self.prompt = prompt
        self.source = source ?? NullGeoSource()
        self.audit = audit
        self.nowBd = nowBd
        self.promptTimeoutSeconds = promptTimeoutSeconds

        // Subscribe to fix updates so we can detect zone transitions.
        // For NullGeoSource this is a no-op.
        self.sourceUnsubscribe = self.source.subscribe { [weak self] _ in
            self?.evaluateZoneTransition()
        }

        // Periodic session-ACL GC: every 30 seconds, prune entries
        // whose sshd_pid is no longer alive (RFC §7.3). The timer
        // fires on the main run loop because LinkAclSession publishes
        // didChangeNotification on the main queue.
        let timer = Timer(timeInterval: 30.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            let removed = self.aclSession.gcDeadSessions()
            if removed > 0 {
                NSLog("[BrightNexus] session ACL GC: removed %d entries (sshd dead)", removed)
                try? self.aclSession.saveToDisk()
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        self.sessionGcTimer = timer
    }

    deinit {
        sourceUnsubscribe?()
        sessionGcTimer?.invalidate()
    }

    // MARK: - Read-only adapters used by the Settings UI (Wave 4h).
    //
    // These don't gate on attestation because they only describe the
    // engine's own state to the local user via SwiftUI; no caller
    // location data flows through them.

    /// `LINK_GEO_STATUS`-shaped snapshot, plain Swift fields. Used by the
    /// Settings → Geo Engine tab. Mirrors what the wire surface returns.
    struct StatusSnapshot {
        var kind: String
        var alive: Bool
        var fixAgeSeconds: Double?
        var accuracyM: Double?
    }

    func statusSnapshot() -> StatusSnapshot {
        let s = source.status()
        return StatusSnapshot(
            kind: s.kind,
            alive: s.alive,
            fixAgeSeconds: s.fix_age_seconds,
            accuracyM: s.accuracy_m
        )
    }

    /// Currently-tracked zone id, or nil if no fix or no matching zone.
    func currentZoneId() -> String? {
        return zoneTracker.zoneId
    }

    /// Number of zone definitions loaded.
    func zonesCount() -> Int {
        return zones.list().count
    }

    // MARK: - LINK_GEO_STATUS (§9.1) — no scope gate

    func status(attestation: PeerAttestation) async -> [String: Any] {
        let s = source.status()
        return [
            "ok":                true,
            "alive":             s.alive,
            "engine_kind":       s.kind,
            "fix_age_seconds":   s.fix_age_seconds as Any? ?? NSNull(),
            "accuracy_m":        s.accuracy_m as Any? ?? NSNull(),
        ]
    }

    // MARK: - LINK_GEO_PROXIMITY (§9.2)

    func proximity(attestation: PeerAttestation, zoneId: String?) async -> [String: Any] {
        let scope: LinkGeoScope = .proximity
        let cmd = "LINK_GEO_PROXIMITY"

        // If no zone id was supplied, the answer is zone_not_found.
        // (We deliberately don't gate the ACL on a missing zone — the
        // request was malformed before we ever needed scope.)
        guard let zoneId = zoneId, !zoneId.isEmpty else {
            return ["error": LinkGeoErrors.ZONE_NOT_FOUND]
        }

        let gate = await gateScope(
            attestation: attestation, scope: scope,
            command: cmd, extra: ["zoneId": zoneId]
        )
        if case .err(let e) = gate { return ["error": e] }

        guard let zone = zones.byId(zoneId) else {
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: nowBd(), command: cmd, scope: scope,
                decision: .engineUnavailable, policyAtDecision: nil,
                attestation: attestation,
                responseSummary: ["error": "zone_not_found", "zoneId": zoneId]
            ))
            return ["error": LinkGeoErrors.ZONE_NOT_FOUND]
        }

        guard let fix = source.currentFix() else {
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: nowBd(), command: cmd, scope: scope,
                decision: .engineUnavailable, policyAtDecision: nil,
                attestation: attestation,
                responseSummary: ["error": "no_fix"]
            ))
            return ["error": LinkGeoErrors.ENGINE_UNAVAILABLE]
        }

        let inZone = pointInZone(fix: fix, zone: zone)
        return [
            "ok":         true,
            "in_zone":    inZone,
            "brightdate": fix.brightdate,
        ]
    }

    // MARK: - LINK_GEO_ZONE (§9.3)

    func zone(attestation: PeerAttestation) async -> [String: Any] {
        let scope: LinkGeoScope = .zone
        let cmd = "LINK_GEO_ZONE"

        let gate = await gateScope(
            attestation: attestation, scope: scope,
            command: cmd, extra: [:]
        )
        if case .err(let e) = gate { return ["error": e] }

        guard let fix = source.currentFix() else {
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: nowBd(), command: cmd, scope: scope,
                decision: .engineUnavailable, policyAtDecision: nil,
                attestation: attestation,
                responseSummary: ["error": "no_fix"]
            ))
            return ["error": LinkGeoErrors.ENGINE_UNAVAILABLE]
        }

        evaluateZoneTransition()
        let z = zones.currentZone(fix: fix)
        return [
            "ok":             true,
            "zone":           z?.id as Any? ?? NSNull(),
            "dwell_seconds":  dwellSecondsAtNow(),
            "brightdate":     fix.brightdate,
        ]
    }

    // MARK: - LINK_GEO_GET (§9.4)

    func get(attestation: PeerAttestation, format: CoordinateFormat) async -> [String: Any] {
        let scope: LinkGeoScope = .precise
        let cmd = "LINK_GEO_GET"

        let gate = await gateScope(
            attestation: attestation, scope: scope,
            command: cmd, extra: ["format": format.rawValue]
        )
        if case .err(let e) = gate { return ["error": e] }

        guard let fix = source.currentFix() else {
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: nowBd(), command: cmd, scope: scope,
                decision: .engineUnavailable, policyAtDecision: nil,
                attestation: attestation,
                responseSummary: ["error": "no_fix"]
            ))
            return ["error": LinkGeoErrors.ENGINE_UNAVAILABLE]
        }

        var position: [String: Any] = [:]
        if format == .wgs84 || format == .both {
            var w: [String: Any] = ["lat": fix.wgs84.lat, "lon": fix.wgs84.lon]
            if let alt = fix.wgs84.alt_m { w["alt_m"] = alt }
            position["wgs84"] = w
        }
        if format == .brightspace || format == .both {
            // Convert WGS84 → ECEF → BrightSpace. ECEF is the canonical
            // intermediate; BrightSpace is just ECEF metres divided by
            // the speed of light per RFC §6.3.
            let ecef = wgs84ToEcef(fix.wgs84)
            let bs = ecefToBrightSpace(ecef, epochBd: fix.brightdate)
            position["brightspace"] = [
                "x_bm":     bs.x_bm,
                "y_bm":     bs.y_bm,
                "z_bm":     bs.z_bm,
                "epoch_bd": bs.epoch_bd,
            ]
        }

        return [
            "ok":         true,
            "position":   position,
            "accuracy_m": fix.accuracy_m,
            "brightdate": fix.brightdate,
        ]
    }

    // MARK: - LINK_GEO_REFRESH (§9.5)

    func refresh(attestation: PeerAttestation, timeoutSeconds: Int) async -> [String: Any] {
        let scope: LinkGeoScope = .status
        let cmd = "LINK_GEO_REFRESH"

        let gate = await gateScope(
            attestation: attestation, scope: scope,
            command: cmd, extra: ["timeoutSeconds": timeoutSeconds]
        )
        if case .err(let e) = gate { return ["error": e] }

        do {
            let fix = try await source.requestRefresh(timeoutMs: timeoutSeconds * 1000)
            return [
                "ok":              true,
                "fix_age_seconds": 0,
                "accuracy_m":      fix.accuracy_m,
            ]
        } catch {
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: nowBd(), command: cmd, scope: scope,
                decision: .engineUnavailable, policyAtDecision: nil,
                attestation: attestation,
                responseSummary: ["error": "refresh_failed"]
            ))
            // For the NullGeoSource we surface ENGINE_UNAVAILABLE rather
            // than REFRESH_TIMED_OUT — there's no engine, not a timeout.
            return ["error": LinkGeoErrors.ENGINE_UNAVAILABLE]
        }
    }

    // MARK: - Push (zone transitions)

    @discardableResult
    func onZoneTransition(_ handler: @escaping (String?, String?, Double) -> Void) -> () -> Void {
        zoneTransitionHandlers.append(handler)
        let idx = zoneTransitionHandlers.count - 1
        return { [weak self] in
            // Best-effort removal — handlers are append-only in practice.
            guard let self = self, idx < self.zoneTransitionHandlers.count else { return }
            self.zoneTransitionHandlers.remove(at: idx)
        }
    }

    // MARK: - Internals

    /// Run the §7.4 lookup + §7.5 prompt flow.
    private func gateScope(
        attestation: PeerAttestation,
        scope: LinkGeoScope,
        command: String,
        extra: [String: Any]
    ) async -> GeoResult<Bool> {
        let now = nowBd()

        // RFC §7.4 step 1: session ACL first. A session-bound grant
        // takes precedence over the durable ACL because it's the one
        // the user explicitly chose at prompt time inside this SSH
        // session. Only consulted when the peer is in an SSH session.
        if let sessionEntry = aclSession.lookup(
            attestation: attestation, scope: scope, nowBd: now
        ) {
            let policy = sessionEntry.scopes[scope] ?? .prompt
            switch policy {
            case .always:
                aclSession.recordUse(entryId: sessionEntry.id, nowBd: now)
                try? aclSession.saveToDisk()
                audit.recordGeoEvent(GeoAuditEntry(
                    brightdate: now, command: command, scope: scope,
                    decision: .allowedByAcl, policyAtDecision: "session",
                    attestation: attestation, responseSummary: extra
                ))
                return .ok(true)
            case .deny:
                audit.recordGeoEvent(GeoAuditEntry(
                    brightdate: now, command: command, scope: scope,
                    decision: .deniedByAcl, policyAtDecision: "session-deny",
                    attestation: attestation, responseSummary: extra
                ))
                return .err(LinkGeoErrors.SCOPE_DENIED_BY_POLICY)
            case .prompt:
                // Fall through to durable ACL lookup; if THAT also says
                // prompt we'll fire the modal. The session entry exists
                // but doesn't decide this scope.
                break
            }
        }

        // RFC §7.4 step 2: durable ACL.
        let lookup = acl.lookup(attestation: attestation, scope: scope, nowBd: now)

        switch lookup {
        case .allow(let entry):
            acl.recordUse(entryId: entry.id, nowBd: now)
            try? acl.saveToDisk()
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .allowedByAcl, policyAtDecision: "always",
                attestation: attestation, responseSummary: extra
            ))
            return .ok(true)

        case .deny(_, _):
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .deniedByAcl, policyAtDecision: "deny",
                attestation: attestation, responseSummary: extra
            ))
            return .err(LinkGeoErrors.SCOPE_DENIED_BY_POLICY)

        case .denyCap:
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .deniedUnsignedCap, policyAtDecision: "unsigned-cap",
                attestation: attestation, responseSummary: extra
            ))
            return .err(LinkGeoErrors.SCOPE_UNAVAILABLE_UNSIGNED)

        case .prompt(let existing):
            let req = PromptRequest(
                attestation: attestation,
                scope: scope,
                existingEntry: existing,
                timeoutSeconds: promptTimeoutSeconds,
                reason: existing == nil ? .noMatch : .policyPrompt
            )
            let outcome = await prompt.prompt(request: req)
            return handlePromptOutcome(
                attestation: attestation, scope: scope,
                command: command, extra: extra,
                outcome: outcome, existing: existing
            )
        }
    }

    private func handlePromptOutcome(
        attestation: PeerAttestation,
        scope: LinkGeoScope,
        command: String,
        extra: [String: Any],
        outcome: PromptOutcome,
        existing: LinkAclEntry?
    ) -> GeoResult<Bool> {
        let now = nowBd()
        switch outcome {
        case .allowOnce:
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .allowedByPrompt, policyAtDecision: "allow_once",
                attestation: attestation, responseSummary: extra
            ))
            return .ok(true)

        case .allowAlways:
            let entry = upsertEntryForScope(
                attestation: attestation, scope: scope,
                policy: .always, existing: existing, nowBd: now
            )
            acl.recordUse(entryId: entry.id, nowBd: now)
            try? acl.saveToDisk()
            var summary = extra; summary["persistedAs"] = "always"
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .allowedByPrompt, policyAtDecision: "always",
                attestation: attestation, responseSummary: summary
            ))
            return .ok(true)

        case .allowSession(let sessionId):
            // RFC §7.3: allow_session writes to geo-acl-session.json,
            // NOT geo-acl.json. The grant lives only as long as the
            // sshd_pid encoded in the session id stays alive (and at
            // most until the bridge restarts).
            let entry = upsertSessionEntryForScope(
                attestation: attestation, scope: scope,
                policy: .always, nowBd: now,
                sshSessionId: sessionId
            )
            aclSession.recordUse(entryId: entry.id, nowBd: now)
            try? aclSession.saveToDisk()
            var summary = extra; summary["sshSessionId"] = sessionId
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .allowedByPrompt, policyAtDecision: "session",
                attestation: attestation, responseSummary: summary
            ))
            return .ok(true)

        case .deny:
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .deniedByPrompt, policyAtDecision: "deny_once",
                attestation: attestation, responseSummary: extra
            ))
            return .err(LinkGeoErrors.USER_DENIED)

        case .denyAlways:
            _ = upsertEntryForScope(
                attestation: attestation, scope: scope,
                policy: .deny, existing: existing, nowBd: now
            )
            try? acl.saveToDisk()
            var summary = extra; summary["persistedAs"] = "deny"
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .deniedByPrompt, policyAtDecision: "deny",
                attestation: attestation, responseSummary: summary
            ))
            return .err(LinkGeoErrors.USER_DENIED)

        case .timeout:
            audit.recordGeoEvent(GeoAuditEntry(
                brightdate: now, command: command, scope: scope,
                decision: .promptTimeout, policyAtDecision: nil,
                attestation: attestation, responseSummary: extra
            ))
            return .err(LinkGeoErrors.PROMPT_TIMED_OUT)
        }
    }

    private func upsertEntryForScope(
        attestation: PeerAttestation,
        scope: LinkGeoScope,
        policy: LinkGeoPolicy,
        existing: LinkAclEntry?,
        nowBd: Double,
        sshSessionId: String? = nil
    ) -> LinkAclEntry {
        let id = existing?.id ?? generateAclEntryId(nowBd: nowBd)
        var scopes = existing?.scopes ?? linkAclDefaultPromptScopes()

        // RFC §7.1 cascade: a grant for a higher-rung scope implies grants
        // for lower rungs. Symmetric for deny: a deny at a lower rung
        // implies deny at every higher rung. This collapses a typical
        // session's three-or-four-scope prompt sequence into a single
        // user decision.
        //
        // For unsigned callers the cascade is bounded by §7.1's
        // unsigned-cap so we never persist a forbidden grant.
        let unsignedCapRank = LINK_GEO_UNSIGNED_MAX_SCOPE.rank
        let isUnsigned = attestation.attestationClass == .unsigned

        switch policy {
        case .always:
            // Grant `always` to the requested scope and every lower scope.
            // (Already-deny entries at lower scopes are NOT clobbered —
            // the user previously made an explicit choice there.)
            for s in LinkGeoScope.allCases where s.rank <= scope.rank {
                if isUnsigned && s.rank > unsignedCapRank { continue }
                if scopes[s] == .deny { continue }
                scopes[s] = .always
            }
        case .deny:
            // Deny at a lower scope implies deny at every higher scope.
            // (Already-always entries at higher scopes ARE clobbered to
            // deny — the user is explicitly tightening trust.)
            for s in LinkGeoScope.allCases where s.rank >= scope.rank {
                scopes[s] = .deny
            }
        case .prompt:
            // Single-scope set; no cascade. (Used by the upsert helper
            // when the engine wants to "downgrade back to prompt" for one
            // specific scope, e.g. a future revoke flow.)
            scopes[scope] = .prompt
        }

        let displayName = existing?.displayName ?? defaultDisplayName(attestation)
        let fallbackHash: String?
        if attestation.attestationClass == .unsigned, let h = attestation.executableHash {
            fallbackHash = "sha256:" + h.map { String(format: "%02x", $0) }.joined()
        } else {
            fallbackHash = nil
        }

        let entry = LinkAclEntry(
            id: id,
            displayName: displayName,
            attestationClass: attestation.attestationClass,
            issuerId: attestation.issuerId,
            subjectId: attestation.subjectId,
            expectedPath: attestation.executablePath,
            fallbackHash: fallbackHash,
            scopes: scopes,
            addedAtBd: existing?.addedAtBd ?? nowBd,
            lastUsedBd: nowBd,
            expiresAtBd: existing?.expiresAtBd,
            purpose: existing?.purpose,
            sshSessionId: sshSessionId ?? existing?.sshSessionId
        )
        acl.upsert(entry)
        return entry
    }

    /// Session-ACL variant of upsertEntryForScope. Writes to
    /// geo-acl-session.json (RFC §7.3) instead of the durable
    /// geo-acl.json. Same §7.1 cascade semantics. Always finds-or-
    /// creates a fresh entry keyed on (attestation, sshSessionId);
    /// never reuses entries from the durable ACL.
    private func upsertSessionEntryForScope(
        attestation: PeerAttestation,
        scope: LinkGeoScope,
        policy: LinkGeoPolicy,
        nowBd: Double,
        sshSessionId: String
    ) -> LinkAclSessionEntry {
        // Find an existing session entry for this caller in this session,
        // if any. Same identity tuple match as the durable lookup.
        let existing: LinkAclSessionEntry? = aclSession.list().first { e in
            e.sshSessionId == sshSessionId
                && e.attestationClass == attestation.attestationClass
                && e.issuerId == attestation.issuerId
                && e.subjectId == attestation.subjectId
        }

        let id = existing?.id ?? generateAclEntryId(nowBd: nowBd)
        var scopes = existing?.scopes ?? linkAclDefaultPromptScopes()

        // Same RFC §7.1 cascade as durable upsert.
        let unsignedCapRank = LINK_GEO_UNSIGNED_MAX_SCOPE.rank
        let isUnsigned = attestation.attestationClass == .unsigned
        switch policy {
        case .always:
            for s in LinkGeoScope.allCases where s.rank <= scope.rank {
                if isUnsigned && s.rank > unsignedCapRank { continue }
                if scopes[s] == .deny { continue }
                scopes[s] = .always
            }
        case .deny:
            for s in LinkGeoScope.allCases where s.rank >= scope.rank {
                scopes[s] = .deny
            }
        case .prompt:
            scopes[scope] = .prompt
        }

        let fallbackHash: String?
        if attestation.attestationClass == .unsigned, let h = attestation.executableHash {
            fallbackHash = "sha256:" + h.map { String(format: "%02x", $0) }.joined()
        } else {
            fallbackHash = nil
        }

        let entry = LinkAclSessionEntry(
            id: id,
            displayName: existing?.displayName ?? defaultDisplayName(attestation),
            attestationClass: attestation.attestationClass,
            issuerId: attestation.issuerId,
            subjectId: attestation.subjectId,
            expectedPath: attestation.executablePath,
            fallbackHash: fallbackHash,
            scopes: scopes,
            addedAtBd: existing?.addedAtBd ?? nowBd,
            lastUsedBd: nowBd,
            sshSessionId: sshSessionId,
            sshdPid: attestation.sshSession?.sshdPid ?? 0,
            sourceUser: attestation.sshSession?.sourceUser,
            sourceHost: attestation.sshSession?.sourceHost
        )
        aclSession.upsert(entry)
        return entry
    }

    /// Re-evaluate the current zone and emit transition events if it changed.
    private func evaluateZoneTransition() {
        guard let fix = source.currentFix() else { return }
        let current = zones.currentZone(fix: fix)
        let toId = current?.id
        if toId == zoneTracker.zoneId { return }
        let fromId = zoneTracker.zoneId
        zoneTracker = ZoneTrackerState(zoneId: toId, enteredAtBd: fix.brightdate)
        for handler in zoneTransitionHandlers {
            handler(fromId, toId, fix.brightdate)
        }
    }

    private func dwellSecondsAtNow() -> Int {
        guard zoneTracker.zoneId != nil else { return 0 }
        let secs = (nowBd() - zoneTracker.enteredAtBd) * 86_400.0
        return max(0, Int(secs))
    }
}

// MARK: - Helpers

private func defaultDisplayName(_ a: PeerAttestation) -> String {
    if let s = a.subjectId, !s.isEmpty { return s }
    if let p = a.executablePath { return (p as NSString).lastPathComponent }
    return "pid \(a.pid)"
}

private func generateAclEntryId(nowBd: Double) -> String {
    // Quick pseudo-ULID. We only need stable lex ordering at the byte
    // level — see TS port for rationale.
    let t = String(Int64(nowBd * 1000), radix: 36, uppercase: true)
    var randBytes = [UInt8](repeating: 0, count: 8)
    _ = SecRandomCopyBytes(kSecRandomDefault, randBytes.count, &randBytes)
    let r = randBytes.map { String(format: "%02X", $0) }.joined()
    let raw = "01" + t + r
    if raw.count >= 26 { return String(raw.prefix(26)) }
    return raw + String(repeating: "0", count: 26 - raw.count)
}

// MARK: - BrightDate clock

/// J2000.0 = Unix ms 946_727_935_816 per the BrightDate spec.
private let J2000_UTC_UNIX_MS: Double = 946_727_935_816
private let SECONDS_PER_DAY: Double = 86_400

func unixSecondsToBrightDate(_ unixSeconds: Double) -> Double {
    return (unixSeconds * 1000.0 - J2000_UTC_UNIX_MS) / 1000.0 / SECONDS_PER_DAY
}

func currentBrightDate() -> Double {
    return unixSecondsToBrightDate(Date().timeIntervalSince1970)
}
