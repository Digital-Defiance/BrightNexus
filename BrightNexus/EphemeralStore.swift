// EphemeralStore.swift
// BrightNexus
//
// Thread-safe in-memory store for decrypted BrightLink payloads with TTL-based
// auto-eviction.
//
// What it owns:
//   - One `Entry` per (sessionId, context) tuple. Re-injecting the same
//     context replaces the prior entry.
//   - A one-shot Timer scheduled for the moment of the nearest expiry.
//     Whenever entries are added or removed, the timer is recomputed.
//   - An `onChange` callback the AppDelegate uses to refresh the menu bar.
//
// What it does NOT own:
//   - Decryption. The caller (`BridgeProtocolHandler.handleLinkDeliver`)
//     has already verified the GCM tag and produced a fully-decoded
//     `BrightLinkPayload` before calling `insert(...)`.
//   - Persistence. Credentials never touch disk by design (RFC §5).

import Foundation

final class EphemeralStore {

    // MARK: - Internal types

    struct Entry: Identifiable {
        let payload: BrightLinkPayload
        let expiresAt: Date
        let sessionIdHex: String
        /// Provenance hint surfaced in the menu-bar / Dashboard (RFC §4.9.5).
        /// Captured at ingest time from `PeerAttestation.displayLabel`. nil
        /// for ingests with no attestation (e.g. unit tests).
        let providerLabel: String?

        /// Stable identity for SwiftUI lists. The (sessionId, context) pair
        /// uniquely identifies an entry — re-injecting the same context
        /// replaces the entry in place rather than creating a new row.
        var id: String { "\(sessionIdHex):\(payload.context)" }
    }

    // MARK: - State

    private let lock = NSLock()
    /// Keyed by context string (e.g. "http://localhost:3005").
    private var entries: [String: Entry] = [:]
    private var sweepTimer: Timer?

    /// Notified on the main thread when the store contents change.
    var onChange: (() -> Void)?

    // MARK: - Lifecycle

    init() {}

    deinit {
        sweepTimer?.invalidate()
    }

    // MARK: - Public API

    /// Store a newly decrypted payload, overwriting any prior entry for the
    /// same context. The session id (hex form) lets the caller bulk-evict
    /// when a session ends. `providerLabel` is the resolved peer-attestation
    /// hint (RFC §4.9.5); pass `nil` if attestation was not performed.
    /// `clampedExpiresAt` is the resolved post-clamp expiry (§4.9.5); the
    /// store does NOT re-derive expiry from the payload's own `ttl` field
    /// since the bridge is responsible for clamping before insert.
    func insert(
        payload: BrightLinkPayload,
        sessionIdHex: String,
        providerLabel: String? = nil,
        expiresAt: Date
    ) {
        let entry = Entry(
            payload: payload,
            expiresAt: expiresAt,
            sessionIdHex: sessionIdHex,
            providerLabel: providerLabel
        )
        lock.lock()
        entries[payload.context] = entry
        lock.unlock()
        notifyChange()
        rescheduleSweeper()
    }

    /// Remove all entries associated with a session (called on disconnect or
    /// session teardown).
    func removeSession(_ sessionIdHex: String) {
        lock.lock()
        entries = entries.filter { $0.value.sessionIdHex != sessionIdHex }
        lock.unlock()
        notifyChange()
        rescheduleSweeper()
    }

    /// Remove every entry. Used by the menu bar's "Clear All".
    func removeAll() {
        lock.lock()
        let wasEmpty = entries.isEmpty
        entries.removeAll()
        lock.unlock()
        if !wasEmpty {
            notifyChange()
            rescheduleSweeper()
        }
    }

    /// Snapshot of all currently active entries, sorted by context. Returns
    /// only entries that have not yet expired — `sweep()` may not have run
    /// yet for an instant past the deadline.
    func activeEntries() -> [Entry] {
        let now = Date()
        lock.lock()
        defer { lock.unlock() }
        return entries.values.filter { $0.expiresAt > now }
            .sorted { $0.payload.context < $1.payload.context }
    }

    // MARK: - TTL Sweeper

    /// Schedule a one-shot timer to fire the instant the nearest credential
    /// expires. Safe from any thread; timer scheduling hops to the main run
    /// loop because `Timer.scheduledTimer` requires it.
    private func rescheduleSweeper() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.sweepTimer?.invalidate()
            self.lock.lock()
            let next = self.entries.values.map(\.expiresAt).min()
            self.lock.unlock()
            guard let next = next else { return }
            let delay = max(0, next.timeIntervalSinceNow)
            self.sweepTimer = Timer.scheduledTimer(
                withTimeInterval: delay,
                repeats: false
            ) { [weak self] _ in
                self?.sweep()
            }
        }
    }

    private func sweep() {
        let now = Date()
        lock.lock()
        let before = entries.count
        entries = entries.filter { $0.value.expiresAt > now }
        let changed = entries.count != before
        lock.unlock()
        if changed {
            notifyChange()
        }
        rescheduleSweeper()
    }

    private func notifyChange() {
        DispatchQueue.main.async { [weak self] in
            self?.onChange?()
        }
    }
}
