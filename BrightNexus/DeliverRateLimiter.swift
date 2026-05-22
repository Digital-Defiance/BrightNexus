// DeliverRateLimiter.swift
// BrightNexus
//
// Per-session sliding-window failure counter for `LINK_DELIVER` and
// `LINK_PUSH`, per RFC §4.4. The limiter holds a fixed-size ring of
// timestamped failure events; on every record + check, expired events
// (older than `windowSeconds`) drop out automatically.
//
// Threshold defaults to 30 failures/min (RFC §4.4 baseline). Successes
// are NOT counted at the protocol layer per the same RFC update.
//
// Each connection owns its own limiter instance; there is no cross-session
// or cross-connection state. When the threshold is reached, the connection
// MUST tear down the SDI session and require re-registration.

import Foundation

final class DeliverRateLimiter {

    // MARK: - Configuration

    /// Failure threshold per `windowSeconds`. RFC §4.4 specifies 30/min.
    let threshold: Int
    /// Sliding window length in seconds. RFC §4.4 specifies 60.
    let windowSeconds: TimeInterval

    init(threshold: Int = 30, windowSeconds: TimeInterval = 60) {
        self.threshold = threshold
        self.windowSeconds = windowSeconds
    }

    // MARK: - State

    private let lock = NSLock()
    /// Unix timestamps of recorded failures within the active window.
    /// Capped at 2× threshold so a runaway emitter can't unboundedly grow
    /// this array — once we exceed threshold the session is torn down by
    /// the caller anyway.
    private var failures: [Date] = []

    // MARK: - API

    /// Record one failure. Returns `true` if the threshold has now been
    /// crossed (and the caller MUST tear down the session); returns
    /// `false` otherwise.
    func recordFailure() -> Bool {
        let now = Date()
        let cutoff = now.addingTimeInterval(-windowSeconds)
        lock.lock()
        defer { lock.unlock() }

        // Drop anything outside the window.
        failures.removeAll { $0 < cutoff }
        failures.append(now)
        if failures.count > threshold * 2 {
            // Hard cap to bound memory; the caller has already learned
            // we're over threshold so the array won't be queried again.
            failures = Array(failures.suffix(threshold * 2))
        }
        return failures.count >= threshold
    }

    /// Current count of recorded failures within the window. Test/debug.
    var currentCount: Int {
        let cutoff = Date().addingTimeInterval(-windowSeconds)
        lock.lock()
        defer { lock.unlock() }
        failures.removeAll { $0 < cutoff }
        return failures.count
    }

    /// Reset the counter (e.g. after session re-registration).
    func reset() {
        lock.lock()
        failures.removeAll()
        lock.unlock()
    }
}
