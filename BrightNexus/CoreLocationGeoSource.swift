// CoreLocationGeoSource.swift
// BrightNexus
//
// CoreLocation-backed `GeoSourceProtocol` implementation (Wave 4i).
//
// macOS CoreLocation differs from iOS in three ways that matter here:
//
//   1. There's no foreground/background distinction; we use
//      `requestWhenInUseAuthorization()` and `startUpdatingLocation()`.
//      The user grants in System Settings → Privacy & Security → Location
//      Services on first request.
//
//   2. Authorization can be `.notDetermined` for a long time. We DO NOT
//      block on it — the engine must remain responsive even if the user
//      never grants. `currentFix()` returns nil and `status()` reflects
//      `alive: false` until a fix lands.
//
//   3. macOS apps must declare `NSLocationUsageDescription` (legacy) and
//      `NSLocationWhenInUseUsageDescription` (modern) in Info.plist or
//      authorization will silently fail.
//
// The bridge keeps a single shared CLLocationManager. CoreLocation
// callbacks land on the main actor (we set the manager's delegate
// queue to nil so it uses the main run loop, the platform default).
// Subscriber notifications happen on the main actor as well, so we
// never need locking.

import Foundation
import CoreLocation

@MainActor
final class CoreLocationGeoSource: NSObject, GeoSourceProtocol, CLLocationManagerDelegate {

    private let manager = CLLocationManager()
    private var latestFix: GeoFix?
    private var subscribers: [UUID: (GeoFix) -> Void] = [:]
    private var pendingRefreshes: [(GeoFix?) -> Void] = []
    private var startedUpdates = false

    override init() {
        super.init()
        manager.delegate = self
        // 10 m desired accuracy is plenty for zone-scale checks; tightening
        // to kCLLocationAccuracyBest burns battery without changing zone
        // outcomes for typical office-building zones (radius ≥ 50 m).
        manager.desiredAccuracy = kCLLocationAccuracyHundredMeters
        // No background updates — this is a menu-bar app.
    }

    // MARK: - GeoSourceProtocol

    func currentFix() -> GeoFix? {
        // Tickle: if we're authorized but haven't kicked CoreLocation
        // yet (e.g. caller hit LINK_GEO_GET without doing a refresh
        // first), start updates lazily so we're warming up while we
        // return the current (possibly nil) value. The caller will get
        // nil this time but a subsequent call will see the fix.
        if isAuthorized(currentAuthorization()) {
            startUpdatesIfNeeded()
        }
        return latestFix
    }

    func requestRefresh(timeoutMs: Int) async throws -> GeoFix {
        ensureAuthorizationRequested()
        // Fast-fail when not authorised: blocking the caller for the full
        // timeout while macOS may or may not show its own permission
        // dialog produces a bad UX. Tell the caller we can't help right
        // now; they (or the user, via Settings) can retry once auth
        // changes. The didChangeAuthorization callback will start
        // updates as soon as the user grants.
        let auth = currentAuthorization()
        guard isAuthorized(auth) else {
            throw GeoSourceError.engineUnavailable(
                reason: "CoreLocation authorization \(authString(auth))"
            )
        }
        startUpdatesIfNeeded()

        // Race a single-fix wait against the timeout.
        return try await withThrowingTaskGroup(of: GeoFix.self) { group in
            group.addTask { @MainActor in
                try await self.awaitNextFix()
            }
            group.addTask {
                let nanos = UInt64(max(0, timeoutMs)) * 1_000_000
                try? await Task.sleep(nanoseconds: nanos)
                throw GeoSourceError.timeout
            }
            do {
                let fix = try await group.next()!
                group.cancelAll()
                return fix
            } catch {
                group.cancelAll()
                throw error
            }
        }
    }

    func subscribe(handler: @escaping (GeoFix) -> Void) -> () -> Void {
        ensureAuthorizationRequested()
        startUpdatesIfNeeded()
        let id = UUID()
        subscribers[id] = handler
        return { [weak self] in
            self?.subscribers.removeValue(forKey: id)
        }
    }

    func status() -> GeoSourceStatus {
        let auth = currentAuthorization()
        let kind = "CoreLocationGeoSource (\(authString(auth)))"
        // Tickle: same lazy-startup as currentFix() so callers who
        // probe status before triggering anything else still wake the
        // engine. status() never blocks; if there's no fix yet we
        // simply report alive=false and the next call will see the
        // engine running.
        if isAuthorized(auth) {
            startUpdatesIfNeeded()
        }
        guard let fix = latestFix else {
            return GeoSourceStatus(
                kind: kind,
                alive: false,
                fix_age_seconds: nil,
                accuracy_m: nil
            )
        }
        let age = (currentBrightDate() - fix.brightdate) * 86_400.0
        return GeoSourceStatus(
            kind: kind,
            alive: true,
            fix_age_seconds: max(0, age),
            accuracy_m: fix.accuracy_m
        )
    }

    // MARK: - CLLocationManagerDelegate

    nonisolated func locationManager(_ manager: CLLocationManager,
                                     didUpdateLocations locations: [CLLocation]) {
        Task { @MainActor in
            guard let cl = locations.last else { return }
            let fix = self.fixFromCLLocation(cl)
            self.latestFix = fix
            // Resolve any pending refresh waiters.
            let pending = self.pendingRefreshes
            self.pendingRefreshes.removeAll()
            for cb in pending { cb(fix) }
            // Notify subscribers.
            for handler in self.subscribers.values {
                handler(fix)
            }
        }
    }

    nonisolated func locationManager(_ manager: CLLocationManager,
                                     didFailWithError error: Error) {
        // CoreLocation often reports kCLErrorLocationUnknown transiently;
        // we don't unwind on the first failure. Pending refresh requests
        // wait for either a fix or the configured timeout.
        NSLog("[BrightNexus] CoreLocation error (transient): %@",
              error.localizedDescription)
    }

    nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        Task { @MainActor in
            let auth = self.currentAuthorization()
            NSLog("[BrightNexus] CoreLocation authorization changed: %@",
                  self.authString(auth))
            if self.isAuthorized(auth) {
                self.startUpdatesIfNeeded()
            }
        }
    }

    // MARK: - Internals

    private func ensureAuthorizationRequested() {
        let auth = currentAuthorization()
        if auth == .notDetermined {
            manager.requestWhenInUseAuthorization()
        }
    }

    private func startUpdatesIfNeeded() {
        guard isAuthorized(currentAuthorization()) else { return }
        guard !startedUpdates else { return }
        startedUpdates = true
        manager.startUpdatingLocation()
    }

    private func awaitNextFix() async throws -> GeoFix {
        // If we already have a recent fix, return it immediately.
        if let fix = latestFix { return fix }
        return try await withCheckedThrowingContinuation { continuation in
            self.pendingRefreshes.append { fix in
                if let fix = fix {
                    continuation.resume(returning: fix)
                } else {
                    continuation.resume(throwing: GeoSourceError.timeout)
                }
            }
        }
    }

    private func fixFromCLLocation(_ cl: CLLocation) -> GeoFix {
        return GeoFix(
            brightdate: currentBrightDate(),
            wgs84: Wgs84LatLon(
                lat: cl.coordinate.latitude,
                lon: cl.coordinate.longitude,
                alt_m: cl.verticalAccuracy >= 0 ? cl.altitude : nil
            ),
            accuracy_m: max(cl.horizontalAccuracy, 0)
        )
    }

    // MARK: - Authorization helpers

    private func currentAuthorization() -> CLAuthorizationStatus {
        return manager.authorizationStatus
    }

    private func isAuthorized(_ status: CLAuthorizationStatus) -> Bool {
        switch status {
        case .authorizedAlways, .authorizedWhenInUse:
            return true
        default:
            return false
        }
    }

    private func authString(_ status: CLAuthorizationStatus) -> String {
        switch status {
        case .notDetermined:    return "notDetermined"
        case .restricted:       return "restricted"
        case .denied:           return "denied"
        case .authorizedAlways: return "authorizedAlways"
        case .authorizedWhenInUse: return "authorizedWhenInUse"
        @unknown default:       return "unknown"
        }
    }
}
