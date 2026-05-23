// LinkCoordinateExchange.swift
// BrightNexus
//
// Tiny in-memory clipboard for moving WGS84 coordinates between the
// Coordinate Converter tab and the Zone Editor.
//
// Two operations:
//   - publish(_ point):   converter pushes its current WGS84 here
//   - peek():             zone editor reads the most recent published point
//
// The exchange is process-local, lives only as long as Nexus is running,
// and never touches disk. It exists purely to spare the user from copying
// lat/lon pairs by hand when bouncing between the two tabs.

import Foundation
import Combine

@MainActor
final class CoordinateExchange: ObservableObject {

    static let shared = CoordinateExchange()

    /// Most recently published WGS84 point, or nil if nothing has been
    /// published in this session yet.
    @Published private(set) var latest: Wgs84LatLon?

    /// Monotonically increasing publish counter — useful for SwiftUI views
    /// that want to react to "a new value arrived" even if the value is
    /// equal to the previous one. SwiftUI re-fires onChange only when the
    /// value differs, so we bump this on every publish.
    @Published private(set) var generation: Int = 0

    private init() {}

    func publish(_ point: Wgs84LatLon) {
        latest = point
        generation &+= 1
    }

    func peek() -> Wgs84LatLon? { latest }

    /// Convenience: build a `Wgs84LatLon` from raw doubles and publish.
    func publish(lat: Double, lon: Double, alt_m: Double? = nil) {
        publish(Wgs84LatLon(lat: lat, lon: lon, alt_m: alt_m))
    }
}
