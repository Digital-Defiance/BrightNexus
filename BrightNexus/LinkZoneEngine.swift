// LinkZoneEngine.swift
// BrightNexus
//
// Zone shape algebra (RFC §8). Ported from
// test-harness/src/mock-brightnexus/zoneEngine.ts.
//
// Four normative shape types:
//   circle_2d    — local-tangent-plane chord distance < radius_m
//   cylinder_3d  — circle_2d + altitude in [min, max]
//   polygon_2d   — ray-casting on lat/lon
//   bbox_2d      — axis-aligned rectangle on lat/lon
//
// Default priorities (higher wins; ties broken by id lex order):
//   cylinder_3d = 200, circle_2d = 100, polygon_2d = 50, bbox_2d = 10
//
// TODO Wave 4i: replace haversine-equivalent local-tangent-plane math
// with proper ECEF chord distance once the wgs84↔ecef helpers are
// ported from spec/index.ts.
// TODO Wave 4i: sign geo-zones.json with BridgeIdentity (currently
// unsigned — it's user state, not security-critical).

import Foundation

// MARK: - Geo primitives

/// A WGS84 lat/lon (decimal degrees) plus optional altitude in metres.
struct Wgs84LatLon: Codable, Equatable {
    var lat: Double
    var lon: Double
    var alt_m: Double?
}

/// A single geographic fix from the platform's geo source. RFC §6.3.
/// Currently used as input to point-in-zone tests; the full ECEF/velocity
/// machinery lands in Wave 4i.
struct GeoFix {
    var brightdate: Double
    var wgs84: Wgs84LatLon
    var accuracy_m: Double
}

/// Status returned by a `GeoSourceProtocol`.
struct GeoSourceStatus {
    var kind: String
    var alive: Bool
    var fix_age_seconds: Double?
    var accuracy_m: Double?
}

// MARK: - Shape definitions

/// The four supported zone shapes. RFC §8.
enum ZoneShape: Equatable {
    case circle2d(center: Wgs84LatLon, radiusM: Double)
    case cylinder3d(center: Wgs84LatLon, radiusM: Double, altitudeMinM: Double, altitudeMaxM: Double)
    case polygon2d(pointsWgs84: [Wgs84LatLon])
    case bbox2d(latMin: Double, latMax: Double, lonMin: Double, lonMax: Double)

    var typeString: String {
        switch self {
        case .circle2d:    return "circle_2d"
        case .cylinder3d:  return "cylinder_3d"
        case .polygon2d:   return "polygon_2d"
        case .bbox2d:      return "bbox_2d"
        }
    }

    var defaultPriority: Int {
        switch self {
        case .cylinder3d: return 200
        case .circle2d:   return 100
        case .polygon2d:  return 50
        case .bbox2d:     return 10
        }
    }
}

/// One zone definition. Stored in `~/.brightchain/brightnexus/geo-zones.json`.
struct ZoneDefinition: Equatable {
    var id: String
    var displayName: String
    var shape: ZoneShape
    var priority: Int?
}

/// Resolved priority — explicit `priority` if set, else the shape default.
func zonePriority(_ z: ZoneDefinition) -> Int {
    return z.priority ?? z.shape.defaultPriority
}

// MARK: - Point-in-zone

/// Test whether a fix is inside a single zone shape.
///
/// TODO Wave 4i: replace with ECEF chord distance once helpers ported.
/// For now we use small-angle local-tangent-plane math:
///   dx = R_earth · cos(lat) · Δlon  (lon in radians)
///   dy = R_earth · Δlat              (lat in radians)
///   dist_m = √(dx² + dy²)
/// with R_earth = 6_378_137.0 (WGS84 equatorial radius). The chord-vs-arc
/// error is below 1 cm for radii < 200 m, well within the 1-σ accuracy
/// reported by CoreLocation.
func pointInZone(fix: GeoFix, zone: ZoneDefinition) -> Bool {
    switch zone.shape {
    case .circle2d(let center, let radiusM):
        return horizontalDistanceMetres(center, fix.wgs84) <= radiusM

    case .cylinder3d(let center, let radiusM, let aMin, let aMax):
        let horizontalOk = horizontalDistanceMetres(center, fix.wgs84) <= radiusM
        let fixAlt = fix.wgs84.alt_m ?? 0
        let verticalOk = fixAlt >= aMin && fixAlt <= aMax
        return horizontalOk && verticalOk

    case .polygon2d(let pts):
        return pointInPolygon(point: fix.wgs84, polygon: pts)

    case .bbox2d(let latMin, let latMax, let lonMin, let lonMax):
        return fix.wgs84.lat >= latMin && fix.wgs84.lat <= latMax
            && fix.wgs84.lon >= lonMin && fix.wgs84.lon <= lonMax
    }
}

private let R_EARTH_M: Double = 6_378_137.0

private func horizontalDistanceMetres(_ a: Wgs84LatLon, _ b: Wgs84LatLon) -> Double {
    let dLat = (b.lat - a.lat) * .pi / 180.0
    let dLon = (b.lon - a.lon) * .pi / 180.0
    let avgLat = ((a.lat + b.lat) / 2.0) * .pi / 180.0
    let dx = R_EARTH_M * cos(avgLat) * dLon
    let dy = R_EARTH_M * dLat
    return (dx * dx + dy * dy).squareRoot()
}

/// Standard ray-casting point-in-polygon. Returns true if the point lies
/// inside the polygon. Polygon assumed simple (non-self-intersecting).
private func pointInPolygon(point: Wgs84LatLon, polygon: [Wgs84LatLon]) -> Bool {
    if polygon.count < 3 { return false }
    let x = point.lon
    let y = point.lat
    var inside = false
    var j = polygon.count - 1
    for i in 0..<polygon.count {
        let xi = polygon[i].lon
        let yi = polygon[i].lat
        let xj = polygon[j].lon
        let yj = polygon[j].lat
        let intersect = ((yi > y) != (yj > y))
            && (x < (xj - xi) * (y - yi) / (yj - yi) + xi)
        if intersect { inside.toggle() }
        j = i
    }
    return inside
}

// MARK: - LinkZoneEngine

/// Holds the user's zone definitions and answers "what zone am I in?".
final class LinkZoneEngine {
    /// Posted on the main queue after every mutation. The Zones Settings
    /// tab subscribes to this for live refresh, same convention as
    /// LinkAcl.didChangeNotification.
    static let didChangeNotification = Notification.Name("LinkZoneEngine.didChange")

    private var zones: [ZoneDefinition] = []

    init(zones: [ZoneDefinition] = []) {
        self.zones = zones
    }

    func setZones(_ zones: [ZoneDefinition]) {
        self.zones = zones
        Self.publishChange()
    }

    func list() -> [ZoneDefinition] { zones }

    func byId(_ id: String) -> ZoneDefinition? {
        return zones.first(where: { $0.id == id })
    }

    /// Add a new zone or replace an existing one (matched by id).
    /// Re-saves; publishes change.
    func upsert(_ zone: ZoneDefinition) {
        if let idx = zones.firstIndex(where: { $0.id == zone.id }) {
            zones[idx] = zone
        } else {
            zones.append(zone)
        }
        Self.publishChange()
    }

    /// Remove a zone by id. No-op if not found. Re-saves; publishes change.
    func remove(id: String) {
        let before = zones.count
        zones.removeAll(where: { $0.id == id })
        if zones.count != before {
            Self.publishChange()
        }
    }

    /// Highest-priority matching zone wins; ties broken by id lex order.
    func currentZone(fix: GeoFix) -> ZoneDefinition? {
        var best: ZoneDefinition? = nil
        var bestPriority = Int.min
        for zone in zones {
            if !pointInZone(fix: fix, zone: zone) { continue }
            let p = zonePriority(zone)
            if p > bestPriority {
                best = zone
                bestPriority = p
            } else if p == bestPriority, let b = best, zone.id < b.id {
                best = zone
            }
        }
        return best
    }

    // MARK: - Persistence (JSON, currently unsigned)

    /// Atomically write `geo-zones.json` (mode 0600). The on-disk format
    /// is the same JSON shape `loadFromDisk` understands.
    /// TODO Wave 4i+: sign with BridgeIdentity.
    func saveToDisk() throws {
        let url = BrightNexusPaths.geoZones
        let arr: [[String: Any]] = zones.map { encodeZoneDefinition($0) }
        let data = try JSONSerialization.data(
            withJSONObject: arr,
            options: [.prettyPrinted, .sortedKeys]
        )
        let tmpURL = url.appendingPathExtension("tmp")
        try data.write(to: tmpURL, options: [.atomic])
        _ = chmod(tmpURL.path, 0o600)
        try FileManager.default.replaceItemAt(url, withItemAt: tmpURL)
    }

    /// Load zones from `~/.brightchain/brightnexus/geo-zones.json`. If the
    /// file is missing or unreadable, returns an empty engine.
    static func loadFromDisk() -> LinkZoneEngine {
        let url = BrightNexusPaths.geoZones
        let fm = FileManager.default
        guard fm.fileExists(atPath: url.path),
              let data = try? Data(contentsOf: url),
              let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            return LinkZoneEngine()
        }
        var zones: [ZoneDefinition] = []
        for d in arr {
            guard let z = decodeZoneDefinition(d) else { continue }
            zones.append(z)
        }
        return LinkZoneEngine(zones: zones)
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
}

// MARK: - JSON decode

private func decodeZoneDefinition(_ d: [String: Any]) -> ZoneDefinition? {
    guard let id = d["id"] as? String,
          let displayName = d["displayName"] as? String,
          let shapeDict = d["shape"] as? [String: Any],
          let shape = decodeShape(shapeDict) else {
        return nil
    }
    let priority = d["priority"] as? Int
    return ZoneDefinition(id: id, displayName: displayName, shape: shape, priority: priority)
}

private func decodeShape(_ d: [String: Any]) -> ZoneShape? {
    guard let type = d["type"] as? String else { return nil }
    switch type {
    case "circle_2d":
        guard let center = decodeLatLon(d["center"]),
              let radius = d["radius_m"] as? Double else { return nil }
        return .circle2d(center: center, radiusM: radius)
    case "cylinder_3d":
        guard let center = decodeLatLon(d["center"]),
              let radius = d["radius_m"] as? Double,
              let aMin = d["altitude_min_m"] as? Double,
              let aMax = d["altitude_max_m"] as? Double else { return nil }
        return .cylinder3d(center: center, radiusM: radius, altitudeMinM: aMin, altitudeMaxM: aMax)
    case "polygon_2d":
        guard let pts = d["points_wgs84"] as? [[String: Any]] else { return nil }
        var out: [Wgs84LatLon] = []
        for p in pts {
            guard let lat = p["lat"] as? Double, let lon = p["lon"] as? Double else { return nil }
            out.append(Wgs84LatLon(lat: lat, lon: lon, alt_m: nil))
        }
        return .polygon2d(pointsWgs84: out)
    case "bbox_2d":
        guard let latMin = d["lat_min"] as? Double,
              let latMax = d["lat_max"] as? Double,
              let lonMin = d["lon_min"] as? Double,
              let lonMax = d["lon_max"] as? Double else { return nil }
        return .bbox2d(latMin: latMin, latMax: latMax, lonMin: lonMin, lonMax: lonMax)
    default:
        return nil
    }
}

private func decodeLatLon(_ raw: Any?) -> Wgs84LatLon? {
    // Accept either { "wgs84": {lat, lon} } or { lat, lon }.
    if let outer = raw as? [String: Any] {
        if let inner = outer["wgs84"] as? [String: Any] {
            return latLonFromDict(inner)
        }
        return latLonFromDict(outer)
    }
    return nil
}

private func latLonFromDict(_ d: [String: Any]) -> Wgs84LatLon? {
    guard let lat = d["lat"] as? Double, let lon = d["lon"] as? Double else { return nil }
    let alt = d["alt_m"] as? Double
    return Wgs84LatLon(lat: lat, lon: lon, alt_m: alt)
}

// MARK: - JSON encode (mirror of decode at the top of this file)

private func encodeZoneDefinition(_ z: ZoneDefinition) -> [String: Any] {
    var out: [String: Any] = [
        "id":          z.id,
        "displayName": z.displayName,
        "shape":       encodeShape(z.shape),
    ]
    if let p = z.priority { out["priority"] = p }
    return out
}

private func encodeShape(_ s: ZoneShape) -> [String: Any] {
    switch s {
    case .circle2d(let center, let radiusM):
        return [
            "type":     "circle_2d",
            "center":   ["wgs84": encodeLatLon(center)],
            "radius_m": radiusM,
        ]
    case .cylinder3d(let center, let radiusM, let aMin, let aMax):
        return [
            "type":            "cylinder_3d",
            "center":          ["wgs84": encodeLatLon(center)],
            "radius_m":        radiusM,
            "altitude_min_m":  aMin,
            "altitude_max_m":  aMax,
        ]
    case .polygon2d(let points):
        return [
            "type":          "polygon_2d",
            "points_wgs84":  points.map { encodeLatLon($0) },
        ]
    case .bbox2d(let latMin, let latMax, let lonMin, let lonMax):
        return [
            "type":     "bbox_2d",
            "lat_min":  latMin,
            "lat_max":  latMax,
            "lon_min":  lonMin,
            "lon_max":  lonMax,
        ]
    }
}

private func encodeLatLon(_ p: Wgs84LatLon) -> [String: Any] {
    var d: [String: Any] = ["lat": p.lat, "lon": p.lon]
    if let alt = p.alt_m { d["alt_m"] = alt }
    return d
}
