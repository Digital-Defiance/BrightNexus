// BrightSpaceCoordinates.swift
// BrightNexus
//
// WGS84 ↔ ECEF ↔ BrightSpace coordinate conversions.
//
// Ported byte-for-byte from test-harness/src/spec/brightlink.ts so the
// Swift side and the TypeScript side produce identical numeric output
// for the same input (within IEEE-754 double-precision rounding). RFC §6.3.
//
// Three coordinate spaces:
//
//   WGS84     — geographic lat/lon/alt; the natural form CoreLocation
//               and most APIs use.
//   ECEF      — Earth-centred Earth-fixed Cartesian metres (ITRF2020 in
//               principle; we don't apply the ITRF↔WGS84 microscopic
//               correction, which is below 1 cm and irrelevant at zone
//               scale).
//   BrightSpace — same Cartesian frame, expressed in BrightMeters where
//               1 BrightMeter ≡ 1/299_792_458 second × c (i.e. just
//               metres divided by the speed of light). The BrightSpace
//               unit is the natural unit for time-of-flight reasoning.
//
// Numerical fidelity: the wgs84↔ecef pair is accurate to better than
// 0.1 mm at the surface (Bowring 1976 closed-form for ecef→wgs84;
// exact closed-form for wgs84→ecef). BrightSpace conversion is a single
// scalar division, exact within FP rounding.

import Foundation

// MARK: - Constants (RFC §6.3)

/// Speed of light in vacuum, m/s. SI definition. Also the conversion
/// factor between ECEF metres and BrightSpace BrightMeters per the
/// BrightSpace standard.
let SPEED_OF_LIGHT_MPS: Double = 299_792_458

/// WGS84 ellipsoid semi-major axis in metres. Exact by definition.
let WGS84_A: Double = 6_378_137.0

/// WGS84 ellipsoid flattening.
let WGS84_F: Double = 1.0 / 298.257_223_563

/// First eccentricity squared, derived: e² = 2f − f².
let WGS84_E2: Double = 2.0 * WGS84_F - WGS84_F * WGS84_F

/// Semi-minor axis derived from a and f.
let WGS84_B: Double = WGS84_A * (1.0 - WGS84_F)

private let DEG2RAD: Double = .pi / 180.0
private let RAD2DEG: Double = 180.0 / .pi

// MARK: - Coordinate types

/// Earth-centred Earth-fixed Cartesian metres.
struct EcefPoint: Equatable {
    var x_m: Double
    var y_m: Double
    var z_m: Double
}

/// BrightSpace BrightMeter coordinates plus their epoch.
struct BrightSpacePoint: Equatable {
    var x_bm: Double
    var y_bm: Double
    var z_bm: Double
    var epoch_bd: Double
}

// MARK: - Conversions

/// WGS84 lat/lon/alt → ECEF metres. Exact closed-form.
func wgs84ToEcef(_ p: Wgs84LatLon) -> EcefPoint {
    let phi = p.lat * DEG2RAD
    let lam = p.lon * DEG2RAD
    let h = p.alt_m ?? 0.0

    let sinPhi = sin(phi)
    let cosPhi = cos(phi)
    let sinLam = sin(lam)
    let cosLam = cos(lam)

    // Radius of curvature in the prime vertical.
    let N = WGS84_A / sqrt(1.0 - WGS84_E2 * sinPhi * sinPhi)

    return EcefPoint(
        x_m: (N + h) * cosPhi * cosLam,
        y_m: (N + h) * cosPhi * sinLam,
        z_m: (N * (1.0 - WGS84_E2) + h) * sinPhi
    )
}

/// ECEF metres → WGS84 lat/lon/alt. Bowring 1976 closed-form.
/// Accurate to better than 0.1 mm at the surface; degrades only at the
/// geocentre (0,0,0) where the answer is undefined anyway.
func ecefToWgs84(_ p: EcefPoint) -> Wgs84LatLon {
    let x = p.x_m
    let y = p.y_m
    let z = p.z_m
    let a = WGS84_A
    let b = WGS84_B
    let e2 = WGS84_E2

    // Second eccentricity squared.
    let ep2 = (a * a - b * b) / (b * b)

    let r = sqrt(x * x + y * y)
    // Bowring's auxiliary angle.
    let theta = atan2(z * a, r * b)
    let sinTheta = sin(theta)
    let cosTheta = cos(theta)

    let phi = atan2(
        z + ep2 * b * sinTheta * sinTheta * sinTheta,
        r - e2 * a * cosTheta * cosTheta * cosTheta
    )
    let lam = atan2(y, x)

    let sinPhi = sin(phi)
    let N = a / sqrt(1.0 - e2 * sinPhi * sinPhi)
    let alt = (r / cos(phi)) - N

    return Wgs84LatLon(
        lat: phi * RAD2DEG,
        lon: lam * RAD2DEG,
        alt_m: alt
    )
}

/// ECEF metres → BrightSpace BrightMeters (divide by c). Exact.
func ecefToBrightSpace(_ p: EcefPoint, epochBd: Double) -> BrightSpacePoint {
    return BrightSpacePoint(
        x_bm: p.x_m / SPEED_OF_LIGHT_MPS,
        y_bm: p.y_m / SPEED_OF_LIGHT_MPS,
        z_bm: p.z_m / SPEED_OF_LIGHT_MPS,
        epoch_bd: epochBd
    )
}

/// BrightSpace BrightMeters → ECEF metres (multiply by c). Exact.
func brightSpaceToEcef(_ p: BrightSpacePoint) -> EcefPoint {
    return EcefPoint(
        x_m: p.x_bm * SPEED_OF_LIGHT_MPS,
        y_m: p.y_bm * SPEED_OF_LIGHT_MPS,
        z_m: p.z_bm * SPEED_OF_LIGHT_MPS
    )
}

/// Euclidean distance between two ECEF points in metres. The chord
/// distance, not the great-circle arc; at terrestrial scales the
/// chord-to-surface-distance error is below 1 cm for radii under 200 m,
/// well within zone tolerance.
func ecefChordDistance(_ a: EcefPoint, _ b: EcefPoint) -> Double {
    let dx = a.x_m - b.x_m
    let dy = a.y_m - b.y_m
    let dz = a.z_m - b.z_m
    return sqrt(dx * dx + dy * dy + dz * dz)
}
