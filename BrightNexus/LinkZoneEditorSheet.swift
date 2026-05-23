// LinkZoneEditorSheet.swift
// BrightNexus
//
// Modal sheet for creating or editing a zone definition. Bound to the
// four ZoneShape variants from RFC §8: circle_2d, cylinder_3d,
// polygon_2d, bbox_2d.
//
// UX choices:
//   - Display name + id (id is auto-generated for new zones; read-only
//     for existing ones since changing it would orphan persisted entries)
//   - Shape picker scoped at the top
//   - Per-shape sub-forms with sensible defaults
//   - "Use Current Location" pre-fills lat/lon for circle/cylinder centers
//     by reading the engine's most recent fix (no extra prompt, since the
//     user is already in the bridge GUI)
//   - Save validates the form; bad input is highlighted inline rather
//     than via an alert.
//
// Polygon editor: a small table of (lat, lon) rows with +/− to add or
// remove. Minimum 3 points enforced at save time.

import SwiftUI

@MainActor
struct ZoneEditorSheet: View {

    let target: ZonesSettingsView.ZoneEditorTarget
    let onSave: (ZoneDefinition) -> Void
    let onCancel: () -> Void

    @State private var displayName: String = ""
    @State private var idString: String = ""
    @State private var shapeKind: ShapeKind = .circle2d
    @State private var priorityText: String = ""

    // Shape-specific state
    @State private var centerLatText: String = ""
    @State private var centerLonText: String = ""
    @State private var radiusMText: String = "100"
    @State private var altMinMText: String = "-50"
    @State private var altMaxMText: String = "200"

    @State private var polygonPoints: [PolygonPointDraft] = [
        PolygonPointDraft(),
        PolygonPointDraft(),
        PolygonPointDraft(),
    ]

    @State private var bboxLatMinText: String = ""
    @State private var bboxLatMaxText: String = ""
    @State private var bboxLonMinText: String = ""
    @State private var bboxLonMaxText: String = ""

    @State private var validationError: String? = nil

    @ObservedObject private var exchange = CoordinateExchange.shared

    enum ShapeKind: String, CaseIterable, Identifiable {
        case circle2d   = "circle_2d"
        case cylinder3d = "cylinder_3d"
        case polygon2d  = "polygon_2d"
        case bbox2d     = "bbox_2d"

        var id: String { rawValue }

        var label: String {
            switch self {
            case .circle2d:   return "Circle (2D)"
            case .cylinder3d: return "Cylinder (3D)"
            case .polygon2d:  return "Polygon (2D)"
            case .bbox2d:     return "Bounding Box (2D)"
            }
        }
    }

    struct PolygonPointDraft: Identifiable {
        let id = UUID()
        var lat: String = ""
        var lon: String = ""
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Identity") {
                    TextField("Display name", text: $displayName)
                    TextField("Id", text: $idString)
                        .disabled(target.isExisting)
                        .foregroundColor(target.isExisting ? .secondary : .primary)
                }

                Section("Shape") {
                    Picker("Shape", selection: $shapeKind) {
                        ForEach(ShapeKind.allCases) { kind in
                            Text(kind.label).tag(kind)
                        }
                    }

                    switch shapeKind {
                    case .circle2d:
                        circleForm
                    case .cylinder3d:
                        cylinderForm
                    case .polygon2d:
                        polygonForm
                    case .bbox2d:
                        bboxForm
                    }
                }

                Section {
                    TextField("Priority (optional, default by shape)", text: $priorityText)
                } header: {
                    Text("Priority")
                } footer: {
                    Text("Higher wins when zones overlap. Defaults: cylinder_3d=200, circle_2d=100, polygon_2d=50, bbox_2d=10.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                if let err = validationError {
                    Text(err)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
            .formStyle(.grouped)
            .navigationTitle(target.isExisting ? "Edit Zone" : "New Zone")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { onCancel() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { attemptSave() }
                }
            }
            .onAppear { hydrateFromTarget() }
        }
        // The form has wide rows (centre lat/lon/radius all on one line,
        // plus the "Use Current Location" button). Need a generous minimum
        // width so labels and buttons don't truncate. Macros and SF Symbols
        // help compress, but the lat/lon TextField pair plus the button is
        // ~500pt minimum. Keep height tall enough for the polygon form
        // which can grow to ~6 rows.
        //
        // Use min/ideal frame rather than a fixed (width:height:) frame
        // so the host NSWindow's `.resizable` styleMask actually takes
        // effect — a fixed `.frame(width:, height:)` clamps the window
        // to that size and overrides the window-level resize flag.
        .frame(minWidth: 560, idealWidth: 720, minHeight: 520, idealHeight: 600)
    }

    // MARK: - Per-shape sub-forms

    private var circleForm: some View {
        Group {
            HStack {
                TextField("Centre lat", text: $centerLatText)
                TextField("Centre lon", text: $centerLonText)
            }
            HStack {
                Spacer()
                Button("Use Current Location") { fillCenterFromCurrentFix() }
                Button("From Converter") { fillCenterFromExchange() }
                    .disabled(exchange.latest == nil)
                Button("Send to Converter") { sendCenterToExchange() }
                    .disabled(!centerHasValues())
            }
            HStack {
                Text("Radius")
                TextField("metres", text: $radiusMText)
                Text("m")
            }
        }
    }

    private var cylinderForm: some View {
        Group {
            HStack {
                TextField("Centre lat", text: $centerLatText)
                TextField("Centre lon", text: $centerLonText)
            }
            HStack {
                Spacer()
                Button("Use Current Location") { fillCenterFromCurrentFix() }
                Button("From Converter") { fillCenterFromExchange() }
                    .disabled(exchange.latest == nil)
                Button("Send to Converter") { sendCenterToExchange() }
                    .disabled(!centerHasValues())
            }
            HStack {
                Text("Radius")
                TextField("metres", text: $radiusMText)
                Text("m")
            }
            HStack {
                Text("Altitude")
                TextField("min m", text: $altMinMText)
                Text("→")
                TextField("max m", text: $altMaxMText)
                Text("m")
            }
        }
    }

    private var polygonForm: some View {
        Group {
            ForEach($polygonPoints) { $pt in
                HStack {
                    TextField("lat", text: $pt.lat)
                    TextField("lon", text: $pt.lon)
                    Button {
                        if let stash = exchange.latest {
                            pt.lat = String(stash.lat)
                            pt.lon = String(stash.lon)
                        }
                    } label: {
                        Image(systemName: "tray.and.arrow.down")
                    }
                    .disabled(exchange.latest == nil)
                    .help("Load this point from the converter exchange.")
                    Button {
                        if let lat = Double(pt.lat),
                           let lon = Double(pt.lon) {
                            CoordinateExchange.shared.publish(lat: lat, lon: lon)
                        }
                    } label: {
                        Image(systemName: "tray.and.arrow.up")
                    }
                    .disabled(Double(pt.lat) == nil || Double(pt.lon) == nil)
                    .help("Send this point to the converter.")
                    Button(role: .destructive) {
                        if let idx = polygonPoints.firstIndex(where: { $0.id == pt.id }) {
                            if polygonPoints.count > 3 {
                                polygonPoints.remove(at: idx)
                            }
                        }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .disabled(polygonPoints.count <= 3)
                }
            }
            Button {
                polygonPoints.append(PolygonPointDraft())
            } label: {
                Label("Add Point", systemImage: "plus.circle")
            }
            if exchange.latest != nil {
                Button {
                    if let stash = exchange.latest {
                        polygonPoints.append(
                            PolygonPointDraft(lat: String(stash.lat), lon: String(stash.lon))
                        )
                    }
                } label: {
                    Label("Append Point from Converter", systemImage: "tray.and.arrow.down.fill")
                }
            }
            Text("Polygons need at least 3 points.")
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }

    private var bboxForm: some View {
        Group {
            HStack {
                Text("Latitude")
                TextField("min", text: $bboxLatMinText)
                Text("→")
                TextField("max", text: $bboxLatMaxText)
            }
            HStack {
                Text("Longitude")
                TextField("min", text: $bboxLonMinText)
                Text("→")
                TextField("max", text: $bboxLonMaxText)
            }
            HStack {
                Button("Use Current Location ± 0.001°") { fillBboxFromCurrentFix() }
                Button("From Converter ± 0.001°") { fillBboxFromExchange() }
                    .disabled(exchange.latest == nil)
                Spacer()
                Button("Send Centre to Converter") { sendBboxCentreToExchange() }
                    .disabled(!bboxHasValues())
            }
        }
    }

    // MARK: - Hydration / save

    private func hydrateFromTarget() {
        switch target {
        case .new:
            idString = generateZoneId()
            displayName = "New Zone"
            shapeKind = .circle2d
        case .existing(let z):
            idString = z.id
            displayName = z.displayName
            if let p = z.priority { priorityText = String(p) }
            switch z.shape {
            case .circle2d(let c, let r):
                shapeKind = .circle2d
                centerLatText = String(c.lat)
                centerLonText = String(c.lon)
                radiusMText = String(r)
            case .cylinder3d(let c, let r, let aMin, let aMax):
                shapeKind = .cylinder3d
                centerLatText = String(c.lat)
                centerLonText = String(c.lon)
                radiusMText = String(r)
                altMinMText = String(aMin)
                altMaxMText = String(aMax)
            case .polygon2d(let pts):
                shapeKind = .polygon2d
                polygonPoints = pts.map {
                    PolygonPointDraft(lat: String($0.lat), lon: String($0.lon))
                }
                if polygonPoints.count < 3 {
                    while polygonPoints.count < 3 {
                        polygonPoints.append(PolygonPointDraft())
                    }
                }
            case .bbox2d(let latMin, let latMax, let lonMin, let lonMax):
                shapeKind = .bbox2d
                bboxLatMinText = String(latMin)
                bboxLatMaxText = String(latMax)
                bboxLonMinText = String(lonMin)
                bboxLonMaxText = String(lonMax)
            }
        }
    }

    private func attemptSave() {
        validationError = nil
        do {
            let zone = try buildZoneFromForm()
            onSave(zone)
        } catch let error as ValidationError {
            validationError = error.message
        } catch {
            validationError = error.localizedDescription
        }
    }

    private func buildZoneFromForm() throws -> ZoneDefinition {
        guard !displayName.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw ValidationError("Display name is required.")
        }
        guard !idString.trimmingCharacters(in: .whitespaces).isEmpty else {
            throw ValidationError("Id is required.")
        }
        let priority: Int?
        let trimmedPriority = priorityText.trimmingCharacters(in: .whitespaces)
        if trimmedPriority.isEmpty {
            priority = nil
        } else if let p = Int(trimmedPriority) {
            priority = p
        } else {
            throw ValidationError("Priority must be an integer.")
        }

        let shape: ZoneShape
        switch shapeKind {
        case .circle2d:
            let c = try parseLatLon(latText: centerLatText, lonText: centerLonText, role: "centre")
            let r = try parsePositiveDouble(radiusMText, role: "radius")
            shape = .circle2d(center: c, radiusM: r)
        case .cylinder3d:
            let c = try parseLatLon(latText: centerLatText, lonText: centerLonText, role: "centre")
            let r = try parsePositiveDouble(radiusMText, role: "radius")
            guard let aMin = Double(altMinMText.trimmingCharacters(in: .whitespaces)) else {
                throw ValidationError("Altitude min must be a number.")
            }
            guard let aMax = Double(altMaxMText.trimmingCharacters(in: .whitespaces)) else {
                throw ValidationError("Altitude max must be a number.")
            }
            if aMin >= aMax {
                throw ValidationError("Altitude min must be < altitude max.")
            }
            shape = .cylinder3d(center: c, radiusM: r, altitudeMinM: aMin, altitudeMaxM: aMax)
        case .polygon2d:
            var points: [Wgs84LatLon] = []
            for (i, pt) in polygonPoints.enumerated() {
                let p = try parseLatLon(latText: pt.lat, lonText: pt.lon, role: "point \(i + 1)")
                points.append(p)
            }
            if points.count < 3 {
                throw ValidationError("Polygon needs at least 3 points.")
            }
            shape = .polygon2d(pointsWgs84: points)
        case .bbox2d:
            guard let latMin = Double(bboxLatMinText.trimmingCharacters(in: .whitespaces)) else {
                throw ValidationError("Lat min must be a number.")
            }
            guard let latMax = Double(bboxLatMaxText.trimmingCharacters(in: .whitespaces)) else {
                throw ValidationError("Lat max must be a number.")
            }
            guard let lonMin = Double(bboxLonMinText.trimmingCharacters(in: .whitespaces)) else {
                throw ValidationError("Lon min must be a number.")
            }
            guard let lonMax = Double(bboxLonMaxText.trimmingCharacters(in: .whitespaces)) else {
                throw ValidationError("Lon max must be a number.")
            }
            if latMin >= latMax || lonMin >= lonMax {
                throw ValidationError("min must be less than max for both axes.")
            }
            shape = .bbox2d(latMin: latMin, latMax: latMax, lonMin: lonMin, lonMax: lonMax)
        }

        return ZoneDefinition(
            id: idString.trimmingCharacters(in: .whitespaces),
            displayName: displayName.trimmingCharacters(in: .whitespaces),
            shape: shape,
            priority: priority
        )
    }

    private func parseLatLon(latText: String, lonText: String, role: String) throws -> Wgs84LatLon {
        guard let lat = Double(latText.trimmingCharacters(in: .whitespaces)) else {
            throw ValidationError("\(role): lat must be a number.")
        }
        guard let lon = Double(lonText.trimmingCharacters(in: .whitespaces)) else {
            throw ValidationError("\(role): lon must be a number.")
        }
        if lat < -90 || lat > 90 {
            throw ValidationError("\(role): lat out of range [-90, 90].")
        }
        if lon < -180 || lon > 180 {
            throw ValidationError("\(role): lon out of range [-180, 180].")
        }
        return Wgs84LatLon(lat: lat, lon: lon, alt_m: nil)
    }

    private func parsePositiveDouble(_ s: String, role: String) throws -> Double {
        guard let v = Double(s.trimmingCharacters(in: .whitespaces)) else {
            throw ValidationError("\(role) must be a number.")
        }
        if v <= 0 {
            throw ValidationError("\(role) must be > 0.")
        }
        return v
    }

    private func fillCenterFromCurrentFix() {
        let engine = BridgeProtocolHandler.sharedGeoEngine
        guard let fix = engine.source.currentFix() else {
            validationError = "No fix available — open the Geo Engine tab and confirm the engine is alive."
            return
        }
        centerLatText = String(fix.wgs84.lat)
        centerLonText = String(fix.wgs84.lon)
    }

    private func fillBboxFromCurrentFix() {
        let engine = BridgeProtocolHandler.sharedGeoEngine
        guard let fix = engine.source.currentFix() else {
            validationError = "No fix available — open the Geo Engine tab and confirm the engine is alive."
            return
        }
        // ±0.001° ≈ ±111 m at the equator, smaller at higher latitudes.
        let pad = 0.001
        bboxLatMinText = String(fix.wgs84.lat - pad)
        bboxLatMaxText = String(fix.wgs84.lat + pad)
        bboxLonMinText = String(fix.wgs84.lon - pad)
        bboxLonMaxText = String(fix.wgs84.lon + pad)
    }

    // MARK: - Coordinate exchange

    private func centerHasValues() -> Bool {
        return Double(centerLatText) != nil && Double(centerLonText) != nil
    }

    private func bboxHasValues() -> Bool {
        return Double(bboxLatMinText) != nil && Double(bboxLatMaxText) != nil
            && Double(bboxLonMinText) != nil && Double(bboxLonMaxText) != nil
    }

    private func fillCenterFromExchange() {
        guard let stash = exchange.latest else { return }
        centerLatText = String(stash.lat)
        centerLonText = String(stash.lon)
        validationError = nil
    }

    private func sendCenterToExchange() {
        guard let lat = Double(centerLatText.trimmingCharacters(in: .whitespaces)),
              let lon = Double(centerLonText.trimmingCharacters(in: .whitespaces)) else {
            validationError = "Centre lat/lon must be numbers before sending to the converter."
            return
        }
        validationError = nil
        CoordinateExchange.shared.publish(lat: lat, lon: lon)
    }

    private func fillBboxFromExchange() {
        guard let stash = exchange.latest else { return }
        let pad = 0.001
        bboxLatMinText = String(stash.lat - pad)
        bboxLatMaxText = String(stash.lat + pad)
        bboxLonMinText = String(stash.lon - pad)
        bboxLonMaxText = String(stash.lon + pad)
        validationError = nil
    }

    private func sendBboxCentreToExchange() {
        guard let latMin = Double(bboxLatMinText),
              let latMax = Double(bboxLatMaxText),
              let lonMin = Double(bboxLonMinText),
              let lonMax = Double(bboxLonMaxText) else {
            validationError = "Bounding box values must be numbers before sending to the converter."
            return
        }
        validationError = nil
        let centreLat = (latMin + latMax) / 2.0
        let centreLon = (lonMin + lonMax) / 2.0
        CoordinateExchange.shared.publish(lat: centreLat, lon: centreLon)
    }
}

// MARK: - Helpers

private struct ValidationError: Error {
    let message: String
    init(_ m: String) { message = m }
}

private func generateZoneId() -> String {
    // Short, copy-pasteable, deterministic-ish id. Format:
    // "zone-<8hex>".
    var bytes = [UInt8](repeating: 0, count: 4)
    _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    return "zone-" + bytes.map { String(format: "%02x", $0) }.joined()
}

extension ZonesSettingsView.ZoneEditorTarget {
    var isExisting: Bool {
        if case .existing = self { return true }
        return false
    }
}
