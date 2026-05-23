// LinkCoordinatesSettingsView.swift
// BrightNexus
//
// Coordinates conversion utility: edit any one of WGS84 / ECEF /
// BrightSpace, see the other two update live.
//
// Math lives in BrightSpaceCoordinates.swift (verified against the
// published GODE/ITRF2020 anchor in the BrightSpace standard). This
// view is a thin SwiftUI shell around those helpers — it does not
// reach for a network or any platform service. "Use Current Location"
// pulls from the engine's CoreLocation source if a fix is available.
//
// Locked-edit semantics: the user picks an "active" tab (WGS84 / ECEF /
// BrightSpace). Editing fields in the active tab updates the other two
// tabs. Switching tab makes that tab the new edit source. This avoids
// round-trip rounding drift from re-converting a partial edit.

import SwiftUI

@MainActor
struct CoordinatesSettingsView: View {

    enum ActiveSpace: String, CaseIterable, Identifiable {
        case wgs84
        case ecef
        case brightspace
        var id: String { rawValue }
        var label: String {
            switch self {
            case .wgs84:       return "WGS84"
            case .ecef:        return "ECEF"
            case .brightspace: return "BrightSpace"
            }
        }
    }

    @State private var active: ActiveSpace = .wgs84

    // Source-of-truth for each space; only the `active` one's text fields
    // are editable. The others are computed and shown read-only-feeling.
    @State private var wgsLat: Double = 47.0
    @State private var wgsLon: Double = -122.0
    @State private var wgsAlt: Double = 0.0

    @State private var ecefX: Double = 0
    @State private var ecefY: Double = 0
    @State private var ecefZ: Double = 0

    @State private var bsX: Double = 0
    @State private var bsY: Double = 0
    @State private var bsZ: Double = 0

    // Backing strings for the editable fields (so the user can type
    // partial / negative / floating-point freely without round-trip
    // truncation). Only the `active` space's strings drive state.
    @State private var wgsLatText = ""
    @State private var wgsLonText = ""
    @State private var wgsAltText = ""
    @State private var ecefXText = ""
    @State private var ecefYText = ""
    @State private var ecefZText = ""
    @State private var bsXText = ""
    @State private var bsYText = ""
    @State private var bsZText = ""

    @State private var lastError: String? = nil
    @State private var copiedToast: String? = nil

    @ObservedObject private var exchange = CoordinateExchange.shared

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Coordinate Converter")
                    .font(.headline)
                Spacer()
                Button {
                    sendToZoneEditor()
                } label: {
                    Label("Send to Zone Editor", systemImage: "arrow.up.right.square")
                }
                .help("Publish the current WGS84 point so the Zone Editor can pick it up.")
                Button {
                    fillFromCurrentFix()
                } label: {
                    Label("Use Current Location", systemImage: "location.fill")
                }
            }
            .padding(.horizontal)
            .padding(.top, 12)
            .padding(.bottom, 8)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Picker("Active space", selection: $active) {
                        ForEach(ActiveSpace.allCases) { space in
                            Text(space.label).tag(space)
                        }
                    }
                    .pickerStyle(.segmented)
                    .padding(.horizontal)
                    .onChange(of: active) { _, _ in syncTextsFromState() }

                    if let stash = exchange.latest {
                        HStack(spacing: 8) {
                            Image(systemName: "tray.full")
                                .foregroundColor(.secondary)
                            Text(String(format: "On exchange: lat=%.6f, lon=%.6f%@",
                                        stash.lat, stash.lon,
                                        stash.alt_m.map { String(format: ", alt=%.1fm", $0) } ?? ""))
                                .font(.caption.monospaced())
                                .foregroundColor(.secondary)
                            Spacer()
                            Button("Load") {
                                wgsLat = stash.lat
                                wgsLon = stash.lon
                                wgsAlt = stash.alt_m ?? 0
                                active = .wgs84
                                syncTextsFromState()
                                recomputeFromWgs()
                            }
                            .buttonStyle(.borderless)
                        }
                        .padding(.horizontal)
                    }

                    wgs84Card
                    ecefCard
                    brightSpaceCard

                    if let err = lastError {
                        Text(err)
                            .font(.caption)
                            .foregroundColor(.red)
                            .padding(.horizontal)
                    }

                    referenceCard
                }
                .padding(.vertical, 12)
            }

            if let toast = copiedToast {
                Divider()
                HStack {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Text(toast).font(.caption)
                    Spacer()
                }
                .padding(.horizontal)
                .padding(.vertical, 6)
                .transition(.opacity)
            }
        }
        .onAppear { syncTextsFromState() }
    }

    // MARK: - Coordinate cards

    private var wgs84Card: some View {
        coordinateCard(
            title: "WGS84",
            subtitle: "Geographic lat/lon/alt; the natural form for CoreLocation and most APIs",
            isActive: active == .wgs84
        ) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    labelled("lat (°)", text: $wgsLatText, editable: active == .wgs84)
                    labelled("lon (°)", text: $wgsLonText, editable: active == .wgs84)
                }
                HStack {
                    labelled("alt (m)", text: $wgsAltText, editable: active == .wgs84)
                    Spacer()
                    copyButton(label: "Copy", what: "WGS84") {
                        return String(format: "lat=%.9f lon=%.9f alt_m=%.3f", wgsLat, wgsLon, wgsAlt)
                    }
                }
            }
            .onChange(of: wgsLatText) { _, _ in if active == .wgs84 { recomputeFromWgs() } }
            .onChange(of: wgsLonText) { _, _ in if active == .wgs84 { recomputeFromWgs() } }
            .onChange(of: wgsAltText) { _, _ in if active == .wgs84 { recomputeFromWgs() } }
        }
    }

    private var ecefCard: some View {
        coordinateCard(
            title: "ECEF (metres)",
            subtitle: "Earth-Centred Earth-Fixed Cartesian, ITRF2020 in principle",
            isActive: active == .ecef
        ) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    labelled("x_m", text: $ecefXText, editable: active == .ecef)
                    labelled("y_m", text: $ecefYText, editable: active == .ecef)
                    labelled("z_m", text: $ecefZText, editable: active == .ecef)
                }
                HStack {
                    Text(String(format: "‖r‖ = %.3f m  (≈ %.1f km from geocentre)",
                                ecefMagnitude(), ecefMagnitude() / 1000.0))
                        .font(.caption.monospaced())
                        .foregroundColor(.secondary)
                    Spacer()
                    copyButton(label: "Copy", what: "ECEF") {
                        return String(format: "x_m=%.6f y_m=%.6f z_m=%.6f", ecefX, ecefY, ecefZ)
                    }
                }
            }
            .onChange(of: ecefXText) { _, _ in if active == .ecef { recomputeFromEcef() } }
            .onChange(of: ecefYText) { _, _ in if active == .ecef { recomputeFromEcef() } }
            .onChange(of: ecefZText) { _, _ in if active == .ecef { recomputeFromEcef() } }
        }
    }

    private var brightSpaceCard: some View {
        coordinateCard(
            title: "BrightSpace (BrightMeters)",
            subtitle: "ECEF metres divided by c. Same vector, time-of-flight units",
            isActive: active == .brightspace
        ) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    labelled("x_bm", text: $bsXText, editable: active == .brightspace)
                    labelled("y_bm", text: $bsYText, editable: active == .brightspace)
                    labelled("z_bm", text: $bsZText, editable: active == .brightspace)
                }
                Text(brightSpacePrefixed())
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
                    .lineLimit(2)
                HStack {
                    Spacer()
                    copyButton(label: "Copy", what: "BrightSpace") {
                        return String(format: "x_bm=%.12f y_bm=%.12f z_bm=%.12f", bsX, bsY, bsZ)
                    }
                }
            }
            .onChange(of: bsXText) { _, _ in if active == .brightspace { recomputeFromBrightSpace() } }
            .onChange(of: bsYText) { _, _ in if active == .brightspace { recomputeFromBrightSpace() } }
            .onChange(of: bsZText) { _, _ in if active == .brightspace { recomputeFromBrightSpace() } }
        }
    }

    private var referenceCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Reference")
                .font(.headline)
            HStack(spacing: 16) {
                Text(String(format: "c = %d m/s (exact)", Int(SPEED_OF_LIGHT_MPS)))
                    .font(.caption.monospaced())
                Text(String(format: "WGS84_A = %.1f m", WGS84_A))
                    .font(.caption.monospaced())
                Text(String(format: "WGS84_F = 1 / %.9f", 1.0 / WGS84_F))
                    .font(.caption.monospaced())
            }
            .foregroundColor(.secondary)
            Text("Round-trip is bit-exact within IEEE-754 double precision (verified against the published GODE/ITRF2020 anchor in the BrightSpace standard).")
                .font(.caption)
                .foregroundColor(.secondary)
                .padding(.top, 2)
        }
        .padding(10)
        .background(.background.tertiary)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .padding(.horizontal)
    }

    // MARK: - Card chrome

    @ViewBuilder
    private func coordinateCard<Content: View>(
        title: String,
        subtitle: String,
        isActive: Bool,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(title)
                    .font(.headline)
                Spacer()
                if isActive {
                    Text("EDITING")
                        .font(.caption2.bold().monospaced())
                        .foregroundColor(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.blue)
                        .clipShape(Capsule())
                }
            }
            Text(subtitle)
                .font(.caption)
                .foregroundColor(.secondary)
            Divider()
            content()
        }
        .padding(10)
        .background(isActive ? .blue.opacity(0.08) : Color(.controlBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .padding(.horizontal)
    }

    @ViewBuilder
    private func labelled(_ label: String, text: Binding<String>, editable: Bool) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption2.monospaced())
                .foregroundColor(.secondary)
            TextField(label, text: text)
                .textFieldStyle(.roundedBorder)
                .disabled(!editable)
                .foregroundColor(editable ? .primary : .secondary)
        }
    }

    @ViewBuilder
    private func copyButton(label: String, what: String, value: @escaping () -> String) -> some View {
        Button {
            let v = value()
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(v, forType: .string)
            withAnimation { copiedToast = "\(what) copied to clipboard." }
            Task { @MainActor in
                try? await Task.sleep(nanoseconds: 2_500_000_000)
                withAnimation { copiedToast = nil }
            }
        } label: {
            Label(label, systemImage: "doc.on.doc")
                .labelStyle(.iconOnly)
        }
        .buttonStyle(.borderless)
    }

    // MARK: - Recomputation

    private func recomputeFromWgs() {
        guard let lat = parseDouble(wgsLatText, range: -90...90),
              let lon = parseDouble(wgsLonText, range: -180...180),
              let alt = parseDouble(wgsAltText) else {
            lastError = "WGS84 inputs out of range or not numbers."
            return
        }
        lastError = nil
        wgsLat = lat
        wgsLon = lon
        wgsAlt = alt
        let ecef = wgs84ToEcef(Wgs84LatLon(lat: lat, lon: lon, alt_m: alt))
        ecefX = ecef.x_m; ecefY = ecef.y_m; ecefZ = ecef.z_m
        let bs = ecefToBrightSpace(ecef, epochBd: 0)
        bsX = bs.x_bm; bsY = bs.y_bm; bsZ = bs.z_bm
        syncDerivedTextsExcept(active: .wgs84)
    }

    private func recomputeFromEcef() {
        guard let x = parseDouble(ecefXText),
              let y = parseDouble(ecefYText),
              let z = parseDouble(ecefZText) else {
            lastError = "ECEF inputs not numbers."
            return
        }
        lastError = nil
        ecefX = x; ecefY = y; ecefZ = z
        let ecef = EcefPoint(x_m: x, y_m: y, z_m: z)
        let w = ecefToWgs84(ecef)
        wgsLat = w.lat; wgsLon = w.lon; wgsAlt = w.alt_m ?? 0
        let bs = ecefToBrightSpace(ecef, epochBd: 0)
        bsX = bs.x_bm; bsY = bs.y_bm; bsZ = bs.z_bm
        syncDerivedTextsExcept(active: .ecef)
    }

    private func recomputeFromBrightSpace() {
        guard let x = parseDouble(bsXText),
              let y = parseDouble(bsYText),
              let z = parseDouble(bsZText) else {
            lastError = "BrightSpace inputs not numbers."
            return
        }
        lastError = nil
        bsX = x; bsY = y; bsZ = z
        let bs = BrightSpacePoint(x_bm: x, y_bm: y, z_bm: z, epoch_bd: 0)
        let ecef = brightSpaceToEcef(bs)
        ecefX = ecef.x_m; ecefY = ecef.y_m; ecefZ = ecef.z_m
        let w = ecefToWgs84(ecef)
        wgsLat = w.lat; wgsLon = w.lon; wgsAlt = w.alt_m ?? 0
        syncDerivedTextsExcept(active: .brightspace)
    }

    private func syncTextsFromState() {
        wgsLatText = String(wgsLat)
        wgsLonText = String(wgsLon)
        wgsAltText = String(wgsAlt)
        ecefXText = String(ecefX)
        ecefYText = String(ecefY)
        ecefZText = String(ecefZ)
        bsXText = String(bsX)
        bsYText = String(bsY)
        bsZText = String(bsZ)
    }

    private func syncDerivedTextsExcept(active: ActiveSpace) {
        if active != .wgs84 {
            wgsLatText = String(wgsLat)
            wgsLonText = String(wgsLon)
            wgsAltText = String(wgsAlt)
        }
        if active != .ecef {
            ecefXText = String(ecefX)
            ecefYText = String(ecefY)
            ecefZText = String(ecefZ)
        }
        if active != .brightspace {
            bsXText = String(bsX)
            bsYText = String(bsY)
            bsZText = String(bsZ)
        }
    }

    private func fillFromCurrentFix() {
        let engine = BridgeProtocolHandler.sharedGeoEngine
        guard let fix = engine.source.currentFix() else {
            lastError = "No fix available — open the Geo Engine tab and confirm the engine is alive."
            return
        }
        wgsLat = fix.wgs84.lat
        wgsLon = fix.wgs84.lon
        wgsAlt = fix.wgs84.alt_m ?? 0
        active = .wgs84
        syncTextsFromState()
        recomputeFromWgs()
    }

    private func sendToZoneEditor() {
        // Always publish in WGS84 — that's the form the Zone Editor's
        // shape sub-forms expect. The current state of `wgsLat/Lon/Alt`
        // is kept in sync by every recomputeFrom* path, so it's safe to
        // publish those regardless of the active editing space.
        CoordinateExchange.shared.publish(
            lat: wgsLat,
            lon: wgsLon,
            alt_m: wgsAlt == 0 ? nil : wgsAlt
        )
        withAnimation { copiedToast = "Sent to Zone Editor exchange." }
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            withAnimation { copiedToast = nil }
        }
    }

    private func ecefMagnitude() -> Double {
        return (ecefX * ecefX + ecefY * ecefY + ecefZ * ecefZ).squareRoot()
    }

    /// Render the BrightSpace coordinates with SI prefixes (μbm / mbm /
    /// bm / etc.) so users can eyeball the order of magnitude.
    private func brightSpacePrefixed() -> String {
        return "\(prefixedBm(bsX, label: "x"))   \(prefixedBm(bsY, label: "y"))   \(prefixedBm(bsZ, label: "z"))"
    }

    private func prefixedBm(_ v: Double, label: String) -> String {
        let abs = Swift.abs(v)
        if abs == 0 { return "\(label)=0 bm" }
        // bm = 1; mbm = 1e-3; μbm = 1e-6; nbm = 1e-9; kbm = 1e3; Mbm = 1e6
        if abs >= 1e3   { return String(format: "%@=%.4f kbm",  label, v / 1e3) }
        if abs >= 1     { return String(format: "%@=%.6f bm",   label, v) }
        if abs >= 1e-3  { return String(format: "%@=%.4f mbm",  label, v * 1e3) }
        if abs >= 1e-6  { return String(format: "%@=%.4f μbm",  label, v * 1e6) }
        return                String(format: "%@=%.4f nbm",  label, v * 1e9)
    }

    private func parseDouble(_ s: String, range: ClosedRange<Double>? = nil) -> Double? {
        guard let v = Double(s.trimmingCharacters(in: .whitespaces)) else { return nil }
        if let r = range, !r.contains(v) { return nil }
        return v
    }
}
