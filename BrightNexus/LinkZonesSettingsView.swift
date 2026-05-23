// LinkZonesSettingsView.swift
// BrightNexus
//
// Settings tab for managing user-defined zones (RFC §8). Backs the
// `geo-zones.json` file at ~/.brightchain/brightnexus/.
//
// Capabilities:
//   - List, add, edit, delete zones
//   - Shape picker with form per shape type:
//       circle_2d   — center (lat/lon) + radius (m)
//       cylinder_3d — center + radius + altitude min/max
//       polygon_2d  — N points (lat/lon each)
//       bbox_2d     — lat/lon bounds
//   - "Use Current Location" pre-fills center from CoreLocation
//   - Auto-refresh on engine notification + filesystem change
//
// All UI runs on the main actor; engine state is read through
// BridgeProtocolHandler.sharedGeoEngine. Mutations go through
// engine.zones.upsert / .remove + saveToDisk; the engine publishes
// LinkZoneEngine.didChangeNotification, the view re-renders.

import SwiftUI

// MARK: - Top-level tab

@MainActor
struct ZonesSettingsView: View {

    @State private var zones: [ZoneDefinition] = []
    @State private var pendingDelete: ZoneDefinition? = nil
    @State private var showDeleteConfirm = false
    @State private var fileWatcher: DispatchSourceFileSystemObject? = nil

    /// What the editor sheet is editing — either a brand-new zone or an
    /// existing one being modified.
    enum ZoneEditorTarget: Identifiable {
        case new
        case existing(ZoneDefinition)

        var id: String {
            switch self {
            case .new: return "<new>"
            case .existing(let z): return z.id
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Zones (\(zones.count))")
                    .font(.headline)
                Spacer()
                Button {
                    ZoneEditorWindowController.shared.show(target: .new) { newZone in
                        let engine = BridgeProtocolHandler.sharedGeoEngine
                        engine.zones.upsert(newZone)
                        try? engine.zones.saveToDisk()
                    }
                } label: {
                    Label("Add Zone", systemImage: "plus")
                }
            }
            .padding(.horizontal)
            .padding(.top, 12)
            .padding(.bottom, 8)

            Divider()

            if zones.isEmpty {
                Spacer()
                VStack(spacing: 6) {
                    Image(systemName: "map")
                        .font(.system(size: 36))
                        .foregroundColor(.secondary)
                    Text("No zones defined.")
                        .font(.body)
                    Text("Define zones to give bsh tools spatial context — \"in the office\", \"in the data center\", a delivery boundary, etc. Zones are checked by LINK_GEO_ZONE and LINK_GEO_PROXIMITY.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(zones, id: \.id) { zone in
                            ZoneRow(
                                zone: zone,
                                onEdit: {
                                    ZoneEditorWindowController.shared.show(
                                        target: .existing(zone)
                                    ) { newZone in
                                        let engine = BridgeProtocolHandler.sharedGeoEngine
                                        engine.zones.upsert(newZone)
                                        try? engine.zones.saveToDisk()
                                    }
                                },
                                onDelete: { pendingDelete = zone; showDeleteConfirm = true }
                            )
                            .padding(.horizontal)
                        }
                    }
                    .padding(.vertical, 8)
                }
            }

            Divider()

            HStack {
                Button("Refresh") { reload() }
                Spacer()
                Button("Open Zones File") { openZonesFile() }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .onAppear {
            reload()
            startWatching()
        }
        .onDisappear { stopWatching() }
        .onReceive(NotificationCenter.default.publisher(for: LinkZoneEngine.didChangeNotification)) { _ in
            reload()
        }
        .alert(
            "Delete this zone?",
            isPresented: $showDeleteConfirm,
            presenting: pendingDelete
        ) { zone in
            Button("Delete", role: .destructive) { deleteZone(zone) }
            Button("Cancel", role: .cancel) { pendingDelete = nil }
        } message: { zone in
            Text("\(zone.displayName) will be removed from geo-zones.json. Tools currently inside this zone will no longer match it.")
        }
    }

    private func reload() {
        let engine = BridgeProtocolHandler.sharedGeoEngine
        zones = engine.zones.list().sorted { a, b in
            // Sort by descending priority, then by display name.
            let pa = zonePriority(a)
            let pb = zonePriority(b)
            if pa != pb { return pa > pb }
            return a.displayName.lowercased() < b.displayName.lowercased()
        }
    }

    private func deleteZone(_ zone: ZoneDefinition) {
        let engine = BridgeProtocolHandler.sharedGeoEngine
        engine.zones.remove(id: zone.id)
        try? engine.zones.saveToDisk()
        pendingDelete = nil
    }

    private func openZonesFile() {
        NSWorkspace.shared.activateFileViewerSelecting([BrightNexusPaths.geoZones])
    }

    // MARK: - Filesystem watcher (catches external `vim geo-zones.json` etc.)

    private func startWatching() {
        stopWatching()
        let path = BrightNexusPaths.geoZones.path
        let fd = open(path, O_EVTONLY)
        guard fd != -1 else { return }
        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .extend],
            queue: .main
        )
        src.setEventHandler {
            Task { @MainActor in
                // External edit means our in-memory state is stale.
                let reloaded = LinkZoneEngine.loadFromDisk()
                BridgeProtocolHandler.sharedGeoEngine.zones.setZones(reloaded.list())
                self.reload()
                self.startWatching()  // re-arm against atomic-rename invalidation
            }
        }
        src.setCancelHandler { close(fd) }
        src.resume()
        fileWatcher = src
    }

    private func stopWatching() {
        fileWatcher?.cancel()
        fileWatcher = nil
    }
}

// MARK: - Zone row

@MainActor
private struct ZoneRow: View {
    let zone: ZoneDefinition
    let onEdit: () -> Void
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: shapeIcon)
                    .foregroundColor(.blue)
                Text(zone.displayName)
                    .font(.headline)
                Spacer()
                Text("priority \(zonePriority(zone))")
                    .font(.caption2.monospaced())
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.background.tertiary)
                    .clipShape(Capsule())
            }
            Text(zone.shape.typeString)
                .font(.caption.monospaced())
                .foregroundColor(.secondary)
            Text(shapeSummary)
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(2)
            HStack {
                Spacer()
                Button("Edit") { onEdit() }
                Button("Delete", role: .destructive) { onDelete() }
            }
            .padding(.top, 2)
        }
        .padding(10)
        .background(.background.secondary)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var shapeIcon: String {
        switch zone.shape {
        case .circle2d:   return "circle"
        case .cylinder3d: return "cylinder"
        case .polygon2d:  return "hexagon"
        case .bbox2d:     return "square.dashed"
        }
    }

    private var shapeSummary: String {
        switch zone.shape {
        case .circle2d(let c, let r):
            return String(format: "centre %.6f, %.6f · radius %.0f m", c.lat, c.lon, r)
        case .cylinder3d(let c, let r, let aMin, let aMax):
            return String(format: "centre %.6f, %.6f · radius %.0f m · alt %.0f–%.0f m", c.lat, c.lon, r, aMin, aMax)
        case .polygon2d(let pts):
            return "\(pts.count) vertices"
        case .bbox2d(let latMin, let latMax, let lonMin, let lonMax):
            return String(format: "lat %.4f→%.4f · lon %.4f→%.4f", latMin, latMax, lonMin, lonMax)
        }
    }
}
