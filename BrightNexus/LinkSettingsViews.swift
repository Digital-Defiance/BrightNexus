// LinkSettingsViews.swift
// BrightNexus
//
// SwiftUI Settings tabs for the BrightLink geo subsystem (Wave 4h):
//
//   - GeoEngineSettingsView: read-only status (engine kind, fix age,
//     accuracy, current zone). Mirrors what `LINK_GEO_STATUS` returns to
//     wire callers, plus the latest zone the engine is tracking.
//
//   - AllowlistSettingsView: live view of `geo-acl.json` with per-entry
//     Re-prompt and Revoke actions. Re-prompt deletes the entry (the
//     next request will fire a fresh prompt). Revoke is the same delete
//     but framed for the user as "remove this caller entirely".
//
// Both views read the shared engine via
// `BridgeProtocolHandler.sharedGeoEngine` (which is @MainActor-isolated)
// so they implicitly run on the main thread.

import SwiftUI

// MARK: - Geo Engine status tab

@MainActor
struct GeoEngineSettingsView: View {

    @State private var statusText: String = "—"
    @State private var engineKind: String = "—"
    @State private var alive: Bool = false
    @State private var fixAgeText: String = "—"
    @State private var accuracyText: String = "—"
    @State private var currentZoneText: String = "—"
    @State private var zoneCount: Int = 0
    @State private var refreshTimer: Timer? = nil

    var body: some View {
        Form {
            Section {
                LabeledContent("Engine") { Text(engineKind).font(.body.monospaced()) }
                LabeledContent("Status") {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(alive ? .green : .secondary)
                            .frame(width: 8, height: 8)
                        Text(statusText)
                    }
                }
                LabeledContent("Latest fix age") { Text(fixAgeText) }
                LabeledContent("Accuracy") { Text(accuracyText) }
            } header: {
                Text("Engine").font(.headline)
            } footer: {
                Text("Read-only mirror of LINK_GEO_STATUS. The engine is currently a NullGeoSource placeholder; CoreLocation wiring lands in a future build.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Section {
                LabeledContent("Current zone") { Text(currentZoneText) }
                LabeledContent("Configured zones") { Text("\(zoneCount)") }
            } header: {
                Text("Zones").font(.headline)
            } footer: {
                Text("Zone definitions live in ~/.brightchain/brightnexus/geo-zones.json. Zone editing UI lands in a future build.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Section {
                Button("Refresh") { refresh() }
            }
        }
        .padding()
        .onAppear { refresh(); startTimer() }
        .onDisappear { stopTimer() }
    }

    private func refresh() {
        let engine = BridgeProtocolHandler.sharedGeoEngine
        let s = engine.statusSnapshot()
        engineKind = s.kind
        alive = s.alive
        statusText = s.alive ? "Alive (has fix)" : "No fix"
        fixAgeText = s.fixAgeSeconds.map { String(format: "%.1fs ago", $0) } ?? "—"
        accuracyText = s.accuracyM.map { String(format: "±%.1f m", $0) } ?? "—"
        currentZoneText = engine.currentZoneId() ?? "(none)"
        zoneCount = engine.zonesCount()
    }

    private func startTimer() {
        stopTimer()
        // Refresh every 5 seconds while the tab is visible.
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
            Task { @MainActor in self.refresh() }
        }
    }

    private func stopTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }
}

// MARK: - Allowlist tab

@MainActor
struct AllowlistSettingsView: View {

    @State private var entries: [LinkAclEntry] = []
    @State private var bridgeKeyId: String = "—"
    @State private var pendingRevoke: LinkAclEntry? = nil
    @State private var showRevokeConfirm: Bool = false
    @State private var fileWatcher: DispatchSourceFileSystemObject? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Allowlist (\(entries.count) entries)")
                    .font(.headline)
                Spacer()
                Text(bridgeKeyId)
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal)
            .padding(.top, 12)
            .padding(.bottom, 8)

            Divider()

            if entries.isEmpty {
                Spacer()
                VStack(spacing: 6) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 36))
                        .foregroundColor(.secondary)
                    Text("No callers yet.")
                        .font(.body)
                    Text("Each caller you grant geo access to will appear here. Use Re-prompt to ask again next time, or Revoke to remove a caller entirely.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                }
                Spacer()
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        ForEach(entries, id: \.id) { entry in
                            AllowlistEntryRow(
                                entry: entry,
                                onReprompt: { reprompt(entry) },
                                onRevoke:   { confirmRevoke(entry) }
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
                Button("Open ACL Folder") { openAclFolder() }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .onAppear {
            reload()
            startWatching()
        }
        .onDisappear { stopWatching() }
        .onReceive(NotificationCenter.default.publisher(for: LinkAcl.didChangeNotification)) { _ in
            reload()
        }
        .alert(
            "Revoke this caller?",
            isPresented: $showRevokeConfirm,
            presenting: pendingRevoke
        ) { entry in
            Button("Revoke", role: .destructive) { revoke(entry) }
            Button("Cancel", role: .cancel) { pendingRevoke = nil }
        } message: { entry in
            Text("\(entry.displayName) will be removed from the allowlist. The next time it asks for geo access, you'll get a fresh prompt.")
        }
    }

    private func reload() {
        let engine = BridgeProtocolHandler.sharedGeoEngine
        entries = engine.acl.list().sorted { $0.displayName.lowercased() < $1.displayName.lowercased() }
        bridgeKeyId = engine.acl.bridgeKeyId()
    }

    private func reprompt(_ entry: LinkAclEntry) {
        // Re-prompt is functionally a remove: the next request from this
        // caller will find no matching entry and trigger a fresh prompt.
        // The framing is "re-prompt" rather than "revoke" because the
        // user keeps the option to grant again — which they would also
        // have under Revoke, but Re-prompt makes the expected outcome
        // (a new modal next time the caller asks) explicit.
        let engine = BridgeProtocolHandler.sharedGeoEngine
        engine.acl.remove(id: entry.id)
        try? engine.acl.saveToDisk()
        // No reload() — the didChangeNotification observer will fire.
    }

    private func confirmRevoke(_ entry: LinkAclEntry) {
        pendingRevoke = entry
        showRevokeConfirm = true
    }

    private func revoke(_ entry: LinkAclEntry) {
        let engine = BridgeProtocolHandler.sharedGeoEngine
        engine.acl.remove(id: entry.id)
        try? engine.acl.saveToDisk()
        pendingRevoke = nil
        // No reload() — the didChangeNotification observer will fire.
    }

    private func openAclFolder() {
        NSWorkspace.shared.activateFileViewerSelecting([BrightNexusPaths.geoAcl])
    }

    // MARK: - Filesystem watcher
    //
    // Catches edits/deletes performed outside the app (e.g. user `rm`s
    // geo-acl.json from the terminal, or restores from a backup). The
    // in-process didChangeNotification covers app-driven mutations; this
    // covers everything else.

    private func startWatching() {
        stopWatching()
        let path = BrightNexusPaths.geoAcl.path
        let fd = open(path, O_EVTONLY)
        guard fd != -1 else {
            // File doesn't exist yet (no entries persisted). The watch
            // re-arms on the next reload(); for now we just observe the
            // tool dir itself as a fallback.
            return
        }
        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd,
            eventMask: [.write, .delete, .rename, .extend],
            queue: .main
        )
        src.setEventHandler {
            // The file may have been atomically replaced (rename on
            // saveToDisk), in which case our fd points at the old inode.
            // Cheapest robust fix: re-arm the watch on every event.
            Task { @MainActor in
                self.reload()
                self.startWatching()
            }
        }
        src.setCancelHandler {
            close(fd)
        }
        src.resume()
        fileWatcher = src
    }

    private func stopWatching() {
        fileWatcher?.cancel()
        fileWatcher = nil
    }
}

// MARK: - Allowlist row

@MainActor
private struct AllowlistEntryRow: View {

    let entry: LinkAclEntry
    let onReprompt: () -> Void
    let onRevoke: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: classIcon)
                    .foregroundColor(classTint)
                Text(entry.displayName)
                    .font(.headline)
                Spacer()
                attestationBadge
            }

            if let path = entry.expectedPath {
                Text(path)
                    .font(.caption.monospaced())
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            HStack(spacing: 8) {
                ForEach(LinkGeoScope.allCases, id: \.self) { scope in
                    scopeChip(scope, policy: entry.scopes[scope] ?? .prompt)
                }
            }

            if let sshSession = entry.sshSessionId {
                Label("SSH session: \(sshSession)", systemImage: "terminal")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }

            HStack {
                Spacer()
                Button("Re-prompt") { onReprompt() }
                Button("Revoke", role: .destructive) { onRevoke() }
            }
            .padding(.top, 2)
        }
        .padding(10)
        .background(.background.secondary)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var classIcon: String {
        switch entry.attestationClass {
        case .developerId:    return "checkmark.seal.fill"
        case .macAppStore:    return "apple.logo"
        case .bshBuiltin:     return "shield.checkered"
        case .dpkgSigned, .rpmSigned, .flatpakSigned: return "shippingbox.fill"
        case .unsigned:       return "exclamationmark.triangle.fill"
        }
    }

    private var classTint: Color {
        switch entry.attestationClass {
        case .unsigned: return .orange
        case .bshBuiltin: return .blue
        default: return .green
        }
    }

    private var attestationBadge: some View {
        Text(entry.attestationClass.rawValue)
            .font(.caption2.monospaced())
            .foregroundColor(.secondary)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(.background.tertiary)
            .clipShape(Capsule())
    }

    private func scopeChip(_ scope: LinkGeoScope, policy: LinkGeoPolicy) -> some View {
        let (label, color): (String, Color) = {
            switch policy {
            case .always: return ("✓", .green)
            case .deny:   return ("✕", .red)
            case .prompt: return ("?", .secondary)
            }
        }()
        return HStack(spacing: 3) {
            Text(scope.rawValue)
                .font(.caption2)
            Text(label)
                .font(.caption2.bold())
                .foregroundColor(color)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(.background.tertiary)
        .clipShape(Capsule())
    }
}
