//
//  ContentView.swift
//  BrightNexus
//
//  Originally created as Enclave Bridge by Jessica Mulein on 1/24/26.
//  Renamed to BrightNexus on 2026-05-21.
//

import SwiftUI
import Combine

enum NavigationItem: Hashable {
    case dashboard
    case credentials
    case connections
    case keys
}

struct ContentView: View {
    @StateObject private var appState = AppState.shared
    @State private var selectedItem: NavigationItem? = .dashboard
    
    var body: some View {
        NavigationSplitView {
            // Sidebar
            List(selection: $selectedItem) {
                Section("Status") {
                    HStack {
                        Circle()
                            .fill(appState.isServerRunning ? Color.green : Color.red)
                            .frame(width: 8, height: 8)
                        Text(appState.isServerRunning ? "Server Running" : "Server Stopped")
                    }
                    if !appState.socketPath.isEmpty {
                        Text(appState.socketPath)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                            .contextMenu {
                                Button(action: {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(appState.socketPath, forType: .string)
                                }) {
                                    Label("Copy Socket Path", systemImage: "doc.on.doc")
                                }
                            }
                            .help("Right-click to copy")
                    }
                }
                
                Section("Navigation") {
                    NavigationLink(value: NavigationItem.dashboard) {
                        Label("Dashboard", systemImage: "gauge.with.dots.needle.bottom.50percent")
                    }

                    NavigationLink(value: NavigationItem.credentials) {
                        Label("Credentials", systemImage: "key.viewfinder")
                            .badge(appState.credentials.count)
                    }

                    NavigationLink(value: NavigationItem.connections) {
                        Label("Connections", systemImage: "network")
                            .badge(appState.connections.count)
                    }
                    
                    NavigationLink(value: NavigationItem.keys) {
                        Label("Keys", systemImage: "key.fill")
                            .badge(appState.keys.count)
                    }
                }
                
                Section("Statistics") {
                    LabeledContent("Total Requests", value: "\(appState.totalRequestsHandled)")
                }
            }
            .listStyle(SidebarListStyle())
            .navigationTitle("BrightNexus")
        } detail: {
            switch selectedItem {
            case .dashboard, .none:
                DashboardView()
            case .credentials:
                CredentialsView()
            case .connections:
                ConnectionsView()
            case .keys:
                KeysView()
            }
        }
        .frame(minWidth: 600, minHeight: 400)
    }
}

struct DashboardView: View {
    @StateObject private var appState = AppState.shared
    
    var body: some View {
        VStack(spacing: 20) {
            // Wordmark — same asset as the About panel. Light/dark variants
            // are baked into Wordmark.imageset, so the asset adapts to the
            // system appearance automatically. The wordmark already says
            // "BrightNexus", so no redundant Text() title is rendered.
            Image("Wordmark")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(maxWidth: 360, maxHeight: 80)
                .accessibilityLabel("BrightNexus")

            Text("Apple Secure Enclave ↔ Node.js bridge + BrightLink agent")
                .font(.title3)
                .foregroundColor(.secondary)
            
            Divider()
                .padding(.horizontal, 40)
            
            VStack(alignment: .leading, spacing: 12) {
                StatusRow(
                    icon: "server.rack",
                    label: "Server",
                    value: appState.isServerRunning ? "Running" : "Stopped",
                    color: appState.isServerRunning ? .green : .red
                )
                StatusRow(
                    icon: "network",
                    label: "Active Connections",
                    value: "\(appState.connections.count)",
                    color: appState.connections.isEmpty ? .secondary : .blue
                )
                StatusRow(
                    icon: "key.fill",
                    label: "Keys Loaded",
                    value: "\(appState.keys.count)",
                    color: .orange
                )
                StatusRow(
                    icon: "key.viewfinder",
                    label: "Active Credentials",
                    value: "\(appState.credentials.count)",
                    color: appState.credentials.isEmpty ? .secondary : .blue
                )
                StatusRow(
                    icon: "arrow.left.arrow.right",
                    label: "Total Requests",
                    value: "\(appState.totalRequestsHandled)",
                    color: .purple
                )
            }
            .padding()
            .background(Color(nsColor: .controlBackgroundColor))
            .cornerRadius(12)
            
            Spacer()
        }
        .padding()
        .frame(minWidth: 400)
        .navigationTitle("Dashboard")
    }
}

struct StatusRow: View {
    let icon: String
    let label: String
    let value: String
    let color: Color
    
    var body: some View {
        HStack {
            Image(systemName: icon)
                .foregroundColor(color)
                .frame(width: 24)
            Text(label)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
        }
    }
}

struct ConnectionsView: View {
    @StateObject private var appState = AppState.shared
    
    var body: some View {
        Group {
            if appState.connections.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "network.slash")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No Active Connections")
                        .font(.title2)
                        .foregroundColor(.secondary)
                    Text("Clients will appear here when connected")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(appState.connections) { connection in
                    ConnectionRow(connection: connection)
                }
            }
        }
        .navigationTitle("Active Connections")
    }
}

struct ConnectionRow: View {
    let connection: ClientConnection
    
    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .short
        f.timeStyle = .medium
        return f
    }()
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(Color.green)
                    .frame(width: 8, height: 8)
                Text("Client \(connection.id.uuidString.prefix(8))...")
                    .fontWeight(.medium)
                Spacer()
                Text("\(connection.requestCount) requests")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            
            HStack {
                Text("Connected: \(dateFormatter.string(from: connection.connectedAt))")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Spacer()
                Text("Last activity: \(dateFormatter.string(from: connection.lastActivity))")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Credentials

struct CredentialsView: View {
    @StateObject private var appState = AppState.shared
    /// 1 Hz tick so TTL countdowns refresh.
    @State private var now = Date()
    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        Group {
            if appState.credentials.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "key.viewfinder")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No Active Credentials")
                        .font(.title2)
                        .foregroundColor(.secondary)
                    Text("Credentials delivered via LINK_DELIVER will appear here")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(appState.credentials) { entry in
                    CredentialRow(entry: entry, now: now)
                }
            }
        }
        .navigationTitle("Credentials")
        .toolbar {
            if !appState.credentials.isEmpty {
                ToolbarItem {
                    Button(action: {
                        AppState.shared.ephemeralStore.removeAll()
                    }) {
                        Label("Clear All", systemImage: "trash")
                    }
                }
            }
        }
        .onReceive(tick) { now = $0 }
    }
}

struct CredentialRow: View {
    let entry: EphemeralStore.Entry
    let now: Date

    private var ttlLabel: String {
        let remaining = max(0, entry.expiresAt.timeIntervalSince(now))
        let mins = Int(remaining) / 60
        let secs = Int(remaining) % 60
        return mins > 0 ? "\(mins)m \(secs)s" : "\(secs)s"
    }

    private var typeColor: Color {
        switch entry.payload.type {
        case BrightLinkPayloadType.ephemeralAuth: return .blue
        case BrightLinkPayloadType.dbConnection:  return .purple
        case BrightLinkPayloadType.geoContext:    return .green
        default:                           return .secondary
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "key.viewfinder")
                    .foregroundColor(typeColor)
                Text(entry.payload.type)
                    .fontWeight(.semibold)
                    .font(.system(.body, design: .monospaced))
                Spacer()
                Label(ttlLabel, systemImage: "timer")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .monospacedDigit()
            }

            Text(entry.payload.context)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.secondary)
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)

            // Provenance hint per RFC §4.9.5 — surfaces the attesting
            // peer (e.g. signed binary path or fallback PID label) so the
            // user can decide if they trust the source before clicking copy.
            if let provider = entry.providerLabel, !provider.isEmpty {
                HStack(spacing: 4) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    Text("from \(provider)")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            // RFC §5: each schema produces its own list of click-to-copy
            // rows. The renderer walks `copyableFields()` regardless of type.
            VStack(alignment: .leading, spacing: 4) {
                ForEach(entry.payload.copyableFields(), id: \.label) { field in
                    CopyableFieldRow(label: field.label,
                                     visible: field.display,
                                     value: field.copyValue)
                }
            }
        }
        .padding(.vertical, 6)
    }
}

private struct CopyableFieldRow: View {
    let label: String
    let visible: String
    let value: String

    var body: some View {
        HStack(spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 70, alignment: .leading)
            Text(visible)
                .font(.system(.caption, design: .monospaced))
            Spacer()
            Button(action: copy) {
                Image(systemName: "doc.on.doc")
                    .font(.caption)
            }
            .buttonStyle(.borderless)
            .help("Copy \(label)")
        }
    }

    private func copy() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }
}

struct KeysView: View {
    @StateObject private var appState = AppState.shared
    
    var body: some View {
        Group {
            if appState.keys.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "key.slash")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No Keys Available")
                        .font(.title2)
                        .foregroundColor(.secondary)
                    Text("Keys will be generated on first use")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(appState.keys) { key in
                    KeyRow(keyInfo: key)
                }
            }
        }
        .navigationTitle("Cryptographic Keys")
        .toolbar {
            ToolbarItem {
                Button(action: { appState.refreshKeys() }) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
            }
        }
    }
}

struct KeyRow: View {
    let keyInfo: KeyInfo
    
    private let dateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: keyInfo.isSecureEnclave ? "cpu" : "key.fill")
                    .foregroundColor(keyInfo.isSecureEnclave ? .blue : .orange)
                Text(keyInfo.type.rawValue)
                    .fontWeight(.semibold)
                Spacer()
                if keyInfo.isSecureEnclave {
                    Label("Hardware", systemImage: "checkmark.shield.fill")
                        .font(.caption)
                        .foregroundColor(.green)
                }
            }
            
            HStack {
                Text("Fingerprint:")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text(keyInfo.publicKeyFingerprint)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.primary)
            }
            
            Text("Created: \(dateFormatter.string(from: keyInfo.createdAt))")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    ContentView()
}
