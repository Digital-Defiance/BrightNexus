//
//  BrightNexusApp.swift
//  BrightNexus
//
//  Originally created as Enclave Bridge by Jessica Mulein on 1/24/26.
//  Renamed and re-anchored on the BrightLink v1 protocol on 2026-05-21.
//
//  Architectural notes — see docs/rfc-brightlink.md:
//    * Bundle ID: org.digitaldefiance.brightchain.BrightNexus
//    * State dir: ~/.brightchain/brightnexus/  (mode 0700)
//    * No App Sandbox (intentional; see RFC v3 §3 trust model)
//

import SwiftUI
import CoreData
import ServiceManagement

// Notifications for showing windows.
extension Notification.Name {
    static let showMainWindow = Notification.Name("showMainWindow")
    static let showSettings = Notification.Name("showSettings")
}

@main
struct BrightNexusApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    let persistenceController = PersistenceController.shared

    /// Single shared socket server. Constructed after `BrightNexusPaths.bootstrap()` runs.
    static let socketServer: SocketServer = {
        BrightNexusPaths.bootstrap()
        return SocketServer()
    }()

    init() {
        BrightNexusApp.socketServer.start()
        Task { @MainActor in
            AppState.shared.isServerRunning = true
            AppState.shared.socketPath = BrightNexusPaths.primarySocket.path
        }
    }

    var body: some Scene {
        WindowGroup(id: "main") {
            ContentView()
                .environment(\.managedObjectContext, persistenceController.container.viewContext)
        }
        .handlesExternalEvents(matching: Set(["main", ""]))
        .commands {
            CommandGroup(replacing: .appTermination) {
                Button("Quit BrightNexus") {
                    BrightNexusApp.socketServer.stop()
                    NSApplication.shared.terminate(nil)
                }
                .keyboardShortcut("q")
            }
        }

        // Settings window
        Settings {
            SettingsView()
        }
    }
}

// MARK: - Settings Window Controller

class SettingsWindowController {
    private static var settingsWindow: NSWindow?
    private static var windowController: NSWindowController?

    static func showSettings() {
        // Ensure app is in regular mode first.
        NSApp.setActivationPolicy(.regular)

        if let window = settingsWindow {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let settingsView = SettingsView()
        let hostingController = NSHostingController(rootView: settingsView)

        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 450, height: 340),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )

        window.title = "BrightNexus Settings"
        window.contentViewController = hostingController
        window.center()
        window.isReleasedWhenClosed = false

        settingsWindow = window
        windowController = NSWindowController(window: window)

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

// MARK: - App Delegate for Status Bar

import Combine

class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, NSMenuDelegate {
    private var statusItem: NSStatusItem!
    private var statusBarMenu: NSMenu!
    private weak var mainWindow: NSWindow?

    private var serverStatusMenuItem: NSMenuItem?
    private var connectionsMenuItem: NSMenuItem?
    private var requestsMenuItem: NSMenuItem?
    private var keysMenuItem: NSMenuItem?
    /// "Credentials" parent menu item; submenu rebuilt on each AppState update.
    private var credentialsMenuItem: NSMenuItem?
    /// Refresh timer that ticks the TTL countdowns when the menu is open.
    private var credentialsRefreshTimer: Timer?
    /// Tracks open state of the *credentials submenu* so we don't replace
    /// `parent.submenu` while it's visible — AppKit handles such replacement
    /// poorly and it can cause the menu (and main runloop) to lock up.
    private var credentialsMenuIsOpen = false
    /// Set when a structural change arrives while the credentials submenu is
    /// open. Drained on `menuDidClose`.
    private var credentialsPendingRebuild = false

    private var cancellables = Set<AnyCancellable>()
    private var windowObservationTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusBar()
        subscribeToAppStateChanges()
        NSApp.setActivationPolicy(.regular)
        startWindowObservation()
        NSLog("[BrightNexus] applicationDidFinishLaunching completed")
    }

    private func startWindowObservation() {
        windowObservationTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] timer in
            guard let self = self else {
                timer.invalidate()
                return
            }
            DispatchQueue.main.async {
                self.captureMainWindowIfNeeded()
            }
        }
    }

    private func captureMainWindowIfNeeded() {
        for window in NSApp.windows {
            guard isMainContentWindow(window) else { continue }
            if self.mainWindow !== window || window.delegate !== self {
                self.mainWindow = window
                window.delegate = self
                NSLog("[BrightNexus] Captured main window: %@", String(describing: window))
            }
        }
    }

    private func isMainContentWindow(_ window: NSWindow) -> Bool {
        guard window.canBecomeMain else { return false }
        guard window.contentView != nil else { return false }
        guard window.styleMask.contains(.titled) else { return false }
        guard !window.isMiniaturized else { return false }
        let title = window.title.lowercased()
        return !title.contains("settings") && !title.contains("preferences")
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationWillTerminate(_ notification: Notification) {
        windowObservationTimer?.invalidate()
        credentialsRefreshTimer?.invalidate()
        BrightNexusApp.socketServer.stop()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if let window = mainWindow, window.isMiniaturized {
            return true
        }
        if !flag {
            showMainWindow()
        }
        return true
    }

    // MARK: - Status Bar Setup

    private func setupStatusBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        guard let button = statusItem.button else {
            NSLog("[BrightNexus] ERROR: failed to get status bar button")
            return
        }

        // Custom menu-bar glyph from Assets.xcassets/WavePulse.imageset.
        // The asset is rendered as a template image (alpha-only), so macOS
        // auto-tints it for both light and dark menu bars without us needing
        // a second variant.
        //
        // Important: NSImage(named:) returns the image at its natural size,
        // which for our SVG is 640×640. The menu bar expects ~18pt icons.
        // We MUST set an explicit size or the image renders far too large
        // (or, after being clipped to fit, appears blank). 18pt is the
        // standard NSStatusBar template-image height.
        if let img = NSImage(named: "WavePulse") {
            img.size = NSSize(width: 18, height: 18)
            img.isTemplate = true
            button.image = img
        } else {
            // Fallback in case the asset hasn't been included in this build.
            NSLog("[BrightNexus] WARN: WavePulse asset missing; using SF symbol fallback")
            let fallback = NSImage(systemSymbolName: "waveform.path.ecg",
                                   accessibilityDescription: "BrightNexus")
            fallback?.isTemplate = true
            button.image = fallback
        }
        button.image?.accessibilityDescription = "BrightNexus"

        statusBarMenu = NSMenu()

        let headerItem = NSMenuItem(title: "BrightNexus", action: nil, keyEquivalent: "")
        headerItem.isEnabled = false
        headerItem.attributedTitle = NSAttributedString(
            string: "BrightNexus",
            attributes: [.font: NSFont.boldSystemFont(ofSize: 13)]
        )
        statusBarMenu.addItem(headerItem)
        statusBarMenu.addItem(NSMenuItem.separator())

        let showItem = NSMenuItem(title: "Show Window", action: #selector(showMainWindow), keyEquivalent: "")
        showItem.target = self
        statusBarMenu.addItem(showItem)
        statusBarMenu.addItem(NSMenuItem.separator())

        serverStatusMenuItem = NSMenuItem(title: "● Server: Starting...", action: nil, keyEquivalent: "")
        serverStatusMenuItem?.isEnabled = false
        statusBarMenu.addItem(serverStatusMenuItem!)

        connectionsMenuItem = NSMenuItem(title: "   Connections: 0", action: nil, keyEquivalent: "")
        connectionsMenuItem?.isEnabled = false
        statusBarMenu.addItem(connectionsMenuItem!)

        requestsMenuItem = NSMenuItem(title: "   Requests: 0", action: nil, keyEquivalent: "")
        requestsMenuItem?.isEnabled = false
        statusBarMenu.addItem(requestsMenuItem!)

        keysMenuItem = NSMenuItem(title: "   Keys: 0", action: nil, keyEquivalent: "")
        keysMenuItem?.isEnabled = false
        statusBarMenu.addItem(keysMenuItem!)

        statusBarMenu.addItem(NSMenuItem.separator())

        // Credentials submenu (RFC §4.9 + §5). Rebuilt by `rebuildCredentialsMenu`
        // whenever AppState.credentials changes; ticks every second while open
        // via `credentialsRefreshTimer` so TTL countdowns stay live.
        credentialsMenuItem = NSMenuItem(title: "Credentials  (none)", action: nil, keyEquivalent: "")
        credentialsMenuItem?.isEnabled = false
        let placeholderSub = NSMenu()
        placeholderSub.delegate = self
        let placeholder = NSMenuItem(title: "No active credentials", action: nil, keyEquivalent: "")
        placeholder.isEnabled = false
        placeholderSub.addItem(placeholder)
        credentialsMenuItem?.submenu = placeholderSub
        statusBarMenu.addItem(credentialsMenuItem!)

        statusBarMenu.addItem(NSMenuItem.separator())

        let settingsItem = NSMenuItem(title: "Settings...", action: #selector(openSettings), keyEquivalent: ",")
        settingsItem.target = self
        statusBarMenu.addItem(settingsItem)

        statusBarMenu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit BrightNexus", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        statusBarMenu.addItem(quitItem)

        statusItem.menu = statusBarMenu

        NSLog("[BrightNexus] Status bar setup complete")
    }

    // MARK: - Window Delegate

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        NSLog("[BrightNexus] windowShouldClose called")
        hideToStatusBar()
        return false
    }

    // MARK: - Window Actions

    private func hideToStatusBar() {
        NSLog("[BrightNexus] Hiding to status bar")
        mainWindow?.orderOut(nil)
        NSApp.setActivationPolicy(.accessory)
    }

    @objc func showMainWindow() {
        NSLog("[BrightNexus] Showing main window")
        NSApp.setActivationPolicy(.regular)

        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
            if let window = self.mainWindow {
                if window.isMiniaturized {
                    window.deminiaturize(nil)
                } else {
                    window.makeKeyAndOrderFront(nil)
                }
            } else {
                for window in NSApp.windows {
                    guard window.canBecomeMain else { continue }
                    guard window.styleMask.contains(.titled) else { continue }

                    let title = window.title.lowercased()
                    if !title.contains("settings") && !title.contains("preferences") {
                        if window.isMiniaturized {
                            window.deminiaturize(nil)
                        } else {
                            window.makeKeyAndOrderFront(nil)
                        }
                        self.mainWindow = window
                        window.delegate = self
                        break
                    }
                }
            }
        }
    }

    @objc func openSettings() {
        NSLog("[BrightNexus] Opening settings")
        SettingsWindowController.showSettings()
    }

    @objc func quitApp() {
        NSApplication.shared.terminate(nil)
    }

    // MARK: - App State Subscription

    private func subscribeToAppStateChanges() {
        Task { @MainActor in
            let appState = AppState.shared

            appState.$isServerRunning
                .receive(on: DispatchQueue.main)
                .sink { [weak self] isRunning in
                    self?.updateServerStatus(isRunning: isRunning)
                }
                .store(in: &cancellables)

            appState.$connections
                .receive(on: DispatchQueue.main)
                .sink { [weak self] connections in
                    self?.connectionsMenuItem?.title = "   Connections: \(connections.count)"
                    self?.updateStatusBarIcon()
                }
                .store(in: &cancellables)

            appState.$totalRequestsHandled
                .receive(on: DispatchQueue.main)
                .sink { [weak self] count in
                    self?.requestsMenuItem?.title = "   Requests: \(count)"
                }
                .store(in: &cancellables)

            appState.$keys
                .receive(on: DispatchQueue.main)
                .sink { [weak self] keys in
                    self?.keysMenuItem?.title = "   Keys: \(keys.count)"
                }
                .store(in: &cancellables)

            appState.$credentials
                .receive(on: DispatchQueue.main)
                .sink { [weak self] entries in
                    self?.rebuildCredentialsMenu(entries: entries)
                }
                .store(in: &cancellables)
        }
    }

    // MARK: - Credentials menu

    /// Rebuild the credentials submenu from the latest `AppState.credentials`.
    /// Called on every store change AND once per second while the menu is open
    /// so TTL countdowns stay live without flicker.
    ///
    /// While the credentials submenu is *open*, we do NOT replace
    /// `parent.submenu` — AppKit handles such replacement poorly during
    /// display and it can cause both the menu and the main runloop to lock
    /// up. Instead we mark `credentialsPendingRebuild` and either rebuild on
    /// `menuDidClose`, or in-place mutate the visible TTL labels via
    /// `updateOpenCredentialsMenuTTLs`.
    private func rebuildCredentialsMenu(entries: [EphemeralStore.Entry]) {
        guard let parent = credentialsMenuItem else { return }

        if credentialsMenuIsOpen {
            // Menu is open — only update visible TTL labels in-place; defer
            // any structural change (additions, removals) to menuDidClose.
            updateOpenCredentialsMenuTTLs(entries: entries)
            credentialsPendingRebuild = true
            return
        }

        let submenu = NSMenu()
        submenu.delegate = self

        if entries.isEmpty {
            parent.title = "Credentials  (none)"
            parent.isEnabled = false
            let placeholder = NSMenuItem(title: "No active credentials", action: nil, keyEquivalent: "")
            placeholder.isEnabled = false
            submenu.addItem(placeholder)
        } else {
            parent.title = "Credentials  (\(entries.count))"
            parent.isEnabled = true

            let now = Date()
            for entry in entries {
                let label = credentialRowLabel(for: entry, now: now)
                let item = NSMenuItem(title: label, action: nil, keyEquivalent: "")
                item.representedObject = entry.id
                item.submenu = buildEntrySubmenu(entry: entry)
                submenu.addItem(item)
            }

            submenu.addItem(NSMenuItem.separator())
            let clearItem = NSMenuItem(title: "Clear All",
                                       action: #selector(clearAllCredentials),
                                       keyEquivalent: "")
            clearItem.target = self
            submenu.addItem(clearItem)
        }

        parent.submenu = submenu

        // 1 Hz refresh only while there are entries. The timer fires
        // `rebuildCredentialsMenu`, which will route through the open-menu
        // branch above when appropriate.
        if entries.isEmpty {
            credentialsRefreshTimer?.invalidate()
            credentialsRefreshTimer = nil
        } else if credentialsRefreshTimer == nil {
            credentialsRefreshTimer = Timer.scheduledTimer(
                withTimeInterval: 1.0,
                repeats: true
            ) { [weak self] _ in
                Task { @MainActor in
                    let latest = AppState.shared.credentials
                    self?.rebuildCredentialsMenu(entries: latest)
                }
            }
        }
    }

    /// Build the credentials-row label `"<context>  [Xm Ys]"`.
    private func credentialRowLabel(for entry: EphemeralStore.Entry, now: Date) -> String {
        let remaining = max(0, entry.expiresAt.timeIntervalSince(now))
        let mins = Int(remaining) / 60
        let secs = Int(remaining) % 60
        let ttl = mins > 0 ? "\(mins)m \(secs)s" : "\(secs)s"
        return "\(entry.payload.context)  [\(ttl)]"
    }

    /// In-place TTL refresh while the menu is open. Walks visible items and
    /// updates titles only — does not add or remove rows. The id stamped onto
    /// each item's `representedObject` lets us match items to entries.
    private func updateOpenCredentialsMenuTTLs(entries: [EphemeralStore.Entry]) {
        guard let submenu = credentialsMenuItem?.submenu else { return }
        let now = Date()
        let entriesById: [String: EphemeralStore.Entry] = Dictionary(
            uniqueKeysWithValues: entries.map { ($0.id, $0) }
        )
        for item in submenu.items {
            guard let id = item.representedObject as? String,
                  let entry = entriesById[id] else { continue }
            item.title = credentialRowLabel(for: entry, now: now)
        }
    }

    // MARK: - NSMenuDelegate

    func menuWillOpen(_ menu: NSMenu) {
        // We installed `self` as the delegate of the credentials submenu (and
        // its placeholder). Both come through here.
        if menu === credentialsMenuItem?.submenu {
            credentialsMenuIsOpen = true
        }
    }

    func menuDidClose(_ menu: NSMenu) {
        if menu === credentialsMenuItem?.submenu {
            credentialsMenuIsOpen = false
            if credentialsPendingRebuild {
                credentialsPendingRebuild = false
                rebuildCredentialsMenu(entries: AppState.shared.credentials)
            }
        }
    }

    private func buildEntrySubmenu(entry: EphemeralStore.Entry) -> NSMenu {
        let sub = NSMenu()
        let typeItem = NSMenuItem(title: "Type: \(entry.payload.type)", action: nil, keyEquivalent: "")
        typeItem.isEnabled = false
        sub.addItem(typeItem)

        // Provenance hint per RFC §4.9.5.
        if let provider = entry.providerLabel, !provider.isEmpty {
            let prov = NSMenuItem(title: "From: \(provider)", action: nil, keyEquivalent: "")
            prov.isEnabled = false
            sub.addItem(prov)
        }
        sub.addItem(NSMenuItem.separator())

        // RFC §5: each schema produces its own list of click-to-copy rows.
        // The renderer is type-agnostic — it just walks `copyableFields()`.
        for field in entry.payload.copyableFields() {
            let title = "Copy \(field.label)  (\(field.display))"
            sub.addItem(makeCopyItem(title, value: field.copyValue))
        }

        return sub
    }

    private func makeCopyItem(_ title: String, value: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: #selector(copyCredentialField(_:)), keyEquivalent: "")
        item.target = self
        item.representedObject = value
        return item
    }

    @objc private func copyCredentialField(_ sender: NSMenuItem) {
        guard let value = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    @objc private func clearAllCredentials() {
        Task { @MainActor in
            AppState.shared.ephemeralStore.removeAll()
        }
    }

    private func updateServerStatus(isRunning: Bool) {
        if isRunning {
            serverStatusMenuItem?.title = "● Server: Running"
            serverStatusMenuItem?.attributedTitle = createColoredStatusTitle(
                "● Server: Running",
                statusColor: .systemGreen
            )
        } else {
            serverStatusMenuItem?.title = "● Server: Stopped"
            serverStatusMenuItem?.attributedTitle = createColoredStatusTitle(
                "● Server: Stopped",
                statusColor: .systemRed
            )
        }
        updateStatusBarIcon()
    }

    private func createColoredStatusTitle(_ text: String, statusColor: NSColor) -> NSAttributedString {
        let attributedString = NSMutableAttributedString(string: text)
        attributedString.addAttribute(.foregroundColor, value: statusColor,
                                      range: NSRange(location: 0, length: 1))
        return attributedString
    }

    private func updateStatusBarIcon() {
        guard let button = statusItem.button else { return }
        Task { @MainActor in
            // The icon itself is constant — running/stopped state is shown in
            // the menu via the colored ● in serverStatusMenuItem. Keeping the
            // glyph stable avoids flicker when the server flaps.
            if let img = NSImage(named: "WavePulse") {
                img.size = NSSize(width: 18, height: 18)
                img.isTemplate = true
                button.image = img
            }
            button.image?.accessibilityDescription = "BrightNexus"
        }
    }
}

// MARK: - Settings View

struct SettingsView: View {
    @StateObject private var appState = AppState.shared

    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem {
                    Label("General", systemImage: "gear")
                }

            BrightLinkSettingsView()
                .tabItem {
                    Label("BrightLink", systemImage: "key.viewfinder")
                }

            GeoEngineSettingsView()
                .tabItem {
                    Label("Geo Engine", systemImage: "location.viewfinder")
                }

            AllowlistSettingsView()
                .tabItem {
                    Label("Allowlist", systemImage: "list.bullet.rectangle")
                }

            AboutView()
                .tabItem {
                    Label("About", systemImage: "info.circle")
                }
        }
        // The Geo Engine and Allowlist tabs need more horizontal room than
        // the original 450×380; bump to 560×460.
        .frame(width: 560, height: 460)
    }
}

// MARK: - BrightLink Settings (RFC §4.9.5)

struct BrightLinkSettingsView: View {
    @State private var attestationMode: PeerAttestationMode = BrightNexusPolicy.peerAttestationMode
    @State private var ttlMinutesText: String = String(
        Int(BrightNexusPolicy.credentialTtlCeilingSeconds / 60)
    )
    @State private var ttlError: String? = nil

    var body: some View {
        Form {
            Section {
                Picker("Peer Attestation", selection: $attestationMode) {
                    Text("Log only (default)").tag(PeerAttestationMode.logOnly)
                    Text("Enforce — reject unsigned").tag(PeerAttestationMode.enforce)
                }
                .onChange(of: attestationMode) { _, newValue in
                    BrightNexusPolicy.setPeerAttestationMode(newValue)
                }
                Text(attestationMode == .logOnly
                     ? "Records the binary that delivered each credential; never blocks."
                     : "Refuses ingests from binaries that fail signature validation.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } header: {
                Text("Peer Attestation").font(.headline)
            }

            Section {
                HStack {
                    TextField("Minutes", text: $ttlMinutesText)
                        .frame(maxWidth: 120)
                        .onSubmit { applyTtlChange() }
                    Stepper("", onIncrement: { adjustTtl(by: 5) },
                                onDecrement: { adjustTtl(by: -5) })
                        .labelsHidden()
                    Spacer()
                    Button("Apply") { applyTtlChange() }
                }
                if let err = ttlError {
                    Text(err).font(.caption).foregroundColor(.red)
                }
                Text("Hard limit on each credential's lifetime in BrightNexus.\n"
                   + "Credentials with longer requested TTLs are clamped to this value.\n"
                   + "Range: 1–480 minutes (1 hour default).")
                    .font(.caption)
                    .foregroundColor(.secondary)
            } header: {
                Text("Credential TTL Ceiling").font(.headline)
            }
        }
        .padding()
    }

    private func applyTtlChange() {
        guard let minutes = Int(ttlMinutesText), minutes > 0 else {
            ttlError = "Enter a positive number of minutes."
            return
        }
        let seconds = TimeInterval(minutes * 60)
        let floorMin = Int(BrightNexusPolicy.credentialTtlCeilingFloorSeconds / 60)
        let ceilingMin = Int(BrightNexusPolicy.credentialTtlCeilingCeilingSeconds / 60)
        if minutes < floorMin || minutes > ceilingMin {
            ttlError = "Out of range; clamped to \(floorMin)–\(ceilingMin) minutes."
        } else {
            ttlError = nil
        }
        BrightNexusPolicy.setCredentialTtlCeilingSeconds(seconds)
        // Re-read so the displayed value reflects clamping.
        ttlMinutesText = String(Int(BrightNexusPolicy.credentialTtlCeilingSeconds / 60))
    }

    private func adjustTtl(by deltaMinutes: Int) {
        let current = Int(ttlMinutesText) ?? Int(BrightNexusPolicy.credentialTtlCeilingSeconds / 60)
        ttlMinutesText = String(max(1, current + deltaMinutes))
        applyTtlChange()
    }
}

struct GeneralSettingsView: View {
    @StateObject private var appState = AppState.shared
    @State private var launchAtLogin: Bool = false
    @State private var loginItemStatus: String = "Unknown"
    @State private var loginItemError: String? = nil

    var body: some View {
        Form {
            Section {
                Toggle("Launch at Login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, newValue in
                        setLoginItem(enabled: newValue)
                    }

                Text("Status: \(loginItemStatus)")
                    .font(.caption)
                    .foregroundColor(.secondary)

                if let error = loginItemError {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }

            Section("Socket Path") {
                Text(appState.socketPath)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
        }
        .padding()
        .onAppear {
            updateLoginItemState()
        }
    }

    private func updateLoginItemState() {
        if #available(macOS 13.0, *) {
            let status = SMAppService.mainApp.status
            switch status {
            case .enabled:
                loginItemStatus = "Enabled"
                launchAtLogin = true
            case .notRegistered:
                loginItemStatus = "Not Registered"
                launchAtLogin = false
            case .requiresApproval:
                loginItemStatus = "Requires Approval (check System Settings > Login Items)"
                launchAtLogin = false
            case .notFound:
                loginItemStatus = "Not Found"
                launchAtLogin = false
            @unknown default:
                loginItemStatus = "Unknown (\(status.rawValue))"
                launchAtLogin = false
            }
            NSLog("[BrightNexus] Login item status: %@", loginItemStatus)
        } else {
            loginItemStatus = "Requires macOS 13+"
        }
    }

    private func setLoginItem(enabled: Bool) {
        loginItemError = nil

        if #available(macOS 13.0, *) {
            do {
                NSLog("[BrightNexus] Setting login item enabled: %@", String(describing: enabled))
                if enabled {
                    try SMAppService.mainApp.register()
                } else {
                    try SMAppService.mainApp.unregister()
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                    updateLoginItemState()
                }
            } catch {
                NSLog("[BrightNexus] Login item error: %@", error.localizedDescription)
                loginItemError = "Failed: \(error.localizedDescription)"
                DispatchQueue.main.async {
                    updateLoginItemState()
                }
            }
        } else {
            loginItemError = "Requires macOS 13 or later"
        }
    }
}

struct AboutView: View {
    var body: some View {
        VStack(spacing: 16) {
            // Wordmark from Assets.xcassets/Wordmark.imageset. Has light/dark
            // variants baked into the asset, so the same Image() reference
            // automatically picks the correct one for the system appearance.
            // The wordmark already contains the "BrightNexus" text, so we
            // don't render a redundant Text() label below it.
            Image("Wordmark")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(maxWidth: 320, maxHeight: 80)
                .accessibilityLabel("BrightNexus")

            let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "–"
            let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "–"
            Text("Version \(version) (\(build))")
                .foregroundColor(.secondary)

            Text("Apple Secure Enclave bridge + BrightLink agent for the BrightChain stack")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)

            Link("GitHub Repository",
                 destination: URL(string: "https://github.com/Digital-Defiance/BrightNexus")!)
        }
        .padding()
    }
}
