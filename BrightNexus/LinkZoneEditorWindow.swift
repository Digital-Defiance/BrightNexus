// LinkZoneEditorWindow.swift
// BrightNexus
//
// macOS-native resizable window wrapper around ZoneEditorSheet.
//
// SwiftUI sheets on macOS Tahoe don't expose a drag handle for resize
// out of the box; .frame(minWidth:idealWidth:) just clamps initial
// size, not user-driven resize. The user-friendly fix is to host the
// editor in a real NSWindow with [.titled, .closable, .resizable,
// .miniaturizable] so it gets a titlebar with traffic lights and
// native resize on every edge.
//
// The window is a singleton that opens for either a "new" editor
// session or to edit an existing zone. Closing without saving
// behaves the same as the sheet's Cancel button.

import AppKit
import SwiftUI

@MainActor
final class ZoneEditorWindowController {
    static let shared = ZoneEditorWindowController()

    private var window: NSWindow?
    private var hosting: NSHostingController<ZoneEditorSheet>?

    private init() {}

    func show(target: ZonesSettingsView.ZoneEditorTarget,
              onSave: @escaping (ZoneDefinition) -> Void) {
        // Build the SwiftUI body. We wire onCancel to close the window.
        let view = ZoneEditorSheet(
            target: target,
            onSave: { [weak self] zone in
                onSave(zone)
                self?.close()
            },
            onCancel: { [weak self] in
                self?.close()
            }
        )

        if let existing = window, let hc = hosting {
            // Reuse the existing window for a fresh session.
            hc.rootView = view
            existing.title = target.windowTitle
            existing.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }

        let hc = NSHostingController(rootView: view)
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 720, height: 600),
            styleMask: [.titled, .closable, .resizable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        win.title = target.windowTitle
        win.contentViewController = hc
        win.center()
        win.isReleasedWhenClosed = false
        win.minSize = NSSize(width: 560, height: 520)

        self.window = win
        self.hosting = hc
        win.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func close() {
        window?.close()
    }
}

private extension ZonesSettingsView.ZoneEditorTarget {
    var windowTitle: String {
        switch self {
        case .new:               return "New Zone"
        case .existing(let z):   return "Edit Zone — \(z.displayName)"
        }
    }
}
