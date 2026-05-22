// LinkAclPromptCoordinator.swift
// BrightNexus
//
// Resolves "user has not granted this caller this scope" prompts.
// RFC §7.5 (hold-open with timeout) and §7.6 (SSH session button rules).
// Ported from test-harness/src/mock-brightnexus/promptCoordinator.ts.

import Foundation
import AppKit

// MARK: - Public types

/// Why the prompt fired (informational, surfaced in the modal subtitle).
enum PromptReason: String {
    case noMatch        = "no_match"
    case policyPrompt   = "policy_prompt"
}

/// Context passed to the coordinator on every prompt.
struct PromptRequest {
    var attestation: PeerAttestation
    var scope: LinkGeoScope
    var existingEntry: LinkAclEntry?
    /// RFC §7.5 hold-open timeout in seconds.
    var timeoutSeconds: Int
    var reason: PromptReason
}

/// Outcome of a prompt resolution.
enum PromptOutcome: Equatable {
    case allowOnce
    case allowAlways
    case allowSession(sshSessionId: String)
    case deny
    case denyAlways
    case timeout
}

/// The interface implementations satisfy.
protocol LinkAclPromptCoordinator: AnyObject {
    func prompt(request: PromptRequest) async -> PromptOutcome
}

// MARK: - NSAlertPromptCoordinator (production)

/// Production coordinator: pops a synchronous `NSAlert.runModal()` on the
/// main actor with up to four buttons depending on SSH context.
///
/// SSH session (RFC §7.6): buttons are
///   "Allow Once", "Allow For This SSH Session", "Deny", "Deny Always"
///   — explicitly NO "Allow Always" (not bound to a specific session).
///
/// Non-SSH: buttons are
///   "Allow Once", "Allow Always", "Deny", "Deny Always"
final class NSAlertPromptCoordinator: LinkAclPromptCoordinator {

    init() {}

    func prompt(request: PromptRequest) async -> PromptOutcome {
        // Race the modal against a timeout.
        return await withTaskGroup(of: PromptOutcome.self) { group in
            group.addTask { [request] in
                await Self.runModalOnMain(request: request)
            }
            group.addTask { [request] in
                let nanos = UInt64(max(0, request.timeoutSeconds)) * 1_000_000_000
                try? await Task.sleep(nanoseconds: nanos)
                // On timeout, dismiss whatever modal is up so the user can't
                // belatedly answer a request the caller has given up on.
                await MainActor.run {
                    NSApp?.modalWindow?.close()
                }
                return .timeout
            }
            // Take whichever finishes first; cancel the other.
            let outcome = await group.next() ?? .timeout
            group.cancelAll()
            return outcome
        }
    }

    @MainActor
    private static func runModalOnMain(request: PromptRequest) async -> PromptOutcome {
        // Ensure the app is foregrounded enough to show modals. BrightNexus
        // is a menu-bar / regular app; this is a no-op when it's already
        // active.
        NSApplication.shared.activate(ignoringOtherApps: true)

        let alert = NSAlert()
        alert.messageText = "BrightLink: Location Access Request"

        let isSsh = request.attestation.sshSession != nil
        let warnsUnsigned = (request.attestation.signatureValid == false)
            || (request.attestation.attestationClass == .unsigned)

        var lines: [String] = []
        lines.append("Caller: \(request.attestation.displayLabel)")
        lines.append("Scope: \(request.scope.rawValue)")
        if let path = request.attestation.executablePath {
            lines.append("Path: \(path)")
        }
        if let ssh = request.attestation.sshSession {
            lines.append("SSH session: \(ssh.sessionId)")
        }
        if warnsUnsigned {
            lines.append("⚠️ This binary is not signed.")
        }
        alert.informativeText = lines.joined(separator: "\n")
        alert.alertStyle = warnsUnsigned ? .warning : .informational

        // Buttons. NSAlert displays buttons right-to-left in the order
        // added (rightmost = first added = default). Order matches the
        // RFC §7.5 "Allow Once / Allow Always / Deny / Deny Always"
        // sequence with the SSH-session swap from §7.6.
        if isSsh {
            alert.addButton(withTitle: "Allow Once")
            alert.addButton(withTitle: "Allow For This SSH Session")
            alert.addButton(withTitle: "Deny")
            alert.addButton(withTitle: "Deny Always")
        } else {
            alert.addButton(withTitle: "Allow Once")
            alert.addButton(withTitle: "Allow Always")
            alert.addButton(withTitle: "Deny")
            alert.addButton(withTitle: "Deny Always")
        }

        let response = alert.runModal()
        // The button responses are .alertFirstButtonReturn (rightmost) ..
        // .alertFourthButtonReturn.
        switch response {
        case .alertFirstButtonReturn:
            return .allowOnce
        case .alertSecondButtonReturn:
            if isSsh {
                let sid = request.attestation.sshSession?.sessionId ?? ""
                return .allowSession(sshSessionId: sid)
            }
            return .allowAlways
        case .alertThirdButtonReturn:
            return .deny
        default:
            // .alertFourthButtonReturn or any other (e.g. window closed by
            // timeout-induced close).
            // If the window was closed via NSApp.modalWindow.close() the
            // runModal call returns .stop / .abort. Treat anything we
            // didn't explicitly map as a deny-once-equivalent timeout.
            // The timeout race is what wins in that case anyway.
            return .denyAlways
        }
    }
}

// MARK: - MockPromptCoordinator (debugging)

/// Scripted coordinator for local debugging and unit tests. Each call to
/// `prompt(request:)` consumes the next outcome from the queue. If empty,
/// returns the configured default (initial: `.timeout`).
final class MockPromptCoordinator: LinkAclPromptCoordinator {
    private var queue: [PromptOutcome] = []
    private var defaultOutcome: PromptOutcome = .timeout
    private(set) var seen: [PromptRequest] = []
    private let lock = NSLock()

    @discardableResult
    func setDefault(_ outcome: PromptOutcome) -> MockPromptCoordinator {
        lock.lock(); defer { lock.unlock() }
        defaultOutcome = outcome
        return self
    }

    @discardableResult
    func push(_ outcome: PromptOutcome) -> MockPromptCoordinator {
        lock.lock(); defer { lock.unlock() }
        queue.append(outcome)
        return self
    }

    func promptsFired() -> [PromptRequest] {
        lock.lock(); defer { lock.unlock() }
        return seen
    }

    func prompt(request: PromptRequest) async -> PromptOutcome {
        lock.lock()
        seen.append(request)
        let next: PromptOutcome
        if queue.isEmpty {
            next = defaultOutcome
        } else {
            next = queue.removeFirst()
        }
        lock.unlock()
        return next
    }
}

// MARK: - Helpers

/// Map a prompt outcome to the per-scope ACL policy to persist (where
/// applicable). Used by `LinkGeoEngine` to update `geo-acl.json`.
func linkPromptOutcomeToPolicy(_ outcome: PromptOutcome) -> LinkGeoPolicy? {
    switch outcome {
    case .allowAlways:                 return .always
    case .allowSession:                return .always
    case .denyAlways:                  return .deny
    case .allowOnce, .deny, .timeout:  return nil
    }
}
