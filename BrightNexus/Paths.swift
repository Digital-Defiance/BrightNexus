// Paths.swift
// BrightNexus
//
// Centralised filesystem layout for BrightNexus state.
//
// Architectural decision (locked, see docs/rfc-brightlink-v1.md):
//
//   ~/.brightchain/                 — umbrella vendor namespace (mode 0700)
//   ~/.brightchain/brightnexus/     — this app's per-tool state dir (mode 0700)
//   ~/.brightchain/brightnexus/brightnexus.sock                — primary EBP/1 + SDI socket
//   ~/.brightchain/brightnexus/brightnexus-<random>.geo.sock   — geo query socket (RFC §7.2)
//   ~/.brightchain/brightnexus/brightnexus.geo.path            — stable path-file pointing at the live geo socket
//   ~/.brightchain/brightnexus/ecies-privkey.bin               — secp256k1 private key (mode 0600)
//   ~/.brightchain/brightnexus/totp-config.json                — TOTP config (mode 0600)
//
// No legacy paths. The Phase 2.5 cleanup removed the `~/.enclave/` compat
// surface — there were no users to migrate.

import Foundation
import Darwin

enum BrightNexusPaths {
    static let umbrellaDirName = ".brightchain"
    static let toolDirName = "brightnexus"
    static let primarySocketFilename = "brightnexus.sock"
    static let geoPathFileFilename = "brightnexus.geo.path"
    static let eciesPrivKeyFilename = "ecies-privkey.bin"
    static let totpConfigFilename = "totp-config.json"

    // MARK: Resolved URLs

    /// `~/.brightchain/`
    static var umbrellaDir: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(umbrellaDirName, isDirectory: true)
    }

    /// `~/.brightchain/brightnexus/`
    static var toolDir: URL {
        umbrellaDir.appendingPathComponent(toolDirName, isDirectory: true)
    }

    /// `~/.brightchain/brightnexus/brightnexus.sock`
    static var primarySocket: URL {
        toolDir.appendingPathComponent(primarySocketFilename, isDirectory: false)
    }

    /// `~/.brightchain/brightnexus/brightnexus.geo.path`
    static var geoPathFile: URL {
        toolDir.appendingPathComponent(geoPathFileFilename, isDirectory: false)
    }

    /// `~/.brightchain/brightnexus/ecies-privkey.bin`
    static var eciesPrivKey: URL {
        toolDir.appendingPathComponent(eciesPrivKeyFilename, isDirectory: false)
    }

    /// `~/.brightchain/brightnexus/totp-config.json`
    static var totpConfig: URL {
        toolDir.appendingPathComponent(totpConfigFilename, isDirectory: false)
    }

    /// `~/.brightchain/brightnexus/brightnexus-<16-hex>.geo.sock`
    /// Generated fresh on each bridge startup per RFC §7.2 squat-resistance.
    static func geoSocket(randomComponent: String) -> URL {
        toolDir.appendingPathComponent("brightnexus-\(randomComponent).geo.sock", isDirectory: false)
    }

    // MARK: One-shot bootstrap

    /// Creates `~/.brightchain/` (mode 0700) and `~/.brightchain/brightnexus/`
    /// (mode 0700) if missing. Idempotent.
    ///
    /// Must be called before any subsystem reads or writes BrightNexus state.
    static func bootstrap() {
        let fm = FileManager.default

        for url in [umbrellaDir, toolDir] {
            if !fm.fileExists(atPath: url.path) {
                do {
                    try fm.createDirectory(at: url,
                                           withIntermediateDirectories: true,
                                           attributes: [.posixPermissions: 0o700])
                    NSLog("[BrightNexus] Created %@ (mode 0700)", url.path)
                } catch {
                    NSLog("[BrightNexus] WARN: failed to create %@: %@",
                          url.path, error.localizedDescription)
                }
            } else {
                _ = chmod(url.path, 0o700)
            }
        }
    }
}
