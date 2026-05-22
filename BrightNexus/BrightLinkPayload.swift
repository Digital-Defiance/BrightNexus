// BrightLinkPayload.swift
// BrightNexus
//
// Decoded plaintext shape of a BrightLink v1 payload (RFC §5).
//
// The entire payload — including the `type` and `context` schema
// identifiers — is delivered to the bridge inside the encrypted LINK_DELIVER
// frame. The LINK_DELIVER plaintext `type` and `context` fields ARE visible
// on the wire (RFC §4.6 nota bene), but the BridgeProtocolHandler treats
// them only as routing hints; the canonical schema identifier and any
// sensitive context come from the decrypted JSON body.
//
// Schema set (RFC §5):
//   §5.1  ephemeral-auth        — username/password/email
//   §5.2  db-connection         — engine/host/port/user/pass
//   §5.3  geo-context           — bidirectional location/zone payload
//   §5.4  api-token             — bearer token + header/prefix/scopes
//   §5.5  cloud-session         — AWS/GCP/Azure short-lived session
//   §5.6  ssh-credential        — SSH private-key + passphrase + host info
//   §5.7  kubeconfig-context    — kubectl context (cluster + user + ns)
//   §5.8  totp-seed             — TOTP secret; bridge computes the code on copy
//   §5.9  mtls-cert             — client cert + key for mTLS
//   §5.10 plaintext             — generic single-field carrier
//
// The body shape varies. We decode the JSON into a generic dictionary and
// expose typed accessors via `BrightLinkPayloadData`; the menu-bar renderer pattern-
// matches on the type identifier to decide which fields to surface and which
// to mask. Unknown types are decoded into `unknown` so the menu bar can still
// display a generic credential entry for integrators that define custom
// vendor-prefixed payload schemas (RFC §5 namespacing rule).

import Foundation

enum BrightLinkPayloadType {
    static let ephemeralAuth     = "ephemeral-auth"
    static let dbConnection      = "db-connection"
    static let geoContext        = "geo-context"
    static let apiToken          = "api-token"
    static let cloudSession      = "cloud-session"
    static let sshCredential     = "ssh-credential"
    static let kubeconfigContext = "kubeconfig-context"
    static let totpSeed          = "totp-seed"
    static let mtlsCert          = "mtls-cert"
    static let plaintext         = "plaintext"
}

/// A single click-to-copy menu row produced by an `BrightLinkPayload`. Each entry has
/// a label, a *display* string (which may be masked), and a *copy* string
/// (which is always the unmasked value). The menu/Dashboard renderer doesn't
/// need to know the payload's type — it just renders `[CopyableField]`.
struct CopyableField {
    /// Human-readable label, e.g. "Username", "Password", "Token".
    let label: String
    /// What to display in the menu (may differ from `copyValue` if masked).
    let display: String
    /// What to put on the pasteboard when the user clicks copy.
    let copyValue: String
    /// True if the sender or schema marks this field as secret-on-paper.
    let masked: Bool
}

/// Top-level BrightLink payload as it appears in `EphemeralStore`.
struct BrightLinkPayload {
    let type: String
    let context: String
    /// Lifetime in seconds the bridge SHOULD honor before sweeping the entry.
    let ttl: TimeInterval
    /// Issued-at, Unix seconds. Zero if the body omits `issued_at`.
    let issuedAt: TimeInterval
    /// Decoded JSON body as a dictionary. The renderer pattern-matches on
    /// `type` to interpret it.
    let body: [String: Any]

    /// Decode the JSON body and combine with the OSC-supplied routing fields.
    /// RFC §4.6 nota bene: body-side `type` / `context` win over OSC plaintext.
    static func decode(plaintext: Data, type: String, context: String) throws -> BrightLinkPayload {
        guard let raw = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            throw NSError(
                domain: "BrightLinkPayload",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "JSON body is not an object"]
            )
        }
        // The body may be the whole payload (with `type`, `context`, `ttl`,
        // `issued_at` at top level and the typed fields under `data`) or just
        // the flat fields. Accept both.
        let resolvedType = (raw["type"] as? String) ?? type
        let resolvedContext = (raw["context"] as? String) ?? context
        let ttl = (raw["ttl"] as? TimeInterval) ?? 300
        let issuedAt = (raw["issued_at"] as? TimeInterval) ?? 0
        // `data` is the canonical home for typed fields per the RFC. If absent,
        // fall back to the raw body itself (flat shape).
        let body: [String: Any]
        if let data = raw["data"] as? [String: Any] {
            body = data
        } else {
            // Strip the wrapper fields so the body only holds typed fields.
            var stripped = raw
            stripped.removeValue(forKey: "type")
            stripped.removeValue(forKey: "context")
            stripped.removeValue(forKey: "ttl")
            stripped.removeValue(forKey: "issued_at")
            body = stripped
        }
        return BrightLinkPayload(
            type: resolvedType,
            context: resolvedContext,
            ttl: ttl,
            issuedAt: issuedAt,
            body: body
        )
    }

    // MARK: - Renderable rows

    /// Build the click-to-copy rows the menu bar / Dashboard should render.
    /// The first row is always the OSC `context` (URL) for convenience.
    /// Type-specific rows follow. Unknown types fall through to a flat
    /// rendering that exposes every string field.
    func copyableFields() -> [CopyableField] {
        var rows: [CopyableField] = [
            CopyableField(label: "URL", display: context, copyValue: context, masked: false)
        ]
        switch type {
        case BrightLinkPayloadType.ephemeralAuth:
            appendString(&rows, "Username", "username", masked: false)
            appendString(&rows, "Password", "password", masked: true)
            appendString(&rows, "Email",    "email",    masked: false)
        case BrightLinkPayloadType.dbConnection:
            appendString(&rows, "Engine", "engine", masked: false)
            appendString(&rows, "Host",   "host",   masked: false)
            appendInt   (&rows, "Port",   "port")
            appendString(&rows, "User",   "user",   masked: false)
            appendString(&rows, "Pass",   "pass",   masked: true)
        case BrightLinkPayloadType.apiToken:
            appendString(&rows, "Token",  "token",  masked: true)
            appendString(&rows, "Header", "header_name", masked: false, fallbackDisplayIfNil: "Authorization")
            appendString(&rows, "Prefix", "prefix",      masked: false, fallbackDisplayIfNil: "Bearer ")
            if let scopes = body["scopes"] as? [String], !scopes.isEmpty {
                let joined = scopes.joined(separator: ", ")
                rows.append(CopyableField(label: "Scopes", display: joined, copyValue: joined, masked: false))
            }
        case BrightLinkPayloadType.cloudSession:
            appendString(&rows, "Provider",        "provider",          masked: false)
            appendString(&rows, "Region",          "region",            masked: false)
            appendString(&rows, "Access Key",      "access_key_id",     masked: false)
            appendString(&rows, "Secret",          "secret_access_key", masked: true)
            appendString(&rows, "Session Token",   "session_token",     masked: true)
        case BrightLinkPayloadType.sshCredential:
            appendString(&rows, "Host", "host", masked: false)
            appendInt   (&rows, "Port", "port")
            appendString(&rows, "User", "user", masked: false)
            appendString(&rows, "Private Key", "private_key_pem", masked: true)
            appendString(&rows, "Passphrase",  "passphrase",      masked: true)
            appendString(&rows, "known_hosts", "known_hosts_line", masked: false)
        case BrightLinkPayloadType.kubeconfigContext:
            appendString(&rows, "Server",     "server",       masked: false)
            appendString(&rows, "Cluster",    "cluster_name", masked: false)
            appendString(&rows, "Namespace",  "namespace",    masked: false, fallbackDisplayIfNil: "default")
            appendString(&rows, "User",       "user",         masked: false)
            appendString(&rows, "Token",      "token",        masked: true)
            appendString(&rows, "Client Cert","client_cert_pem", masked: false)
            appendString(&rows, "Client Key", "client_key_pem",  masked: true)
            appendString(&rows, "CA",         "ca_pem",          masked: false)
        case BrightLinkPayloadType.totpSeed:
            appendString(&rows, "Issuer",   "issuer",   masked: false)
            appendString(&rows, "Account",  "account",  masked: false)
            appendString(&rows, "Secret",   "secret_base32", masked: true)
            // Note: ideal UX is "click to copy CURRENT 6-digit code, not the
            // seed". The TOTP-code generator wiring lives in the menu-bar
            // renderer, not here. This row exposes the seed for fallback.
        case BrightLinkPayloadType.mtlsCert:
            appendString(&rows, "Endpoint",       "endpoint",       masked: false)
            appendString(&rows, "Cert",           "cert_pem",       masked: false)
            appendString(&rows, "Key",            "key_pem",        masked: true)
            appendString(&rows, "Key Passphrase", "key_passphrase", masked: true)
            appendString(&rows, "CA Bundle",      "ca_bundle_pem",  masked: false)
        case BrightLinkPayloadType.plaintext:
            // Drop the default "URL" row in favour of the type's own label —
            // plaintext payloads define exactly one click-to-copy row.
            rows.removeAll()
            let label  = (body["label"]  as? String) ?? "Value"
            let value  = (body["value"]  as? String) ?? ""
            let masked = (body["masked"] as? Bool)   ?? false
            let display = masked ? "••••••••" : value
            rows.append(CopyableField(label: label, display: display, copyValue: value, masked: masked))
        case BrightLinkPayloadType.geoContext:
            // Geo payloads aren't credentials; we don't surface them in the
            // credentials menu. Future: a dedicated geo Dashboard view.
            return []
        default:
            // Unknown / vendor-prefixed type. Render every string field at
            // top level as a non-masked row. Best-effort.
            for (k, v) in body {
                if let s = v as? String {
                    rows.append(CopyableField(label: k, display: s, copyValue: s, masked: false))
                } else if let n = v as? NSNumber {
                    let s = n.stringValue
                    rows.append(CopyableField(label: k, display: s, copyValue: s, masked: false))
                }
            }
        }
        return rows
    }

    // MARK: - Internal helpers

    private func appendString(
        _ rows: inout [CopyableField],
        _ label: String,
        _ key: String,
        masked: Bool,
        fallbackDisplayIfNil: String? = nil
    ) {
        if let v = body[key] as? String, !v.isEmpty {
            let display = masked ? "••••••••" : v
            rows.append(CopyableField(label: label, display: display, copyValue: v, masked: masked))
        } else if let fallback = fallbackDisplayIfNil {
            rows.append(CopyableField(label: label, display: fallback, copyValue: fallback, masked: false))
        }
    }

    private func appendInt(
        _ rows: inout [CopyableField],
        _ label: String,
        _ key: String
    ) {
        if let n = body[key] as? Int {
            rows.append(CopyableField(label: label, display: String(n), copyValue: String(n), masked: false))
        } else if let n = body[key] as? NSNumber {
            let s = n.stringValue
            rows.append(CopyableField(label: label, display: s, copyValue: s, masked: false))
        }
    }
}
