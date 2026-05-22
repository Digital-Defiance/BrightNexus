// BridgeProtocolHandler.swift
// BrightNexus
//
// EBP/1 command dispatch (HEARTBEAT, GET_PUBLIC_KEY, ENCLAVE_DECRYPT, …) plus
// the BrightLink v1 command surface (LINK_REGISTER, LINK_DELIVER, LINK_PUSH,
// LINK_GEO_*, LINK_AUDIT_EMIT). LINK_REGISTER and LINK_DELIVER are implemented;
// the remainder are reserved stubs that return "not implemented in this build"
// so v1-aware clients can detect a BrightLink-aware bridge that hasn't shipped
// the rest of the surface yet. See docs/rfc-brightlink.md.

import Foundation
import CryptoKit

class BridgeProtocolHandler {
    // Per-connection peer key cache (EBP/1 §4.7). Set by SET_PEER_PUBLIC_KEY,
    // surfaced via STATUS.peerPublicKeySet.
    private var peerPublicKey: Data?

    /// Per-connection BrightLink session bound by LINK_REGISTER (RFC §4.5).
    /// Re-issuing LINK_REGISTER on the same connection invalidates the prior
    /// session per RFC §4.3.
    private var brightLinkSession: BrightLinkSession.Record?

    /// Connecting-peer attestation captured by SocketServer at accept() time
    /// (RFC §4.9.5). nil for connections that pre-date attestation wiring
    /// (e.g. unit tests using a directly-constructed handler).
    let peerAttestation: PeerAttestation?

    /// Per-connection rate limiter for LINK_DELIVER + LINK_PUSH failures
    /// (RFC §4.4). Reset on session re-registration.
    private let deliverFailureLimiter = DeliverRateLimiter(threshold: 30, windowSeconds: 60)

    private static let startTime = Date()

    init(peerAttestation: PeerAttestation? = nil) {
        self.peerAttestation = peerAttestation
    }

    deinit {
        // Wipe the session key on connection close. Credentials are NOT
        // evicted here — they live until their own TTL expires regardless
        // of connection state. Rationale: the `ttl` field on each payload
        // is the user-visible promise; a transient disconnect of the
        // injecting process should not invalidate it. The `EphemeralStore`
        // sweeper handles expiry on its own clock.
        brightLinkSession?.wipe()
    }

    /// Identity string returned in HEARTBEAT/METRICS for backward compatibility with
    /// EBP/1 clients that pin on `service == "enclave-bridge"`. New v3-aware clients
    /// SHOULD instead inspect VERSION's `app` field, which is `"brightnexus"`.
    private static let legacyServiceName = "enclave-bridge"

    /// New canonical app identity surfaced in VERSION/INFO.
    private static let appName = "brightnexus"

    /// Handle one inbound JSON request and return the JSON response bytes.
    func handleMessage(_ data: Data) -> Data {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let cmd = json["cmd"] as? String else {
            return BridgeProtocolHandler.errorResponse("Invalid request format")
        }
        switch cmd {

        // MARK: - EBP/1 core surface

        case "ENABLE_TOTP":
            guard let keyId = json["keyId"] as? String,
                  let account = json["account"] as? String,
                  let issuer = json["issuer"] as? String else {
                return BridgeProtocolHandler.errorResponse("Missing keyId, account, or issuer")
            }
            // Cross-actor hop: AppState is @MainActor.
            let result = MainActorSync.run { AppState.shared.enableTOTP(forKeyId: keyId, account: account, issuer: issuer) }
            if let uri = result {
                return BridgeProtocolHandler.jsonResponse(["provisioningURI": uri])
            } else {
                return BridgeProtocolHandler.errorResponse("Failed to enable TOTP for key")
            }

        case "EXPORT_KEY":
            guard let keyId = json["keyId"] as? String else {
                return BridgeProtocolHandler.errorResponse("Missing keyId")
            }
            let totpCode = json["totpCode"] as? String
            let valid = MainActorSync.run { AppState.shared.validateTOTP(forKeyId: keyId, code: totpCode) }
            if !valid {
                return BridgeProtocolHandler.errorResponse("TOTP code required or invalid for this key")
            }
            if keyId == "ecies-secp256k1" {
                do {
                    let pubKey = try ECIESKeyManager.getOrCreateSecp256k1PublicKey()
                    return BridgeProtocolHandler.jsonResponse(["publicKey": pubKey.base64EncodedString()])
                } catch {
                    return BridgeProtocolHandler.errorResponse(
                        "Failed to export ECIES public key: \(error.localizedDescription)")
                }
            } else if keyId == "secure-enclave-p256" {
                do {
                    let pubKey = try SecureEnclaveKeyManager.getPublicKeyData()
                    return BridgeProtocolHandler.jsonResponse(["publicKey": pubKey.base64EncodedString()])
                } catch {
                    return BridgeProtocolHandler.errorResponse(
                        "Failed to export Secure Enclave public key: \(error.localizedDescription)")
                }
            } else {
                return BridgeProtocolHandler.errorResponse("Unknown keyId")
            }

        case "HEARTBEAT":
            let timestamp = ISO8601DateFormatter().string(from: Date())
            return BridgeProtocolHandler.jsonResponse([
                "ok": true,
                "timestamp": timestamp,
                // Legacy identity preserved for EBP/1 clients.
                "service": Self.legacyServiceName
            ])

        case "VERSION", "INFO":
            let dict: [String: Any] = [
                "appVersion": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
                "build": Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "unknown",
                "platform": "macOS",
                "uptimeSeconds": Int(Date().timeIntervalSince(Self.startTime)),
                // New: canonical app name. v3-aware clients pin on this; EBP/1 clients
                // ignore unknown fields per EBP/1 §13.
                "app": Self.appName,
                // BrightLink protocol version supported. LINK_REGISTER and
                // LINK_DELIVER are implemented as of this build;
                // LINK_PUSH, LINK_GEO_*, and LINK_AUDIT_EMIT are still
                // reserved (return "not implemented in this build"). v1-aware
                // clients see this and know to use the BrightLink surface.
                "brightlinkProtocolVersion": 1
            ]
            return BridgeProtocolHandler.jsonResponse(dict)

        case "STATUS":
            let enclaveAvailable: Bool
            do {
                _ = try SecureEnclaveKeyManager.getPublicKeyData()
                enclaveAvailable = true
            } catch {
                enclaveAvailable = false
            }
            let dict: [String: Any] = [
                "ok": true,
                "peerPublicKeySet": peerPublicKey != nil,
                "enclaveKeyAvailable": enclaveAvailable
            ]
            return BridgeProtocolHandler.jsonResponse(dict)

        case "METRICS":
            let dict: [String: Any] = [
                "uptimeSeconds": Int(Date().timeIntervalSince(Self.startTime)),
                "service": Self.legacyServiceName,
                "requestCounters": [:]  // TODO: hook into real counters once available
            ]
            return BridgeProtocolHandler.jsonResponse(dict)

        case "GET_PUBLIC_KEY":
            do {
                let pubKey = try ECIESKeyManager.getOrCreateSecp256k1PublicKey()
                return BridgeProtocolHandler.jsonResponse(["publicKey": pubKey.base64EncodedString()])
            } catch {
                return BridgeProtocolHandler.errorResponse(
                    "Failed to get ECIES public key: \(error.localizedDescription)")
            }

        case "GET_ENCLAVE_PUBLIC_KEY":
            do {
                let pubKey = try SecureEnclaveKeyManager.getPublicKeyData()
                return BridgeProtocolHandler.jsonResponse(["publicKey": pubKey.base64EncodedString()])
            } catch {
                return BridgeProtocolHandler.errorResponse(
                    "Failed to get Secure Enclave public key: \(error.localizedDescription)")
            }

        case "SET_PEER_PUBLIC_KEY":
            if let keyStr = json["publicKey"] as? String, let keyData = Data(base64Encoded: keyStr) {
                peerPublicKey = keyData
                return BridgeProtocolHandler.jsonResponse(["ok": true])
            } else {
                return BridgeProtocolHandler.errorResponse("Missing or invalid publicKey")
            }

        case "LIST_KEYS":
            let keysDict: [[String: Any]] = MainActorSync.run {
                AppState.shared.keys.map { key in
                    [
                        "id": key.id,
                        "type": key.type.rawValue,
                        "publicKeyFingerprint": key.publicKeyFingerprint,
                        "isSecureEnclave": key.isSecureEnclave,
                        "totpEnabled": key.totpSecret != nil,
                        "totpProvisioningURI": key.totpProvisioningURI ?? ""
                    ]
                }
            }
            return BridgeProtocolHandler.jsonResponse(["keys": keysDict])

        case "ENCLAVE_SIGN":
            guard let dataStr = json["data"] as? String, let dataToSign = Data(base64Encoded: dataStr) else {
                return BridgeProtocolHandler.errorResponse("Missing or invalid data to sign")
            }
            do {
                let signature = try SecureEnclaveKeyManager.sign(data: dataToSign)
                return BridgeProtocolHandler.jsonResponse(["signature": signature.base64EncodedString()])
            } catch {
                return BridgeProtocolHandler.errorResponse(
                    "Signing failed: \(error.localizedDescription)")
            }

        case "ENCLAVE_DECRYPT":
            guard let dataStr = json["data"] as? String,
                  let encryptedData = Data(base64Encoded: dataStr) else {
                return BridgeProtocolHandler.errorResponse("Missing or invalid data to decrypt")
            }
            return decryptEnvelope(encryptedData)

        case "ENCLAVE_GENERATE_KEY":
            // Reserved by EBP/1 §4.11. Keys are auto-created on first use.
            return BridgeProtocolHandler.errorResponse("ENCLAVE_GENERATE_KEY not implemented")

        case "ENCLAVE_ROTATE_KEY":
            // Reserved by EBP/1 §4.12.
            return BridgeProtocolHandler.errorResponse("ENCLAVE_ROTATE_KEY not supported on this platform")

        // MARK: - BrightLink v1 command surface (RFC §4.5–4.7, §8)
        //
        // LINK_REGISTER and LINK_DELIVER are implemented. The remainder are reserved
        // stubs so a v1-aware client can detect it is talking to a BrightLink-aware
        // BrightNexus that hasn't shipped them yet. The error string is stable:
        // clients can match on the suffix `"not implemented in this build"` to
        // distinguish a v1-aware bridge from one that returns the EBP/1 generic
        // `"Unknown command: <cmd>"`.

        case "LINK_REGISTER":
            return handleLinkRegister(json)

        case "LINK_DELIVER":
            return handleLinkDeliver(json)

        case "LINK_PUSH":
            // TODO Wave 4h: real push needs per-connection AAD-sealed
            // frame emission and the engine zone-transition subscription.
            // The engine surface (`onZoneTransition`) is wired but never
            // fires today (NullGeoSource never emits fixes).
            return BridgeProtocolHandler.errorResponse("LINK_PUSH not implemented in this build")

        case "LINK_GEO_STATUS":
            return handleLinkGeoStatus(json)

        case "LINK_GEO_PROXIMITY":
            return handleLinkGeoProximity(json)

        case "LINK_GEO_ZONE":
            return handleLinkGeoZone(json)

        case "LINK_GEO_GET":
            return handleLinkGeoGet(json)

        case "LINK_GEO_REFRESH":
            return handleLinkGeoRefresh(json)

        case "LINK_AUDIT_EMIT":
            // TODO Wave 4h: agent-emitted audit events flow through the
            // engine's audit sink alongside bridge-emitted entries.
            return BridgeProtocolHandler.errorResponse("LINK_AUDIT_EMIT not implemented in this build")

        default:
            return BridgeProtocolHandler.errorResponse("Unknown command: \(cmd)")
        }
    }

    // MARK: - LINK_REGISTER handler (RFC §4.5)

    /// Implements the `LINK_REGISTER` command. The flow is:
    ///
    ///   1. Validate request shape: `protocolVersion=1`, base64 `clientNonce` of
    ///      16 bytes, base64 `envelope`.
    ///   2. ECIES-decrypt `envelope` with the bridge's persistent secp256k1 key
    ///      to recover the §4.5.1 plaintext (JSON containing `clientPub`,
    ///      `clientShare`, `issuedAtBd`, `ttlSeconds`, `agent`).
    ///   3. Validate `issuedAtBd` is not more than 60s in the future.
    ///   4. Cap `ttlSeconds` at BrightLinkSession.maxTtlSeconds.
    ///   5. Generate `bridgeShare` (32 random bytes) and `sessionId` (16 random bytes).
    ///   6. Derive K_session via the bilateral HKDF.
    ///   7. Build the canonical 238-byte transcript and sign with the SEP P-256 key.
    ///   8. ECIES-encrypt `bridgeShare` to the client's `clientPub`.
    ///   9. Bind the session to this connection. Return the response envelope.
    private func handleLinkRegister(_ json: [String: Any]) -> Data {
        // 1. Protocol version check.
        guard let pv = json["protocolVersion"] as? Int, pv == 1 else {
            return BridgeProtocolHandler.errorResponse("Unsupported BrightLink protocol version")
        }

        // 1b. clientNonce.
        guard
            let clientNonceB64 = json["clientNonce"] as? String,
            let clientNonce = Data(base64Encoded: clientNonceB64),
            clientNonce.count == BrightLinkSession.clientNonceLength
        else {
            return BridgeProtocolHandler.errorResponse("Missing clientNonce")
        }

        // 1c. envelope.
        guard
            let envelopeB64 = json["envelope"] as? String,
            let envelope = Data(base64Encoded: envelopeB64)
        else {
            return BridgeProtocolHandler.errorResponse("Missing envelope")
        }

        // 2. ECIES-decrypt the envelope using ENCLAVE_DECRYPT's existing path.
        // We reuse `decryptEnvelope` rather than reimplementing the parser so
        // any envelope-shape bug shows up consistently across both EBP/1 and
        // LINK_REGISTER paths.
        let decryptResp = decryptEnvelope(envelope)
        guard
            let decryptJson = try? JSONSerialization.jsonObject(with: decryptResp) as? [String: Any],
            let plaintextB64 = decryptJson["plaintext"] as? String,
            let plaintext = Data(base64Encoded: plaintextB64)
        else {
            // Whatever decryptEnvelope returned (with its own error string) is
            // not what we want for LINK_REGISTER. Per RFC §4.5.6 we surface
            // `Decryption failed` for any envelope decode/AEAD failure.
            return BridgeProtocolHandler.errorResponse("Decryption failed")
        }

        // 3. Parse the §4.5.1 plaintext.
        let parsed: BrightLinkSession.RegisterPlaintext
        do {
            parsed = try BrightLinkSession.parseRegisterPlaintext(plaintext)
        } catch {
            return BridgeProtocolHandler.errorResponse("Invalid envelope plaintext")
        }
        guard parsed.v == 1 else {
            return BridgeProtocolHandler.errorResponse("Invalid envelope plaintext")
        }

        // 4. Clock-skew check.
        let nowUnix = Int(Date().timeIntervalSince1970)
        let issuedAtUnix = Int((parsed.issuedAtBd * 86400.0).rounded())
        if Double(issuedAtUnix - nowUnix) > BrightLinkSession.registrationFutureSkewToleranceSeconds {
            return BridgeProtocolHandler.errorResponse("Stale registration")
        }

        // 5. Cap TTL.
        let grantedTtl = max(0, min(parsed.ttlSeconds, BrightLinkSession.maxTtlSeconds))

        // 6. Generate bridge-side randomness. `bridgeShare` is half of the
        //    IKM that derives K_session; zero it after we're done with it
        //    so the only secret the bridge holds long-term is K_session
        //    itself (RFC §4.9.6 memory hygiene).
        var bridgeShare = Data(count: BrightLinkSession.shareLength)
        var sessionId = Data(count: BrightLinkSession.sessionIdLength)
        defer {
            // Best-effort overwrite of the locally-held secret. Note: Data's
            // copy-on-write semantics mean any aliased copy may have already
            // been retained; we accept that as a residual issue documented
            // in §4.9.6.
            bridgeShare.resetBytes(in: 0..<bridgeShare.count)
        }
        let r1 = bridgeShare.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, BrightLinkSession.shareLength, $0.baseAddress!)
        }
        let r2 = sessionId.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, BrightLinkSession.sessionIdLength, $0.baseAddress!)
        }
        guard r1 == errSecSuccess, r2 == errSecSuccess else {
            return BridgeProtocolHandler.errorResponse(
                "internal: bridge RNG failed during LINK_REGISTER"
            )
        }

        // 7. Derive K_session via the bilateral HKDF.
        let sessionKey: SymmetricKey
        do {
            sessionKey = try BrightLinkSession.deriveSessionKey(
                clientShare: parsed.clientShare,
                bridgeShare: bridgeShare,
                clientNonce: clientNonce,
                sessionId: sessionId
            )
        } catch {
            return BridgeProtocolHandler.errorResponse(
                "internal: K_session derivation failed: \(error)"
            )
        }

        // 8. Build the canonical transcript and sign with the SEP key.
        let transcript: Data
        do {
            transcript = try BrightLinkSession.buildTranscript(
                clientNonce: clientNonce,
                clientPub: parsed.clientPub,
                clientShare: parsed.clientShare,
                sessionId: sessionId,
                bridgeShare: bridgeShare,
                issuedAtBd: parsed.issuedAtBd,
                bridgeIssuedAtUnix: nowUnix,
                ttlSeconds: grantedTtl
            )
        } catch {
            return BridgeProtocolHandler.errorResponse(
                "internal: transcript construction failed: \(error)"
            )
        }
        let transcriptSig: Data
        do {
            transcriptSig = try SecureEnclaveKeyManager.sign(data: transcript)
        } catch {
            return BridgeProtocolHandler.errorResponse(
                "internal: SEP transcript sign failed: \(error.localizedDescription)"
            )
        }

        // 9. Encrypt bridgeShare back to the client's ephemeral public key.
        let responseEnvelope: Data
        do {
            responseEnvelope = try ECIES.encryptBasicEnvelope(
                plaintext: bridgeShare,
                recipientPubUncompressed: parsed.clientPub
            )
        } catch {
            return BridgeProtocolHandler.errorResponse(
                "internal: response envelope encryption failed: \(error.localizedDescription)"
            )
        }

        // 10. Bind session to this connection. Re-registration on the same
        //     connection wipes the prior session per RFC §4.3 and resets the
        //     per-session rate limiter.
        if let prior = brightLinkSession {
            prior.wipe()
        }
        deliverFailureLimiter.reset()
        brightLinkSession = BrightLinkSession.Record(
            sessionId: sessionId,
            sessionKey: sessionKey,
            bridgeIssuedAtUnix: nowUnix,
            ttlSeconds: grantedTtl,
            agentName: parsed.agentName,
            agentVersion: parsed.agentVersion,
            agentPlatform: parsed.agentPlatform
        )

        // 11. Return the response per RFC §4.5.3.
        return BridgeProtocolHandler.jsonResponse([
            "ok": true,
            "sessionId": sessionId.base64EncodedString(),
            "bridgeIssuedAtUnix": nowUnix,
            "ttlSeconds": grantedTtl,
            "responseEnvelope": responseEnvelope.base64EncodedString(),
            "transcriptSig": transcriptSig.base64EncodedString()
        ])
    }

    // MARK: - LINK_DELIVER handler (RFC §4.9)
    //
    // BrightLink v1's Shell → Agent credential delivery path. The client
    // sends a JSON request:
    //
    //   {
    //     "cmd":        "LINK_DELIVER",
    //     "counter":    7,
    //     "type":       "ephemeral-auth",
    //     "context":    "http://localhost:3005",
    //     "iv":         "<base64 12 bytes>",
    //     "ciphertext": "<base64>",
    //     "authTag":    "<base64 16 bytes>"
    //   }
    //
    // The bridge:
    //
    //   1. Verifies a session is bound to this connection.
    //   2. Reads `counter` and applies the §4.6.4 replay window.
    //   3. Reconstructs AAD from (`dir_tag = 0x01`, counter, type, context)
    //      using the §4.6.3 length-prefixed encoding.
    //   4. AES-256-GCM-opens the ciphertext under K_session with that AAD.
    //   5. Decodes the JSON body as an `BrightLinkPayload` (§5).
    //   6. Drops the entry into `AppState.shared.ephemeralStore`, which
    //      auto-expires it per the resolved (post-clamp) TTL.
    //   7. Returns `{ok:true, type, context}` so the client can confirm
    //      delivery.
    //
    // Replay protection: counters MUST be strictly greater than
    // `lastInboundCounter` and within `replayWindow` of it.
    private func handleLinkDeliver(_ json: [String: Any]) -> Data {
        // 1. Session bound?
        guard let session = brightLinkSession else {
            return BridgeProtocolHandler.errorResponse(
                "Session not registered on this connection"
            )
        }
        let nowUnix = Int(Date().timeIntervalSince1970)
        if nowUnix > session.expiresAtUnix {
            return BridgeProtocolHandler.errorResponse("Session expired")
        }

        // 2. Peer-attestation enforce mode (RFC §4.9.5).
        if BrightNexusPolicy.peerAttestationMode == .enforce {
            let isAttestedAndValid =
                (peerAttestation?.signatureValid ?? false) &&
                (peerAttestation?.codeSigningIdentity != nil)
            if !isAttestedAndValid {
                _ = self.recordDeliverFailureAndMaybeTearDown()
                return BridgeProtocolHandler.errorResponse("Peer attestation failed")
            }
        }

        // 3. Parse the JSON wire fields.
        guard let counterRaw = (json["counter"] as? NSNumber)?.uint64Value else {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse("Missing counter")
        }
        guard let type = json["type"] as? String else {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse("Missing type")
        }
        guard let contextStr = json["context"] as? String else {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse("Missing context")
        }
        guard let ivB64 = json["iv"] as? String,
              let ctB64 = json["ciphertext"] as? String,
              let tagB64 = json["authTag"] as? String else {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse("Missing iv/ciphertext/authTag")
        }
        guard let iv = Data(base64Encoded: ivB64),
              let ct = Data(base64Encoded: ctB64),
              let tag = Data(base64Encoded: tagB64) else {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse("iv/ciphertext/authTag not base64")
        }
        if iv.count != BrightLinkSession.gcmIvLength {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse(
                "iv must be \(BrightLinkSession.gcmIvLength) bytes"
            )
        }
        if tag.count != BrightLinkSession.gcmTagLength {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse(
                "authTag must be \(BrightLinkSession.gcmTagLength) bytes"
            )
        }

        // 4. Replay window (RFC §4.6.4).
        if counterRaw <= session.lastInboundCounter {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse("Counter replayed")
        }
        if counterRaw > session.lastInboundCounter + UInt64(BrightLinkSession.replayWindow) {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse("Counter out of replay window")
        }

        // 5. Reconstruct AAD with the receiver's direction tag (0x01).
        let aad = BrightLinkSession.buildDeliverAad(
            direction: .shellToAgent,
            counter: counterRaw,
            type: type,
            contextBytes: Data(contextStr.utf8)
        )

        // 6. AES-256-GCM open.
        let plaintext: Data
        do {
            let nonce = try AES.GCM.Nonce(data: iv)
            let sealed = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
            plaintext = try AES.GCM.open(sealed, using: session.sessionKey, authenticating: aad)
        } catch {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse("AES-GCM authentication failed")
        }

        // 7. Decode the payload body.
        let payload: BrightLinkPayload
        do {
            payload = try BrightLinkPayload.decode(
                plaintext: plaintext,
                type: type,
                context: contextStr
            )
        } catch {
            _ = self.recordDeliverFailureAndMaybeTearDown()
            return BridgeProtocolHandler.errorResponse(
                "Invalid payload body: \(error.localizedDescription)"
            )
        }

        // 8. RFC §4.9.5 TTL clamp.
        let ttlCeiling = BrightNexusPolicy.credentialTtlCeilingSeconds
        let requestedTtl = payload.ttl > 0 ? payload.ttl : 300
        let resolvedTtl = min(requestedTtl, ttlCeiling)
        let resolvedExpiresAt = Date().addingTimeInterval(resolvedTtl)

        // 9. Counter advance + store.
        session.lastInboundCounter = counterRaw
        let sessionIdHex = session.sessionId.map { String(format: "%02x", $0) }.joined()
        let providerLabel = peerAttestation?.displayLabel
        AppState.shared.ephemeralStore.insert(
            payload: payload,
            sessionIdHex: sessionIdHex,
            providerLabel: providerLabel,
            expiresAt: resolvedExpiresAt
        )

        return BridgeProtocolHandler.jsonResponse([
            "ok": true,
            "type": payload.type,
            "context": payload.context
        ])
    }

    /// Record one LINK_DELIVER failure against the per-session §4.4 limiter.
    /// If the threshold is breached, tear down the session and return true.
    @discardableResult
    private func recordDeliverFailureAndMaybeTearDown() -> Bool {
        let breached = deliverFailureLimiter.recordFailure()
        if breached {
            brightLinkSession?.wipe()
            brightLinkSession = nil
        }
        return breached
    }

    // MARK: - ENCLAVE_DECRYPT helper
    //
    // Implements the wire format expected by `@digitaldefiance/node-ecies-lib`:
    //   version(1) || cipherSuite(1) || type(1) || ephemeralPub(33|65)
    //                              || iv(12) || tag(16) || [length(8)] || ciphertext
    // The 16-byte-IV helper that previously lived in this file (for hypothetical
    // server-originated outputs) was removed during the BrightNexus rename — see
    // RFC v3 §5.2: only 12-byte IVs are conformant to the canonical ecies-lib v4 wire format.

    private func decryptEnvelope(_ encryptedData: Data) -> Data {
        let ivSize = 12
        let tagSize = 16
        // Minimum: 1+1+1+33+12+16 = 64 bytes for compressed ephemeral key.
        let minHeaderCompressed = 1 + 1 + 1 + 33 + ivSize + tagSize
        guard encryptedData.count > minHeaderCompressed else {
            return BridgeProtocolHandler.errorResponse("Encrypted data too short")
        }

        var offset = 0
        let version = encryptedData[offset]; offset += 1
        let cipherSuite = encryptedData[offset]; offset += 1
        let encType = encryptedData[offset]; offset += 1

        // Ephemeral key length: 33 (compressed) — strictly. RFC v3 §15
        // (Compatibility posture) says BrightNexus opts out of the DD-ECIES
        // §5.3 65/64-byte tolerance on all decode paths. A non-conformant
        // sender that emits 0x04-prefixed (uncompressed) or raw bytes is
        // rejected immediately rather than allowed to flow into a misshapen
        // ECDH that fails later with a misleading `Decryption failed`.
        let ephemeralPubLen = 33
        guard encryptedData[offset] == 0x02 || encryptedData[offset] == 0x03 else {
            return BridgeProtocolHandler.errorResponse("Invalid ephemeral public key format")
        }
        guard encryptedData.count >= offset + ephemeralPubLen else {
            return BridgeProtocolHandler.errorResponse("Encrypted data too short")
        }
        let ephemeralPub = encryptedData.subdata(in: offset..<(offset + ephemeralPubLen))
        offset += ephemeralPubLen
        let iv = encryptedData.subdata(in: offset..<(offset + ivSize)); offset += ivSize
        let tag = encryptedData.subdata(in: offset..<(offset + tagSize)); offset += tagSize

        let ciphertext: Data
        // WithLength type byte = 0x42 (66 decimal).
        if encType == 66 {
            guard encryptedData.count >= offset + 8 else {
                return BridgeProtocolHandler.errorResponse("Missing length field")
            }
            let lengthData = encryptedData.subdata(in: offset..<(offset + 8))
            offset += 8
            let length = lengthData.withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
            guard encryptedData.count >= offset + Int(length) else {
                return BridgeProtocolHandler.errorResponse("Ciphertext length mismatch")
            }
            ciphertext = encryptedData.subdata(in: offset..<(offset + Int(length)))
        } else {
            ciphertext = encryptedData.suffix(from: offset)
        }

        // AAD per RFC §5.5: version || cipherSuite || type || ephemeralPub
        let aad = Data([version, cipherSuite, encType]) + ephemeralPub

        do {
            let privKey = try ECIESKeyManager.getOrCreateSecp256k1PrivateKeyObject()
            let sharedSecret = ECIES.computeSharedSecret(privateKey: privKey,
                                                        peerPublicKey: ephemeralPub)
            if sharedSecret.isEmpty {
                return BridgeProtocolHandler.errorResponse("ECDH failed: empty shared secret")
            }
            let symKey = ECIES.deriveSymmetricKey(sharedSecret: sharedSecret)
            guard let plaintext = ECIES.decrypt(ciphertext: ciphertext, tag: tag,
                                                symmetricKey: symKey, iv: iv, aad: aad) else {
                return BridgeProtocolHandler.errorResponse("Decryption failed")
            }
            return BridgeProtocolHandler.jsonResponse(["plaintext": plaintext.base64EncodedString()])
        } catch {
            return BridgeProtocolHandler.errorResponse("ECDH failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Response helpers

    static func jsonResponse(_ dict: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: dict)) ?? Data()
    }

    static func errorResponse(_ message: String) -> Data {
        jsonResponse(["error": message])
    }
}

// MARK: - MainActor sync helper
//
// `BridgeProtocolHandler.handleMessage` is invoked from background dispatch queues
// in `SocketServer`, but `AppState` is `@MainActor`-isolated. This helper synchronously
// hops to the main actor for the rare cross-actor reads we need on the request path
// (LIST_KEYS, ENABLE_TOTP, EXPORT_KEY's TOTP validation). All other AppState mutations
// happen via `Task { @MainActor in … }` because they are fire-and-forget UI updates.

enum MainActorSync {
    static func run<T>(_ body: @MainActor () -> T) -> T {
        if Thread.isMainThread {
            return MainActor.assumeIsolated { body() }
        }
        return DispatchQueue.main.sync { MainActor.assumeIsolated { body() } }
    }
}

// MARK: - LINK_GEO_* dispatch (Wave 4g wiring)
//
// The dispatcher is currently synchronous but `LinkGeoEngine` is async.
// Approach A (locked, see Wave 4g spec): bridge async↔sync with a
// detached Task + DispatchSemaphore. NOT ideal long-term — making
// `handleMessage` truly async is a Wave 4i+ goal.
// TODO Wave 4i: gate LINK_GEO_* on session-registered (RFC §9 requires
// a bound session). Currently we skip the gate so probe scripts that
// don't pre-register can drive the engine.

private func awaitAsync<T>(_ op: @escaping @Sendable () async -> T) -> T {
    let sem = DispatchSemaphore(value: 0)
    let box = AwaitAsyncBox<T>()
    Task.detached {
        let result = await op()
        box.set(result)
        sem.signal()
    }
    sem.wait()
    return box.get()!
}

// Reference-typed box so we can write from inside the detached task and
// read from the calling thread without Swift complaining about capture.
private final class AwaitAsyncBox<T>: @unchecked Sendable {
    nonisolated(unsafe) private var value: T?
    private let lock = NSLock()
    nonisolated func set(_ v: T) { lock.lock(); value = v; lock.unlock() }
    nonisolated func get() -> T? { lock.lock(); defer { lock.unlock() }; return value }
}

extension BridgeProtocolHandler {

    /// Lazily-instantiated process-wide geo engine. Pinned to the SEP
    /// bridge identity so `LinkAcl` can persist a signed document.
    /// `@MainActor` to keep ACL/zones state reads consistent with the
    /// AppState audit-log writer thread.
    @MainActor
    static let sharedGeoEngine: LinkGeoEngine = {
        // Construct at first use. If `SepBridgeIdentity()` fails (e.g.
        // SEP unavailable in CI), we fall back to a placeholder engine
        // that errors on every call — the dispatcher catches that.
        let identity: BridgeIdentity
        do {
            identity = try SepBridgeIdentity()
        } catch {
            NSLog("[BrightNexus] WARN: SepBridgeIdentity init failed for geo engine: %@",
                  error.localizedDescription)
            // Fallback: throw on use. We construct anyway so the engine
            // surface is at least defined.
            identity = NullBridgeIdentity()
        }
        let (acl, tampered) = LinkAcl.loadFromDisk(identity: identity)
        if tampered {
            NSLog("[BrightNexus] WARN: geo-acl.json tamper detected on boot; reverted entries to prompt")
        }
        let zones = LinkZoneEngine.loadFromDisk()
        let prompt: LinkAclPromptCoordinator = NSAlertPromptCoordinator()
        let source: GeoSourceProtocol = CoreLocationGeoSource()
        let audit: GeoAuditSink = MainActorAuditLog()
        return LinkGeoEngine(
            acl: acl, zones: zones, prompt: prompt,
            source: source, audit: audit,
            nowBd: { currentBrightDate() }
        )
    }()

    /// LINK_GEO_STATUS (RFC §9.1). No scope gate.
    func handleLinkGeoStatus(_ json: [String: Any]) -> Data {
        let attestation = peerAttestation ?? defaultAttestation()
        let result: [String: Any] = awaitAsync {
            let engine = await Self.sharedGeoEngine
            return await engine.status(attestation: attestation)
        }
        return Self.jsonResponse(prependProtocolVersion(result))
    }

    /// LINK_GEO_PROXIMITY (RFC §9.2).
    func handleLinkGeoProximity(_ json: [String: Any]) -> Data {
        let attestation = peerAttestation ?? defaultAttestation()
        let zoneId = json["zone"] as? String
        let result: [String: Any] = awaitAsync {
            let engine = await Self.sharedGeoEngine
            return await engine.proximity(attestation: attestation, zoneId: zoneId)
        }
        return Self.jsonResponse(prependProtocolVersion(result))
    }

    /// LINK_GEO_ZONE (RFC §9.3).
    func handleLinkGeoZone(_ json: [String: Any]) -> Data {
        let attestation = peerAttestation ?? defaultAttestation()
        let result: [String: Any] = awaitAsync {
            let engine = await Self.sharedGeoEngine
            return await engine.zone(attestation: attestation)
        }
        return Self.jsonResponse(prependProtocolVersion(result))
    }

    /// LINK_GEO_GET (RFC §9.4).
    func handleLinkGeoGet(_ json: [String: Any]) -> Data {
        let attestation = peerAttestation ?? defaultAttestation()
        let formatRaw = (json["format"] as? String) ?? "wgs84"
        guard let format = CoordinateFormat(rawValue: formatRaw) else {
            return Self.errorResponse(LinkGeoErrors.FORMAT_INVALID)
        }
        let result: [String: Any] = awaitAsync {
            let engine = await Self.sharedGeoEngine
            return await engine.get(attestation: attestation, format: format)
        }
        return Self.jsonResponse(prependProtocolVersion(result))
    }

    /// LINK_GEO_REFRESH (RFC §9.5).
    func handleLinkGeoRefresh(_ json: [String: Any]) -> Data {
        let attestation = peerAttestation ?? defaultAttestation()
        let timeoutSeconds: Int = {
            if let n = json["timeout_seconds"] as? Int, n > 0 { return n }
            if let n = json["timeout_seconds"] as? NSNumber { return max(1, n.intValue) }
            return 10
        }()
        let result: [String: Any] = awaitAsync {
            let engine = await Self.sharedGeoEngine
            return await engine.refresh(attestation: attestation, timeoutSeconds: timeoutSeconds)
        }
        return Self.jsonResponse(prependProtocolVersion(result))
    }

    /// Inject `protocolVersion: 1` at the front of the response. The
    /// engine returns either an `error` dict or a success dict; both
    /// gain the version stamp.
    private func prependProtocolVersion(_ dict: [String: Any]) -> [String: Any] {
        var out: [String: Any] = ["protocolVersion": 1]
        for (k, v) in dict { out[k] = v }
        return out
    }

    /// Synthetic placeholder used when the connection lacks attestation
    /// (e.g. unit tests). The engine treats this as `unsigned` with no
    /// path/hash, so all scopes above proximity will be denied via the
    /// unsigned-binary cap.
    private func defaultAttestation() -> PeerAttestation {
        return PeerAttestation(
            pid: 0, uid: 0,
            executablePath: nil, executableHash: nil,
            attestationClass: .unsigned,
            issuerId: nil, subjectId: nil,
            signatureValid: false,
            peerLineage: [],
            sshSession: nil
        )
    }
}

/// Last-resort identity used only if SEP init fails. Returns empty bytes
/// for everything; signing produces an empty signature so verification
/// fails. The dispatcher logs a warning when this is used.
private final class NullBridgeIdentity: BridgeIdentity {
    var keyId: String { "p256:null" }
    func publicKey() throws -> Data { Data(count: 65) }
    func sign(data: Data) throws -> Data { Data() }
    var kind: BridgeIdentityKind { .file }
}
