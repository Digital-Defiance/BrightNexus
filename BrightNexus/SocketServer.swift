// SocketServer.swift
// BrightNexus
//
// Unix domain socket server for the BrightNexus protocol surface (EBP/1 + BrightLink v1).
//
// Single canonical socket: ~/.brightchain/brightnexus/brightnexus.sock
//
// Phase 2.5 cleanup removed the legacy `~/.enclave/enclave-bridge.sock` compat
// socket — there were no users to migrate.

import Foundation
import Darwin

class SocketServer {
    private let primarySocketPath: String
    private var primaryFD: Int32 = -1

    private let queue = DispatchQueue(label: "BrightNexus.SocketServer", qos: .userInitiated)
    private var isRunning = false

    private var connectionIds: [Int32: UUID] = [:]
    private let connectionLock = NSLock()

    /// Construct using the canonical paths from `BrightNexusPaths`. Callers
    /// MUST have invoked `BrightNexusPaths.bootstrap()` before instantiating.
    init() {
        self.primarySocketPath = BrightNexusPaths.primarySocket.path
    }

    func start() {
        queue.async { [weak self] in
            self?.runServer()
        }
    }

    func stop() {
        isRunning = false
        Task { @MainActor in
            AppState.shared.isServerRunning = false
        }
        if primaryFD != -1 {
            close(primaryFD)
            unlink(primarySocketPath)
            primaryFD = -1
        }
    }

    // MARK: - Bind helper

    private func bindListener(at path: String, backlog: Int32 = 5) -> Int32 {
        unlink(path)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd != -1 else {
            NSLog("[BrightNexus] socket() failed for %@: errno=%d", path, errno)
            return -1
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let sunPathSize = MemoryLayout.size(ofValue: addr.sun_path)
        if path.utf8.count >= sunPathSize {
            NSLog("[BrightNexus] FATAL: socket path %@ exceeds sun_path limit (%d bytes)",
                  path, sunPathSize)
            close(fd)
            return -1
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            path.withCString { cstr in
                _ = strlcpy(UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self),
                            cstr, sunPathSize)
            }
        }

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            NSLog("[BrightNexus] bind(%@) failed: errno=%d", path, errno)
            close(fd)
            return -1
        }

        chmod(path, 0o600)

        guard listen(fd, backlog) == 0 else {
            NSLog("[BrightNexus] listen(%@) failed: errno=%d", path, errno)
            close(fd)
            unlink(path)
            return -1
        }

        return fd
    }

    private func runServer() {
        isRunning = true

        primaryFD = bindListener(at: primarySocketPath)
        guard primaryFD != -1 else {
            NSLog("[BrightNexus] FATAL: failed to bind socket at %@", primarySocketPath)
            return
        }
        NSLog("[BrightNexus] Socket listening at %@", primarySocketPath)

        Task { @MainActor in
            AppState.shared.isServerRunning = true
            AppState.shared.socketPath = primarySocketPath
        }

        // Single accept loop on the canonical socket.
        while isRunning {
            acceptOne(on: primaryFD)
        }

        if primaryFD != -1 {
            close(primaryFD)
            unlink(primarySocketPath)
            primaryFD = -1
        }
    }

    private func acceptOne(on listeningFD: Int32) {
        var clientAddr = sockaddr_un()
        var clientLen: socklen_t = socklen_t(MemoryLayout<sockaddr_un>.size)
        let clientFD = withUnsafeMutablePointer(to: &clientAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                accept(listeningFD, $0, &clientLen)
            }
        }
        if clientFD == -1 { return }

        let clientQueue = DispatchQueue(label: "BrightNexus.Client-\(clientFD)", qos: .utility)
        clientQueue.async { [weak self] in
            self?.handleClient(clientFD)
        }
    }

    // MARK: - Per-client handling

    private func handleClient(_ clientFd: Int32) {
        let connectionId = registerConnection(clientFd: clientFd)
        // RFC §4.9.5 — peer attestation at accept time. Best-effort; nil
        // fields are tolerated by the handler.
        let attestation = PeerAttestationLookup.attest(clientFd: clientFd)
        let protocolHandler = BridgeProtocolHandler(peerAttestation: attestation)

        let bufferSize = 4096
        var buffer = [UInt8](repeating: 0, count: bufferSize)
        var dataBuffer = Data()

        defer {
            close(clientFd)
            unregisterConnection(clientFd: clientFd, connectionId: connectionId)
        }

        while true {
            let bytesRead = read(clientFd, &buffer, bufferSize)
            if bytesRead < 0 {
                NSLog("[BrightNexus] read error on fd %d: errno=%d", clientFd, errno)
                break
            } else if bytesRead == 0 {
                break
            }
            dataBuffer.append(Data(buffer[0..<bytesRead]))

            // EBP/1 §3.2 brace-terminator framing: one '}' delimits one message.
            while let range = dataBuffer.range(of: Data([0x7d])) {
                let end = range.upperBound
                let messageData = dataBuffer.subdata(in: 0..<end)
                dataBuffer.removeSubrange(0..<end)

                updateConnectionActivity(connectionId: connectionId)

                let response = protocolHandler.handleMessage(messageData)
                let written = response.withUnsafeBytes { write(clientFd, $0.baseAddress, response.count) }
                if written < 0 {
                    NSLog("[BrightNexus] write error on fd %d: errno=%d", clientFd, errno)
                    break
                }
            }
        }
    }

    // MARK: - Connection tracking

    private func registerConnection(clientFd: Int32) -> UUID {
        let connectionId = UUID()
        connectionLock.lock()
        connectionIds[clientFd] = connectionId
        connectionLock.unlock()

        Task { @MainActor in
            AppState.shared.addConnection(id: connectionId, fileDescriptor: clientFd)
        }

        return connectionId
    }

    private func unregisterConnection(clientFd: Int32, connectionId: UUID) {
        connectionLock.lock()
        connectionIds.removeValue(forKey: clientFd)
        connectionLock.unlock()

        Task { @MainActor in
            AppState.shared.removeConnection(fileDescriptor: clientFd)
        }
    }

    private func updateConnectionActivity(connectionId: UUID) {
        Task { @MainActor in
            AppState.shared.updateConnectionActivity(id: connectionId)
        }
    }
}
