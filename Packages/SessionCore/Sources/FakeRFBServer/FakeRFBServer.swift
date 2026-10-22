import Foundation
import Synchronization

/// A minimal RFB 3.8 server on localhost for tests: security type None or VNC password, records every client
/// message, and sends server messages or drops the connection on demand.
/// It serves one client at a time and accepts the next one once the current client is gone.
/// Call `stop()` when done: the accept thread keeps the server alive until then.
public final class FakeRFBServer: Sendable {
    public enum ClientMessage: Equatable, Sendable {
        case setPixelFormat
        case setEncodings([Int32])
        case framebufferUpdateRequest(incremental: Bool)
        case keyEvent(down: Bool, keysym: UInt32)
        case pointerEvent(buttonMask: UInt8, x: UInt16, y: UInt16)
        case clientCutText([UInt8])
        /// A message type the server cannot parse yet. Its length is unknown, so the server drops the client.
        case unknown(type: UInt8)
    }

    public enum Security: Sendable {
        case none
        /// VNC authentication with an all-zero challenge. Any response is accepted and recorded.
        case vncPassword
    }

    public let port: UInt16
    public let security: Security
    public let width: UInt16
    public let height: UInt16
    /// Encodings the server claims to support. When the client's SetEncodings lists one of them,
    /// the server answers with an empty pseudo-encoding rectangle for it, which is only a valid
    /// announcement for encodings without a payload, such as QEMU Extended Key Event (-258).
    public let advertisedEncodings: [Int32]

    private let listener: Int32
    private let client = Mutex<Int32?>(nil)
    private let recorded = Mutex<[ClientMessage]>([])
    private let response = Mutex<[UInt8]?>(nil)

    public init(width: UInt16 = 64, height: UInt16 = 48, security: Security = .none,
                advertisedEncodings: [Int32] = []) throws {
        self.security = security
        self.width = width
        self.height = height
        self.advertisedEncodings = advertisedEncodings

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_port = 0
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, length) == 0 && listen(fd, 1) == 0 && getsockname(fd, $0, &length) == 0
            }
        }
        guard bound else {
            close(fd)
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        listener = fd
        port = UInt16(bigEndian: address.sin_port)

        Thread.detachNewThread { [self] in acceptLoop() }
    }

    /// Every message the client has sent since the handshake, in order.
    public var messages: [ClientMessage] {
        recorded.withLock { $0 }
    }

    /// The client's 16-byte answer to the VNC authentication challenge.
    public var authenticationResponse: [UInt8]? {
        response.withLock { $0 }
    }

    /// Sends raw bytes (a server-to-client message) to the connected client.
    public func send(_ bytes: [UInt8]) {
        client.withLock { fd in
            if let fd { writeAll(fd, bytes) }
        }
    }

    /// Closes the current client connection without any protocol goodbye.
    public func dropConnection() {
        client.withLock { fd in
            if let fd { shutdown(fd, SHUT_RDWR) }
        }
    }

    public func stop() {
        dropConnection()
        shutdown(listener, SHUT_RDWR)
        close(listener)
    }

    private func acceptLoop() {
        while true {
            let fd = accept(listener, nil, nil)
            guard fd >= 0 else { return }
            var noSigPipe: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
            client.withLock { $0 = fd }
            serve(fd)
            client.withLock {
                $0 = nil
                close(fd)
            }
        }
    }

    private func serve(_ fd: Int32) {
        // Handshake: version, security type, SecurityResult OK, ClientInit, ServerInit.
        writeAll(fd, Array("RFB 003.008\n".utf8))
        guard readExactly(fd, 12) != nil else { return }
        writeAll(fd, [1, security == .none ? 1 : 2])
        guard readExactly(fd, 1) != nil else { return }
        if security == .vncPassword {
            writeAll(fd, [UInt8](repeating: 0, count: 16))
            guard let answer = readExactly(fd, 16) else { return }
            response.withLock { $0 = answer }
        }
        writeAll(fd, be32(0))
        guard readExactly(fd, 1) != nil else { return }
        let name = Array("fake".utf8)
        // 32 bpp, depth 24, little endian, true colour, max 255, shifts 16/8/0.
        let pixelFormat: [UInt8] = [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]
        writeAll(fd, be16(width) + be16(height) + pixelFormat + be32(UInt32(name.count)) + name)

        while let message = readMessage(fd) {
            recorded.withLock { $0.append(message) }
            if case .setEncodings(let requested) = message {
                announce(advertisedEncodings.filter(requested.contains))
            }
            if case .unknown = message { return }
        }
    }

    private func announce(_ encodings: [Int32]) {
        guard !encodings.isEmpty else { return }
        var update: [UInt8] = [0, 0] + be16(UInt16(encodings.count))
        for encoding in encodings {
            update += [UInt8](repeating: 0, count: 8) + be32(UInt32(bitPattern: encoding))
        }
        send(update)
    }

    private func readMessage(_ fd: Int32) -> ClientMessage? {
        guard let type = readExactly(fd, 1)?.first else { return nil }
        switch type {
        case 0:
            guard readExactly(fd, 19) != nil else { return nil }
            return .setPixelFormat
        case 2:
            guard let header = readExactly(fd, 3) else { return nil }
            let count = Int(u16(header, 1))
            guard let body = readExactly(fd, count * 4) else { return nil }
            return .setEncodings((0..<count).map { Int32(bitPattern: u32(body, $0 * 4)) })
        case 3:
            guard let body = readExactly(fd, 9) else { return nil }
            return .framebufferUpdateRequest(incremental: body[0] != 0)
        case 4:
            guard let body = readExactly(fd, 7) else { return nil }
            return .keyEvent(down: body[0] != 0, keysym: u32(body, 3))
        case 5:
            guard let body = readExactly(fd, 5) else { return nil }
            return .pointerEvent(buttonMask: body[0], x: u16(body, 1), y: u16(body, 3))
        case 6:
            guard let header = readExactly(fd, 7), let text = readExactly(fd, Int(u32(header, 3))) else { return nil }
            return .clientCutText(text)
        default:
            return .unknown(type: type)
        }
    }
}

private func readExactly(_ fd: Int32, _ count: Int) -> [UInt8]? {
    var buffer = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress! + offset, count - offset) }
        guard n > 0 else { return nil }
        offset += n
    }
    return buffer
}

private func writeAll(_ fd: Int32, _ bytes: [UInt8]) {
    var offset = 0
    while offset < bytes.count {
        let n = bytes.withUnsafeBytes { write(fd, $0.baseAddress! + offset, bytes.count - offset) }
        guard n > 0 else { return }
        offset += n
    }
}

private func be16(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 0xFF)] }
private func be32(_ value: UInt32) -> [UInt8] { be16(UInt16(value >> 16)) + be16(UInt16(value & 0xFFFF)) }
private func u16(_ bytes: [UInt8], _ at: Int) -> UInt16 { UInt16(bytes[at]) << 8 | UInt16(bytes[at + 1]) }
private func u32(_ bytes: [UInt8], _ at: Int) -> UInt32 { UInt32(u16(bytes, at)) << 16 | UInt32(u16(bytes, at + 2)) }
