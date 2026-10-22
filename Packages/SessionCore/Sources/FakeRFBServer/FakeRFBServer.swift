import CryptoSwift
import Foundation
import Security
import Synchronization

/// A minimal RFB 3.8 server on localhost for tests: security type None, VNC password, Apple Remote Desktop or RSA-AES,
/// records every client message, and sends server messages or drops the connection on demand.
/// It serves one client at a time and accepts the next one once the current client is gone.
/// Call `stop()` when done: the accept thread keeps the server alive until then.
public final class FakeRFBServer: Sendable {
    public enum ClientMessage: Hashable, Sendable {
        case setPixelFormat
        case setEncodings([Int32])
        case framebufferUpdateRequest(incremental: Bool)
        case keyEvent(down: Bool, keysym: UInt32)
        case pointerEvent(buttonMask: UInt8, x: UInt16, y: UInt16)
        case clientCutText([UInt8])
        /// QEMU Extended Key Event: the keysym and the XT keycode, with E0-prefixed keys as 0x80 | low byte.
        case qemuKeyEvent(down: Bool, keysym: UInt32, keycode: UInt32)
        /// A message type the server cannot parse yet. Its length is unknown, so the server drops the client.
        case unknown(type: UInt8)
    }

    public enum Security: Equatable, Sendable {
        case none
        /// VNC authentication with an all-zero challenge. Any response is accepted and recorded.
        case vncPassword
        /// Apple Remote Desktop's Diffie-Hellman login (type 30) over a 1024-bit group. Any credentials are accepted
        /// and recorded.
        case appleRemoteDesktop
        /// rfbproto RSA-AES with a 2048-bit server key: after the key exchange every byte in both directions travels
        /// in AES-EAX frames. Any credentials are accepted and recorded.
        case rsaAES(RSAAESType, passwordOnly: Bool = false)
        /// Offers only this security type, one the client is expected not to support.
        case unsupported(UInt8)
    }

    public enum RSAAESType: UInt8, Sendable {
        /// SHA-1 and AES-128, 16-byte randoms.
        case aes128 = 5
        /// SHA-256 and AES-256, 32-byte randoms as neatvnc sends them.
        case aes256 = 129
    }

    public let port: UInt16
    public let security: Security
    public let width: UInt16
    public let height: UInt16
    /// Answers every login with a failed SecurityResult.
    public let rejectsLogin: Bool
    /// Encodings the server claims to support. When the client's SetEncodings lists one of them,
    /// the server answers with an empty pseudo-encoding rectangle for it, which is only a valid
    /// announcement for encodings without a payload, such as QEMU Extended Key Event (-258).
    public let advertisedEncodings: [Int32]

    private let listener: Int32
    private let client = Mutex<Client?>(nil)
    private let recorded = Mutex<[ClientMessage]>([])
    private let response = Mutex<[UInt8]?>(nil)
    private let serverKey: Mutex<SecKey?>

    public init(width: UInt16 = 64, height: UInt16 = 48, security: Security = .none, rejectsLogin: Bool = false,
                advertisedEncodings: [Int32] = []) throws {
        self.security = security
        self.rejectsLogin = rejectsLogin
        self.width = width
        self.height = height
        self.advertisedEncodings = advertisedEncodings
        if case .rsaAES = security {
            serverKey = Mutex(try newRSAKey())
        } else {
            serverKey = Mutex(nil)
        }

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

    /// The client's answer to the login: the 16-byte response to the VNC authentication challenge, or the decrypted
    /// RSA-AES credentials message.
    public var authenticationResponse: [UInt8]? {
        response.withLock { $0 }
    }

    /// Gives the server a new RSA key, as if it had been reinstalled. Later clients see the new key.
    public func replaceServerKey() throws {
        try serverKey.withLock { $0 = try newRSAKey() }
    }

    /// Sends raw bytes (a server-to-client message) to the connected client, encrypted once RSA-AES is set up.
    public func send(_ bytes: [UInt8]) {
        client.withLock { client in
            guard client != nil else { return }
            client!.write(bytes)
        }
    }

    /// Closes the current client connection without any protocol goodbye.
    public func dropConnection() {
        client.withLock { client in
            if let client { shutdown(client.fd, SHUT_RDWR) }
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
            client.withLock { $0 = Client(fd: fd) }
            var reader = Reader(fd: fd)
            serve(&reader)
            client.withLock {
                $0 = nil
                close(fd)
            }
        }
    }

    private func serve(_ reader: inout Reader) {
        // Handshake: version, security type, SecurityResult OK, ClientInit, ServerInit.
        send(Array("RFB 003.008\n".utf8))
        guard reader.read(12) != nil else { return }
        switch security {
        case .none:
            send([1, 1])
            guard reader.read(1) != nil else { return }
        case .vncPassword:
            send([1, 2])
            guard reader.read(1) != nil else { return }
            send([UInt8](repeating: 0, count: 16))
            guard let answer = reader.read(16) else { return }
            response.withLock { $0 = answer }
        case .appleRemoteDesktop:
            send([1, 30])
            guard reader.read(1) != nil, let credentials = ardHandshake(&reader) else { return }
            response.withLock { $0 = credentials }
        case .rsaAES(let type, let passwordOnly):
            send([1, type.rawValue])
            guard reader.read(1) != nil,
                  let credentials = rsaAESHandshake(&reader, type: type, passwordOnly: passwordOnly) else { return }
            response.withLock { $0 = credentials }
        case .unsupported(let type):
            send([1, type])
            _ = reader.read(1)
            return
        }
        if rejectsLogin {
            let reason = Array("Authentication failed".utf8)
            return send(be32(1) + be32(UInt32(reason.count)) + reason)
        }
        send(be32(0))
        guard reader.read(1) != nil else { return }
        let name = Array("fake".utf8)
        // 32 bpp, depth 24, little endian, true colour, max 255, shifts 16/8/0.
        let pixelFormat: [UInt8] = [32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]
        send(be16(width) + be16(height) + pixelFormat + be32(UInt32(name.count)) + name)

        while let message = readMessage(&reader) {
            recorded.withLock { $0.append(message) }
            if case .setEncodings(let requested) = message {
                announce(advertisedEncodings.filter(requested.contains))
            }
            if case .unknown = message { return }
        }
    }

    /// The server side of the Apple Remote Desktop login. Returns the decrypted credentials as length-prefixed username
    /// and password, or nil when the client breaks the protocol.
    private func ardHandshake(_ reader: inout Reader) -> [UInt8]? {
        let prime = CS.BigUInt(Data(hex: oakleyGroup2Prime))
        let keyLength = 128
        let privateKey = CS.BigUInt(Data((0..<127).map { _ in UInt8.random(in: .min ... .max) }))
        let publicKey = Array(CS.BigUInt(2).power(privateKey, modulus: prime).serialize())
        send([0, 2] + be16(UInt16(keyLength)) + Array(prime.serialize())
             + [UInt8](repeating: 0, count: keyLength - publicKey.count) + publicKey)

        guard let cipherText = reader.read(128), let clientKey = reader.read(keyLength) else { return nil }
        // The client hashes the shared secret without leading zero bytes.
        let secret = CS.BigUInt(Data(clientKey)).power(privateKey, modulus: prime).serialize()
        guard let plaintext = try? AES(key: Array(secret.md5()), blockMode: ECB(), padding: .noPadding)
            .decrypt(cipherText) else { return nil }
        // Each field is a C string in its own 64 bytes, the rest random.
        let username = plaintext[..<64].prefix { $0 != 0 }
        let password = plaintext[64...].prefix { $0 != 0 }
        return [UInt8(username.count)] + username + [UInt8(password.count)] + password
    }

    /// The server side of rfbproto's RSA-AES handshake. Returns the decrypted credentials message, or nil when the
    /// client breaks the protocol.
    private func rsaAESHandshake(_ reader: inout Reader, type: RSAAESType, passwordOnly: Bool) -> [UInt8]? {
        let hash: ([UInt8]) -> [UInt8] = type == .aes128 ? { $0.sha1() } : { $0.sha256() }
        let randomLength = type == .aes128 ? 16 : 32
        guard let privateKey = serverKey.withLock({ $0 }),
              let publicKey = SecKeyCopyPublicKey(privateKey),
              let serverKeyMessage = rfbPublicKeyMessage(publicKey) else { return nil }
        send(serverKeyMessage)

        guard let bits = reader.read(4) else { return nil }
        let clientKeyLength = (Int(u32(bits, 0)) + 7) / 8
        guard let modulusAndExponent = reader.read(clientKeyLength * 2),
              let clientKey = rsaPublicKey(modulus: Array(modulusAndExponent[..<clientKeyLength]),
                                           exponent: Array(modulusAndExponent[clientKeyLength...])) else { return nil }
        let clientKeyMessage = bits + modulusAndExponent

        let serverRandom = (0..<randomLength).map { _ in UInt8.random(in: .min ... .max) }
        guard let encryptedServerRandom = SecKeyCreateEncryptedData(clientKey, .rsaEncryptionPKCS1,
                                                                    Data(serverRandom) as CFData, nil) as Data? else { return nil }
        send(be16(UInt16(encryptedServerRandom.count)) + encryptedServerRandom)

        guard let lengthBytes = reader.read(2), let encryptedClientRandom = reader.read(Int(u16(lengthBytes, 0))),
              let clientRandom = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1,
                                                           Data(encryptedClientRandom) as CFData, nil) as Data?,
              clientRandom.count == randomLength else { return nil }

        let sessionKeyLength = type == .aes128 ? 16 : 32
        let clientSessionKey = Array(hash(serverRandom + clientRandom).prefix(sessionKeyLength))
        let serverSessionKey = Array(hash(Array(clientRandom) + serverRandom).prefix(sessionKeyLength))
        client.withLock { $0?.encryptor = FrameCipher(key: serverSessionKey) }
        reader.decryptor = FrameCipher(key: clientSessionKey)

        send(hash(serverKeyMessage + clientKeyMessage))
        let clientHash = hash(clientKeyMessage + serverKeyMessage)
        guard reader.read(clientHash.count) == clientHash else { return nil }

        send([passwordOnly ? 2 : 1])
        guard let usernameLength = reader.read(1), let username = reader.read(Int(usernameLength[0])),
              let passwordLength = reader.read(1), let password = reader.read(Int(passwordLength[0])) else { return nil }
        return usernameLength + username + passwordLength + password
    }

    private func announce(_ encodings: [Int32]) {
        guard !encodings.isEmpty else { return }
        var update: [UInt8] = [0, 0] + be16(UInt16(encodings.count))
        for encoding in encodings {
            update += [UInt8](repeating: 0, count: 8) + be32(UInt32(bitPattern: encoding))
        }
        send(update)
    }

    private func readMessage(_ reader: inout Reader) -> ClientMessage? {
        guard let type = reader.read(1)?.first else { return nil }
        switch type {
        case 0:
            guard reader.read(19) != nil else { return nil }
            return .setPixelFormat
        case 2:
            guard let header = reader.read(3) else { return nil }
            let count = Int(u16(header, 1))
            guard let body = reader.read(count * 4) else { return nil }
            return .setEncodings((0..<count).map { Int32(bitPattern: u32(body, $0 * 4)) })
        case 3:
            guard let body = reader.read(9) else { return nil }
            return .framebufferUpdateRequest(incremental: body[0] != 0)
        case 4:
            guard let body = reader.read(7) else { return nil }
            return .keyEvent(down: body[0] != 0, keysym: u32(body, 3))
        case 5:
            guard let body = reader.read(5) else { return nil }
            return .pointerEvent(buttonMask: body[0], x: u16(body, 1), y: u16(body, 3))
        case 6:
            guard let header = reader.read(7), let text = reader.read(Int(u32(header, 3))) else { return nil }
            return .clientCutText(text)
        case 255:
            guard let body = reader.read(11), body[0] == 0 else { return .unknown(type: type) }
            return .qemuKeyEvent(down: u16(body, 1) != 0, keysym: u32(body, 3), keycode: u32(body, 7))
        default:
            return .unknown(type: type)
        }
    }
}

/// The write side of the client connection; `send` and the serving thread share it under a lock.
private struct Client {
    let fd: Int32
    var encryptor: FrameCipher?

    mutating func write(_ bytes: [UInt8]) {
        guard encryptor != nil else { return writeAll(fd, bytes) }
        writeAll(fd, encryptor!.seal(bytes))
    }
}

/// The read side of the client connection, owned by the serving thread.
private struct Reader {
    let fd: Int32
    var decryptor: FrameCipher?
    private var plaintext: [UInt8] = []

    init(fd: Int32) {
        self.fd = fd
    }

    mutating func read(_ count: Int) -> [UInt8]? {
        guard decryptor != nil else { return readExactly(fd, count) }
        while plaintext.count < count {
            guard let header = readExactly(fd, 2),
                  let body = readExactly(fd, Int(u16(header, 0)) + 16),
                  let frame = decryptor!.open(header: header, body: body) else { return nil }
            plaintext += frame
        }
        defer { plaintext.removeFirst(count) }
        return Array(plaintext.prefix(count))
    }
}

/// AES-EAX frames as rfbproto's RSA-AES section describes them, built from CryptoSwift's CTR and CMAC.
private struct FrameCipher {
    let key: [UInt8]
    var messageIndex: UInt64 = 0

    mutating func seal(_ plaintext: [UInt8]) -> [UInt8] {
        let header = be16(UInt16(plaintext.count))
        let (ciphertext, mac) = eax(header: header, plaintext, encrypting: true)
        return header + ciphertext + mac
    }

    /// Nil when the MAC does not match.
    mutating func open(header: [UInt8], body: [UInt8]) -> [UInt8]? {
        let ciphertext = Array(body.dropLast(16))
        let (plaintext, mac) = eax(header: header, ciphertext, encrypting: false)
        return mac == Array(body.suffix(16)) ? plaintext : nil
    }

    private mutating func eax(header: [UInt8], _ input: [UInt8], encrypting: Bool) -> ([UInt8], [UInt8]) {
        let nonce = withUnsafeBytes(of: messageIndex.littleEndian, Array.init) + [UInt8](repeating: 0, count: 8)
        messageIndex += 1
        let cmac = try! CMAC(key: key)
        let omac = { (tweak: UInt8, data: [UInt8]) in try! cmac.authenticate([UInt8](repeating: 0, count: 15) + [tweak] + data) }
        let nonceMAC = omac(0, nonce)
        let output = try! AES(key: key, blockMode: CTR(iv: nonceMAC), padding: .noPadding).encrypt(input)
        let ciphertext = encrypting ? output : input
        let mac = zip(zip(nonceMAC, omac(1, header)), omac(2, ciphertext)).map { $0.0 ^ $0.1 ^ $1 }
        return (output, mac)
    }
}

private func newRSAKey() throws -> SecKey {
    var error: Unmanaged<CFError>?
    let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary
    guard let key = SecKeyCreateRandomKey(attributes, &error) else { throw error!.takeRetainedValue() as Error }
    return key
}

/// rfbproto's public key message: the key length in bits, then modulus and exponent, each as long as the modulus.
private func rfbPublicKeyMessage(_ key: SecKey) -> [UInt8]? {
    // Security exports RSA public keys as PKCS#1 DER: SEQUENCE { INTEGER modulus, INTEGER exponent }.
    guard let der = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return nil }
    var bytes = ArraySlice(der)
    guard var sequence = derContents(&bytes),
          let modulus = derContents(&sequence).map({ Array($0.drop { $0 == 0 }) }),
          let exponent = derContents(&sequence).map({ Array($0.drop { $0 == 0 }) }) else { return nil }
    return be32(UInt32(modulus.count * 8)) + modulus + [UInt8](repeating: 0, count: modulus.count - exponent.count) + exponent
}

private func rsaPublicKey(modulus: [UInt8], exponent: [UInt8]) -> SecKey? {
    let der = derSequence(derInteger(modulus) + derInteger(exponent))
    let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic] as CFDictionary
    return SecKeyCreateWithData(Data(der) as CFData, attributes, nil)
}

/// Reads one DER element and returns its contents.
private func derContents(_ bytes: inout ArraySlice<UInt8>) -> ArraySlice<UInt8>? {
    guard bytes.count >= 2 else { return nil }
    bytes.removeFirst()
    var length = Int(bytes.removeFirst())
    if length & 0x80 != 0 {
        let lengthBytes = length & 0x7F
        guard bytes.count >= lengthBytes else { return nil }
        length = bytes.prefix(lengthBytes).reduce(0) { $0 << 8 | Int($1) }
        bytes.removeFirst(lengthBytes)
    }
    guard bytes.count >= length else { return nil }
    defer { bytes.removeFirst(length) }
    return bytes.prefix(length)
}

private func derInteger(_ value: [UInt8]) -> [UInt8] {
    let trimmed = Array(value.drop { $0 == 0 })
    return derElement(tag: 0x02, (trimmed.first ?? 0x80) & 0x80 != 0 ? [0] + trimmed : trimmed)
}

private func derSequence(_ contents: [UInt8]) -> [UInt8] {
    derElement(tag: 0x30, contents)
}

private func derElement(tag: UInt8, _ contents: [UInt8]) -> [UInt8] {
    let length = contents.count < 0x80 ? [UInt8(contents.count)]
        : contents.count < 0x100 ? [0x81, UInt8(contents.count)] : [0x82] + be16(UInt16(contents.count))
    return [tag] + length + contents
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

/// RFC 2409's 1024-bit MODP group.
private let oakleyGroup2Prime = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
"""
