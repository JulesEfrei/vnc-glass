import FakeRFBServer
import Foundation
@testable import SessionCore
import Testing

@MainActor
struct SessionTests {
    @Test func connectsAndReportsTheRemoteScreenSize() async throws {
        let server = try FakeRFBServer(width: 64, height: 48)
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port)

        session.connect()

        try await eventually { session.state == .connected }
        try await eventually { session.screenSize == ScreenSize(width: 64, height: 48) }
    }

    @Test func asksForThePasswordAndSendsItToTheServer() async throws {
        let server = try FakeRFBServer(security: .vncPassword)
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port)

        session.connect()
        try await eventually { session.credentialRequest != nil }
        #expect(session.credentialRequest == CredentialRequest(needsUsername: false))

        session.submitCredentials(username: "", password: "password")

        try await eventually { session.state == .connected }
        #expect(session.credentialRequest == nil)
        // DES of the server's all-zero challenge keyed by "password", computed with openssl.
        let block: [UInt8] = [0xFF, 0x97, 0x50, 0x2E, 0x94, 0x22, 0xF0, 0x89]
        #expect(server.authenticationResponse == block + block)
    }

    @Test func noLoginOutsideTailscaleWarnsTheUser() async throws {
        let server = try FakeRFBServer(security: .none)
        defer { server.stop() }

        let session = try await connectedSession(to: server)

        #expect(session.isUnauthenticatedOutsideTailscale)
    }

    @Test func aLoginDoesNotWarn() async throws {
        let server = try FakeRFBServer(security: .vncPassword)
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port, password: "password")

        session.connect()

        try await eventually { session.state == .connected }
        #expect(!session.isUnauthenticatedOutsideTailscale)
    }

    // Tests cannot reach a 100.x address, so the range itself is checked on its own.
    @Test(arguments: [
        ("100.64.0.1", true), ("100.101.102.103", true), ("100.127.255.255", true),
        ("100.63.255.255", false), ("100.128.0.0", false), ("127.0.0.1", false), ("192.168.1.10", false),
        ("desk.tailnet.ts.net", false), ("", false),
    ])
    func tailscaleAddressesAreThoseIn100_64Slash10(address: String, isTailscale: Bool) {
        #expect(Session.isTailscaleAddress(address) == isTailscale)
    }

    @Test func logsInWithAppleRemoteDesktopAuthentication() async throws {
        let server = try FakeRFBServer(security: .appleRemoteDesktop)
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port)

        session.connect()
        try await eventually { session.credentialRequest != nil }
        #expect(session.credentialRequest == CredentialRequest(needsUsername: true))

        session.submitCredentials(username: "jane", password: "secret")

        try await eventually { session.state == .connected }
        // Decrypted by the server: length-prefixed username, then password.
        #expect(server.authenticationResponse == [4] + Array("jane".utf8) + [6] + Array("secret".utf8))
    }

    @Test func aSavedPasswordLogsInWithoutAsking() async throws {
        let server = try FakeRFBServer(security: .vncPassword)
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port, username: "", password: "password")

        session.connect()

        try await eventually { session.state == .connected }
        let block: [UInt8] = [0xFF, 0x97, 0x50, 0x2E, 0x94, 0x22, 0xF0, 0x89]
        #expect(server.authenticationResponse == block + block)
    }

    @Test func aRejectedSavedPasswordIsAskedForOnTheNextConnect() async throws {
        let server = try FakeRFBServer(security: .vncPassword, rejectsLogin: true)
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port, username: "", password: "stale")
        session.connect()
        try await eventually { session.state == .disconnected(.authenticationFailed) }

        session.connect()

        try await eventually { session.credentialRequest != nil }
    }

    @Test func cancellingThePasswordPromptDisconnects() async throws {
        let server = try FakeRFBServer(security: .vncPassword)
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port)

        session.connect()
        try await eventually { session.credentialRequest != nil }
        session.cancelCredentials()

        try await eventually { session.state == .disconnected(nil) }
        #expect(session.credentialRequest == nil)
    }

    @Test(arguments: [FakeRFBServer.RSAAESType.aes128, .aes256])
    func logsInWithUsernameAndPasswordOverRSAAES(type: FakeRFBServer.RSAAESType) async throws {
        let server = try FakeRFBServer(security: .rsaAES(type))
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port, knownServerKeys: freshDefaults())

        session.connect()
        try await eventually { session.credentialRequest != nil }
        #expect(session.credentialRequest == CredentialRequest(needsUsername: true))

        session.submitCredentials(username: "jane", password: "secret")

        try await eventually { session.state == .connected }
        // The decrypted credentials message: length-prefixed UTF-8 username, then password.
        #expect(server.authenticationResponse == [4] + Array("jane".utf8) + [6] + Array("secret".utf8))
    }

    @Test func asksForThePasswordOnlyWhenTheRSAAESServerNeedsNoUsername() async throws {
        let server = try FakeRFBServer(security: .rsaAES(.aes256, passwordOnly: true))
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port, knownServerKeys: freshDefaults())

        session.connect()
        try await eventually { session.credentialRequest != nil }
        #expect(session.credentialRequest == CredentialRequest(needsUsername: false))

        session.submitCredentials(username: "ignored", password: "secret")

        try await eventually { session.state == .connected }
        #expect(server.authenticationResponse == [0, 6] + Array("secret".utf8))
    }

    @Test func inputAndScreenUpdatesTravelOverTheEncryptedStream() async throws {
        let server = try FakeRFBServer(width: 64, height: 48, security: .rsaAES(.aes256))
        defer { server.stop() }
        let session = try await loggedInSession(to: server, knownServerKeys: freshDefaults())
        #expect(session.image == nil)

        session.handle(.key(KeyCode(hidUsage: 0x04), isDown: true))
        session.handle(.pointerButton(.left, isDown: true, x: 10, y: 20))
        // FramebufferUpdate, 1 rectangle at 0,0 sized 2x1, Raw encoding, two 32-bit pixels.
        server.send([0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0] + [0, 0, 255, 0, 255, 0, 0, 0])

        try await eventually { keyEvents(server).count == 1 && pointerEvents(server).count == 1 }
        #expect(keyEvents(server) == [.keyEvent(down: true, keysym: 0x61)])
        #expect(pointerEvents(server) == [.pointerEvent(buttonMask: 1, x: 10, y: 20)])
        // The Session has no picture until the server's first update arrives.
        try await eventually { session.image != nil }
    }

    @Test func aChangedServerKeyWaitsForTheUserToAcceptIt() async throws {
        let server = try FakeRFBServer(security: .rsaAES(.aes256))
        defer { server.stop() }
        let knownServerKeys = freshDefaults()
        try await loggedInSession(to: server, knownServerKeys: knownServerKeys).disconnect()

        try server.replaceServerKey()
        let session = Session(address: "127.0.0.1", port: server.port, knownServerKeys: knownServerKeys)
        session.connect()

        try await eventually { session.serverKeyChange != nil }
        #expect(session.serverKeyChange?.fingerprint.hasPrefix("SHA256:") == true)
        // Stopped before the login: no credentials asked for.
        try await Task.sleep(for: .milliseconds(200))
        #expect(session.credentialRequest == nil)
        #expect(session.state == .connecting)

        session.trustServerKey()
        try await eventually { session.credentialRequest != nil }
        session.submitCredentials(username: "jane", password: "secret")
        try await eventually { session.state == .connected }
        session.disconnect()

        // The accepted key is now the remembered one.
        let again = try await loggedInSession(to: server, knownServerKeys: knownServerKeys)
        #expect(again.serverKeyChange == nil)
    }

    @Test func refusingAChangedServerKeyDisconnects() async throws {
        let server = try FakeRFBServer(security: .rsaAES(.aes256))
        defer { server.stop() }
        let knownServerKeys = freshDefaults()
        try await loggedInSession(to: server, knownServerKeys: knownServerKeys).disconnect()

        try server.replaceServerKey()
        let session = Session(address: "127.0.0.1", port: server.port, knownServerKeys: knownServerKeys)
        session.connect()
        try await eventually { session.serverKeyChange != nil }

        session.rejectServerKey()

        try await eventually {
            if case .disconnected = session.state { true } else { false }
        }
        #expect(session.serverKeyChange == nil)
        #expect(session.credentialRequest == nil)
    }

    @Test func remoteScreenUpdatesProduceAPicture() async throws {
        let server = try FakeRFBServer(width: 2, height: 1)
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        #expect(session.image == nil)

        // FramebufferUpdate, 1 rectangle at 0,0 sized 2x1, Raw encoding, two 32-bit pixels.
        server.send([0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0] + [0, 0, 255, 0, 255, 0, 0, 0])

        try await eventually { session.image?.width == 2 && session.image?.height == 1 }
    }

    @Test func typedLettersAndDigitsReachTheRemoteAsKeysyms() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        // USB HID usages: 0x04 is the A key, 0x1E the 1 key, 0x27 the 0 key.
        for usage: UInt16 in [0x04, 0x1E, 0x27] {
            session.handle(.key(KeyCode(hidUsage: usage), isDown: true))
            session.handle(.key(KeyCode(hidUsage: usage), isDown: false))
        }

        try await eventually { keyEvents(server).count == 6 }
        #expect(keyEvents(server) == [
            .keyEvent(down: true, keysym: 0x61), .keyEvent(down: false, keysym: 0x61), // a
            .keyEvent(down: true, keysym: 0x31), .keyEvent(down: false, keysym: 0x31), // 1
            .keyEvent(down: true, keysym: 0x30), .keyEvent(down: false, keysym: 0x30), // 0
        ])
    }

    @Test func pointerMovementAndClicksReachTheRemote() async throws {
        let server = try FakeRFBServer(width: 64, height: 48)
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        session.handle(.pointerMoved(x: 10, y: 20))
        session.handle(.pointerButton(.left, isDown: true, x: 10, y: 20))
        session.handle(.pointerButton(.left, isDown: false, x: 10, y: 20))
        session.handle(.pointerButton(.right, isDown: true, x: 30.6, y: 40))
        session.handle(.pointerButton(.right, isDown: false, x: 30.6, y: 40))

        try await eventually { pointerEvents(server).count == 5 }
        // RFB button mask: bit 0 is left, bit 2 is right.
        #expect(pointerEvents(server) == [
            .pointerEvent(buttonMask: 0, x: 10, y: 20),
            .pointerEvent(buttonMask: 1, x: 10, y: 20),
            .pointerEvent(buttonMask: 0, x: 10, y: 20),
            .pointerEvent(buttonMask: 4, x: 30, y: 40),
            .pointerEvent(buttonMask: 0, x: 30, y: 40),
        ])
    }

    @Test func pointerOutsideTheRemoteScreenIsClampedToItsEdge() async throws {
        let server = try FakeRFBServer(width: 64, height: 48)
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        session.handle(.pointerMoved(x: -5, y: 500))

        try await eventually { pointerEvents(server).count == 1 }
        #expect(pointerEvents(server) == [.pointerEvent(buttonMask: 0, x: 0, y: 47)])
    }

    @Test func aRefusedConnectionSaysSo() async throws {
        let server = try FakeRFBServer()
        server.stop() // Nothing listens on the port any more.
        let session = Session(address: "127.0.0.1", port: server.port)

        session.connect()

        try await eventually { session.state == .disconnected(.refused) }
    }

    @Test func anUnknownHostIsUnreachable() async throws {
        let session = Session(address: "no-such-host.invalid", port: 5900)

        session.connect()

        try await eventually(timeout: .seconds(15)) { session.state == .disconnected(.unreachable) }
    }

    @Test func aRejectedLoginIsAnAuthenticationFailure() async throws {
        let server = try FakeRFBServer(security: .vncPassword, rejectsLogin: true)
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port)

        session.connect()
        try await eventually { session.credentialRequest != nil }
        session.submitCredentials(username: "", password: "wrong")

        try await eventually { session.state == .disconnected(.authenticationFailed) }
    }

    // 19 is VeNCrypt, 16 Tight security, which RoyalVNCKit names but never implemented.
    @Test(arguments: [19, 16] as [UInt8])
    func aServerOfferingOnlyUnknownLoginsIsUnsupported(type: UInt8) async throws {
        let server = try FakeRFBServer(security: .unsupported(type))
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port)

        session.connect()

        try await eventually { session.state == .disconnected(.unsupportedSecurityType) }
    }

    @Test func serverDroppingTheConnectionDisconnectsTheSession() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        server.dropConnection()

        try await eventually {
            if case .disconnected = session.state { true } else { false }
        }
    }
}

@MainActor
private func connectedSession(to server: FakeRFBServer) async throws -> Session {
    let session = Session(address: "127.0.0.1", port: server.port)
    session.connect()
    try await eventually { session.state == .connected }
    return session
}

/// An empty settings domain, so no test sees server keys remembered by another.
private func freshDefaults() -> UserDefaults {
    UserDefaults(suiteName: "SessionTests.\(UUID().uuidString)")!
}

/// Connects to an RSA-AES server and logs in. A key the Session has not seen before is trusted without asking.
@MainActor
private func loggedInSession(to server: FakeRFBServer, knownServerKeys: UserDefaults) async throws -> Session {
    let session = Session(address: "127.0.0.1", port: server.port, knownServerKeys: knownServerKeys)
    session.connect()
    try await eventually { session.credentialRequest != nil }
    #expect(session.serverKeyChange == nil)
    session.submitCredentials(username: "jane", password: "secret")
    try await eventually { session.state == .connected }
    return session
}

private func keyEvents(_ server: FakeRFBServer) -> [FakeRFBServer.ClientMessage] {
    server.messages.filter { if case .keyEvent = $0 { true } else { false } }
}

/// Polls `condition` until it holds, yielding the main actor so Session updates can land.
@MainActor
func eventually(timeout: Duration = .seconds(5), _ condition: () -> Bool) async throws {
    let deadline = ContinuousClock.now + timeout
    while !condition() {
        guard ContinuousClock.now < deadline else {
            Issue.record("Condition not met within \(timeout)")
            return
        }
        try await Task.sleep(for: .milliseconds(10))
    }
}

private func pointerEvents(_ server: FakeRFBServer) -> [FakeRFBServer.ClientMessage] {
    server.messages.filter { if case .pointerEvent = $0 { true } else { false } }
}
