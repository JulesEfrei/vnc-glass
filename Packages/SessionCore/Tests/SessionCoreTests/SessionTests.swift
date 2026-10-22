import FakeRFBServer
import SessionCore
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
