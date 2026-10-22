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

    @Test func withTheDefaultProfileCmdIsSuper() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server, keyboardProfile: .default)

        press([leftCmd, one], session)

        try await eventually { keyEvents(server).count == 4 }
        #expect(keyEvents(server) == [
            .keyEvent(down: true, keysym: 0xFFEB), .keyEvent(down: true, keysym: 0x31), // Super_L, 1
            .keyEvent(down: false, keysym: 0x31), .keyEvent(down: false, keysym: 0xFFEB),
        ])
    }

    @Test func withTheMacStyleProfileCmdIsCtrl() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server, keyboardProfile: .macStyle)

        press([leftCmd, c], session)

        try await eventually { keyEvents(server).count == 4 }
        #expect(keyEvents(server) == [
            .keyEvent(down: true, keysym: 0xFFE3), .keyEvent(down: true, keysym: 0x63), // Control_L, c
            .keyEvent(down: false, keysym: 0x63), .keyEvent(down: false, keysym: 0xFFE3),
        ])
    }

    @Test(arguments: KeyboardProfile.allCases)
    func bothOptionKeysAreAlt(profile: KeyboardProfile) async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server, keyboardProfile: profile)

        press([leftOption], session)
        press([rightOption], session)

        try await eventually { keyEvents(server).count == 4 }
        let altL = FakeRFBServer.ClientMessage.keyEvent(down: true, keysym: 0xFFE9)
        let altLUp = FakeRFBServer.ClientMessage.keyEvent(down: false, keysym: 0xFFE9)
        #expect(keyEvents(server) == [altL, altLUp, altL, altLUp])
    }

    @Test func keysGoAsScancodesWhenTheServerAdvertisesQEMUExtendedKeyEvents() async throws {
        let server = try FakeRFBServer(advertisedEncodings: [-258])
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        try await waitForAnnouncements(server, session)

        press([leftCmd, one], session)

        try await eventually { keyEvents(server).count == 4 }
        // XT scancodes: Left GUI is E0 5B, sent as 0xDB; the 1 key is 0x02.
        #expect(keyEvents(server) == [
            .qemuKeyEvent(down: true, keysym: 0xFFEB, keycode: 0xDB), .qemuKeyEvent(down: true, keysym: 0x31, keycode: 0x02),
            .qemuKeyEvent(down: false, keysym: 0x31, keycode: 0x02), .qemuKeyEvent(down: false, keysym: 0xFFEB, keycode: 0xDB),
        ])
    }

    @Test func keysGoAsKeysymsWhenTheServerDoesNotAdvertiseQEMUExtendedKeyEvents() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        try await waitForAnnouncements(server, session)

        press([one], session)

        try await eventually { keyEvents(server).count == 2 }
        #expect(keyEvents(server) == [.keyEvent(down: true, keysym: 0x31), .keyEvent(down: false, keysym: 0x31)])
    }

    @Test func withMatchWindowAResizeAsksTheServerForTheWindowsPixelSize() async throws {
        let server = try FakeRFBServer(advertisedEncodings: [FakeRFBServer.extendedDesktopSizeEncoding])
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port, displaySizing: .matchWindow)

        // Before connecting: held until the server shows it can resize.
        session.windowResized(width: 1280, height: 800)
        session.connect()

        try await eventually { desktopSizeRequests(server).count == 1 }
        #expect(desktopSizeRequests(server) == [desktopSizeRequest(width: 1280, height: 800)])

        session.windowResized(width: 2880, height: 1750)

        try await eventually { desktopSizeRequests(server).count == 2 }
        #expect(desktopSizeRequests(server).last == desktopSizeRequest(width: 2880, height: 1750))
    }

    @Test func withScaleToFitAResizeSendsNothing() async throws {
        let server = try FakeRFBServer(advertisedEncodings: [FakeRFBServer.extendedDesktopSizeEncoding])
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port, displaySizing: .scaleToFit)
        session.windowResized(width: 1280, height: 800)
        session.connect()
        try await eventually { session.state == .connected }
        try await waitForAnnouncements(server, session)

        session.windowResized(width: 2880, height: 1750)
        // Sent after any resize request would have been, so its arrival means none is coming.
        press([one], session)

        try await eventually { keyEvents(server).count == 2 }
        #expect(desktopSizeRequests(server).isEmpty)
        #expect(session.screenSize == ScreenSize(width: 64, height: 48))
    }

    @Test func theRemoteScreenTakesTheSizeTheServerAnswersWith() async throws {
        let server = try FakeRFBServer(width: 64, height: 48,
                                       advertisedEncodings: [FakeRFBServer.extendedDesktopSizeEncoding])
        defer { server.stop() }
        let session = Session(address: "127.0.0.1", port: server.port, displaySizing: .matchWindow)
        session.connect()
        try await eventually { session.state == .connected }

        session.windowResized(width: 1280, height: 800)

        try await eventually { session.screenSize == ScreenSize(width: 1280, height: 800) }
    }

    @Test func releasingOneOfTwoOptionKeysKeepsAltDown() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        session.handle(.key(leftOption, isDown: true))
        session.handle(.key(rightOption, isDown: true))
        session.handle(.key(leftOption, isDown: false))
        session.handle(.key(one, isDown: true))
        session.handle(.key(one, isDown: false))
        session.handle(.key(rightOption, isDown: false))

        try await eventually { keyEvents(server).count == 4 }
        #expect(keyEvents(server) == [
            .keyEvent(down: true, keysym: 0xFFE9), .keyEvent(down: true, keysym: 0x31),
            .keyEvent(down: false, keysym: 0x31), .keyEvent(down: false, keysym: 0xFFE9),
        ])
    }

    // wayvnc #461: keys left down when the client goes away stay stuck on Hyprland.
    @Test func disconnectingReleasesEveryHeldKeyFirst() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.handle(.key(leftCmd, isDown: true))
        session.handle(.key(one, isDown: true))
        session.handle(.key(c, isDown: true))
        session.handle(.key(c, isDown: false))

        session.disconnect()

        try await eventually {
            if case .disconnected = session.state { true } else { false }
        }
        let events = keyEvents(server)
        #expect(events.count == 6)
        #expect(Set(events.suffix(2)) == [.keyEvent(down: false, keysym: 0xFFEB), .keyEvent(down: false, keysym: 0x31)])
    }

    @Test func theUnlockShortcutTogglesLockModeAndNeverReachesTheRemote() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        press([leftControl, leftOption], session)
        #expect(session.lockMode == .locked)
        // Released in the order pressed this time.
        session.handle(.key(leftControl, isDown: true))
        session.handle(.key(leftOption, isDown: true))
        session.handle(.key(leftControl, isDown: false))
        session.handle(.key(leftOption, isDown: false))
        #expect(session.lockMode == .unlocked)
        press([one], session)

        // The 1 key's events land after anything sent before them.
        try await eventually { keyEvents(server).count == 2 }
        #expect(keyEvents(server) == [.keyEvent(down: true, keysym: 0x31), .keyEvent(down: false, keysym: 0x31)])
    }

    @Test func controlOptionTReachesTheRemoteAsCtrlAltTAndLeavesLockModeAlone() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        press([leftControl, leftOption, t], session)

        try await eventually { keyEvents(server).count == 6 }
        #expect(keyEvents(server) == [
            .keyEvent(down: true, keysym: 0xFFE3), .keyEvent(down: true, keysym: 0xFFE9), // Control_L, Alt_L
            .keyEvent(down: true, keysym: 0x74), .keyEvent(down: false, keysym: 0x74), // t
            .keyEvent(down: false, keysym: 0xFFE9), .keyEvent(down: false, keysym: 0xFFE3),
        ])
        #expect(session.lockMode == .unlocked)
    }

    @Test func aLoneControlTapStillReachesTheRemote() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        press([leftControl], session)

        try await eventually { keyEvents(server).count == 2 }
        #expect(keyEvents(server) == [.keyEvent(down: true, keysym: 0xFFE3), .keyEvent(down: false, keysym: 0xFFE3)])
        #expect(session.lockMode == .unlocked)
    }

    @Test func controlClickReachesTheRemoteWithControlDown() async throws {
        let server = try FakeRFBServer(width: 64, height: 48)
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        try await eventually { session.screenSize != nil }

        session.handle(.key(leftControl, isDown: true))
        session.handle(.pointerButton(.left, isDown: true, x: 1, y: 1))

        try await eventually { keyEvents(server).count == 1 && pointerEvents(server).count == 1 }
        #expect(keyEvents(server) == [.keyEvent(down: true, keysym: 0xFFE3)])
        session.handle(.key(leftOption, isDown: true))
        session.handle(.key(leftOption, isDown: false))
        session.handle(.key(leftControl, isDown: false))
        #expect(session.lockMode == .unlocked)
    }

    @Test func losingTheAbilityToLockUnlocks() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.lock()

        session.isLockModeAvailable = false

        #expect(session.lockMode == .unlocked)
    }

    @Test func losingWindowFocusPausesLockModeAndRegainingItResumes() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.toggleLockMode()
        #expect(session.lockMode == .locked)

        session.windowFocusChanged(isFocused: false)
        #expect(session.lockMode == .paused)

        session.windowFocusChanged(isFocused: true)
        #expect(session.lockMode == .locked)
    }

    @Test func focusChangesLeaveAnUnlockedSessionUnlocked() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        session.windowFocusChanged(isFocused: false)
        session.windowFocusChanged(isFocused: true)

        #expect(session.lockMode == .unlocked)
    }

    @Test func disconnectingWhileLockedUnlocks() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.lock()

        session.disconnect()

        #expect(session.lockMode == .unlocked)
        try await eventually {
            if case .disconnected = session.state { true } else { false }
        }
        #expect(session.lockMode == .unlocked)
    }

    @Test func theServerDroppingTheConnectionUnlocks() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.lock()

        server.dropConnection()

        try await eventually { session.lockMode == .unlocked }
    }

    @Test(arguments: [false, true])
    func pausingOrUnlockingReleasesEveryHeldKey(byLosingFocus: Bool) async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.lock()
        session.handle(.key(leftCmd, isDown: true))
        session.handle(.key(one, isDown: true))

        if byLosingFocus { session.windowFocusChanged(isFocused: false) } else { session.toggleLockMode() }

        try await eventually { keyEvents(server).count == 4 }
        #expect(Set(keyEvents(server).suffix(2)) == [
            .keyEvent(down: false, keysym: 0xFFEB), .keyEvent(down: false, keysym: 0x31),
        ])
        #expect(session.lockMode == (byLosingFocus ? .paused : .unlocked))
    }

    @Test func lockModeIsUnavailableUntilAllowed() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.isLockModeAvailable = false

        session.lock()
        press([leftControl, leftOption], session)
        #expect(session.lockMode == .unlocked)

        session.isLockModeAvailable = true
        session.lock()
        #expect(session.lockMode == .locked)
    }

    @Test func lockModeNeedsAConnectedSession() {
        let session = Session(address: "127.0.0.1", port: 1)

        session.lock()

        #expect(session.lockMode == .unlocked)
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

    @Test func aLocalClipboardChangeIsSentToTheRemote() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        session.localClipboardChanged(text: "café", types: ["public.utf8-plain-text"])

        try await eventually { !cutTexts(server).isEmpty }
        #expect(cutTexts(server) == [.clientCutText([0x63, 0x61, 0x66, 0xE9])]) // Latin-1
    }

    @Test(arguments: ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"])
    func concealedAndTransientClipboardItemsAreNeverSent(marker: String) async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        session.localClipboardChanged(text: "hunter2", types: ["public.utf8-plain-text", marker])
        // Messages arrive in order, so once this one is in, the secret would have been too.
        session.localClipboardChanged(text: "ok", types: ["public.utf8-plain-text"])

        try await eventually { !cutTexts(server).isEmpty }
        #expect(cutTexts(server) == [.clientCutText(Array("ok".utf8))])
    }

    @Test func theRemoteClipboardIsReceivedAsText() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        #expect(session.remoteClipboardText == nil)

        server.send(serverCutText([0x63, 0x61, 0x66, 0xE9])) // "café" in Latin-1

        try await eventually { session.remoteClipboardText == "café" }
    }

    @Test func textJustReceivedFromTheRemoteIsNotSentBack() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        server.send(serverCutText(Array("from remote".utf8)))
        try await eventually { session.remoteClipboardText == "from remote" }

        // The platform writes it to the Mac's clipboard, which then reports the change.
        session.localClipboardChanged(text: "from remote", types: ["public.utf8-plain-text"])
        session.localClipboardChanged(text: "from mac", types: ["public.utf8-plain-text"])

        try await eventually { !cutTexts(server).isEmpty }
        #expect(cutTexts(server) == [.clientCutText(Array("from mac".utf8))])
        #expect(session.remoteClipboardText == nil)
    }

    @Test func textTheRemoteEchoesBackIsNotWrittenToTheMac() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.localClipboardChanged(text: "from mac", types: ["public.utf8-plain-text"])
        try await eventually { !cutTexts(server).isEmpty }

        server.send(serverCutText(Array("from mac".utf8)))
        // The Session reads in order, so once this screen update lands the echo has been handled.
        server.send(screenUpdate)
        try await eventually { session.image != nil }
        #expect(session.remoteClipboardText == nil)

        server.send(serverCutText(Array("from remote".utf8)))
        try await eventually { session.remoteClipboardText == "from remote" }
    }

    @Test func anEchoOfTextLatin1CouldNotCarryIsStillRecognized() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        session.localClipboardChanged(text: "a→b", types: ["public.utf8-plain-text"])
        try await eventually { !cutTexts(server).isEmpty }
        #expect(cutTexts(server) == [.clientCutText(Array("a?b".utf8))])

        server.send(serverCutText(Array("a?b".utf8)))
        server.send(screenUpdate)
        try await eventually { session.image != nil }

        #expect(session.remoteClipboardText == nil)
    }

    @Test func copyingSomethingOtherThanTextOnTheMacLetsTheSameRemoteTextArriveAgain() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)
        server.send(serverCutText(Array("from remote".utf8)))
        try await eventually { session.remoteClipboardText == "from remote" }

        session.localClipboardChanged(text: nil, types: ["public.png"])
        #expect(session.remoteClipboardText == nil)

        server.send(serverCutText(Array("from remote".utf8)))
        try await eventually { session.remoteClipboardText == "from remote" }
        #expect(cutTexts(server).isEmpty)
    }

    @Test func withExtendedClipboardLocalTextWithEmojiArrivesIntact() async throws {
        let server = try FakeRFBServer(advertisedEncodings: [FakeRFBServer.extendedClipboardEncoding])
        defer { server.stop() }
        let session = try await extendedClipboardSession(to: server)

        session.localClipboardChanged(text: "café 😀\nok", types: ["public.utf8-plain-text"])

        try await eventually { !providedTexts(server).isEmpty }
        #expect(providedTexts(server) == [Array("café 😀\r\nok".utf8) + [0]])
        #expect(cutTexts(server).isEmpty)
    }

    @Test func withExtendedClipboardServerTextWithEmojiArrivesIntact() async throws {
        let server = try FakeRFBServer(advertisedEncodings: [FakeRFBServer.extendedClipboardEncoding])
        defer { server.stop() }
        let session = try await extendedClipboardSession(to: server)

        server.sendClipboardText("naïve 🎉\nline")

        try await eventually { session.remoteClipboardText == "naïve 🎉\nline" }
    }

    @Test func withoutExtendedClipboardTextGoesAsLatin1() async throws {
        let server = try FakeRFBServer()
        defer { server.stop() }
        let session = try await connectedSession(to: server)

        session.localClipboardChanged(text: "café → ok", types: ["public.utf8-plain-text"])

        try await eventually { !cutTexts(server).isEmpty }
        #expect(cutTexts(server) == [.clientCutText(Array("caf".utf8) + [0xE9] + Array(" ? ok".utf8))])
        #expect(!server.messages.contains { if case .extendedClientCutText = $0 { true } else { false } })
    }

    @Test(arguments: ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"])
    func withExtendedClipboardConcealedAndTransientItemsAreNeverSent(marker: String) async throws {
        let server = try FakeRFBServer(advertisedEncodings: [FakeRFBServer.extendedClipboardEncoding])
        defer { server.stop() }
        let session = try await extendedClipboardSession(to: server)

        session.localClipboardChanged(text: "hunter2 🔑", types: ["public.utf8-plain-text", marker])
        session.localClipboardChanged(text: "ok 👍", types: ["public.utf8-plain-text"])

        try await eventually { !providedTexts(server).isEmpty }
        #expect(providedTexts(server) == [Array("ok 👍".utf8) + [0]])
    }

    @Test func withExtendedClipboardTextJustReceivedIsNotSentBack() async throws {
        let server = try FakeRFBServer(advertisedEncodings: [FakeRFBServer.extendedClipboardEncoding])
        defer { server.stop() }
        let session = try await extendedClipboardSession(to: server)
        server.sendClipboardText("from remote 🎉")
        try await eventually { session.remoteClipboardText == "from remote 🎉" }

        session.localClipboardChanged(text: "from remote 🎉", types: ["public.utf8-plain-text"])
        session.localClipboardChanged(text: "from mac 🍎", types: ["public.utf8-plain-text"])

        try await eventually { !providedTexts(server).isEmpty }
        #expect(providedTexts(server) == [Array("from mac 🍎".utf8) + [0]])
    }

    @Test func withExtendedClipboardTextTheRemoteEchoesBackIsNotWrittenToTheMac() async throws {
        let server = try FakeRFBServer(advertisedEncodings: [FakeRFBServer.extendedClipboardEncoding])
        defer { server.stop() }
        let session = try await extendedClipboardSession(to: server)
        session.localClipboardChanged(text: "from mac 🍎\nline", types: ["public.utf8-plain-text"])
        try await eventually { !providedTexts(server).isEmpty }

        server.sendClipboardText("from mac 🍎\nline")
        // The server provides once the client requests, and the Session reads in order.
        try await eventually { requestCount(server) == 1 }
        server.send(screenUpdate)
        try await eventually { session.image != nil }

        #expect(session.remoteClipboardText == nil)
    }

    @Test func withExtendedClipboardAnEchoOfCRLFTextIsRecognized() async throws {
        let server = try FakeRFBServer(advertisedEncodings: [FakeRFBServer.extendedClipboardEncoding])
        defer { server.stop() }
        let session = try await extendedClipboardSession(to: server)
        session.localClipboardChanged(text: "a\r\nb", types: ["public.utf8-plain-text"])
        try await eventually { !providedTexts(server).isEmpty }

        server.sendClipboardText("a\nb") // the echo, which comes back with LF line endings
        try await eventually { requestCount(server) == 1 }
        server.send(screenUpdate)
        try await eventually { session.image != nil }

        #expect(session.remoteClipboardText == nil)
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

// USB HID usages of the keys the keyboard tests press.
private let leftControl = KeyCode(hidUsage: 0xE0)
private let leftOption = KeyCode(hidUsage: 0xE2)
private let leftCmd = KeyCode(hidUsage: 0xE3)
private let rightOption = KeyCode(hidUsage: 0xE6)
private let one = KeyCode(hidUsage: 0x1E)
private let c = KeyCode(hidUsage: 0x06)
private let t = KeyCode(hidUsage: 0x17)

/// Presses the keys in order, then releases them in reverse, as a chord.
@MainActor
private func press(_ keys: [KeyCode], _ session: Session) {
    keys.forEach { session.handle(.key($0, isDown: true)) }
    keys.reversed().forEach { session.handle(.key($0, isDown: false)) }
}

@MainActor
private func connectedSession(to server: FakeRFBServer, keyboardProfile: KeyboardProfile = .default) async throws -> Session {
    let session = Session(address: "127.0.0.1", port: server.port, keyboardProfile: keyboardProfile)
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

/// Waits until the Session has read the server's answer to its SetEncodings: the server answers before sending the
/// screen update that follows, and the Session reads in order.
@MainActor
private func waitForAnnouncements(_ server: FakeRFBServer, _ session: Session) async throws {
    try await eventually { server.messages.contains { if case .setEncodings = $0 { true } else { false } } }
    server.send(screenUpdate)
    try await eventually { session.image != nil }
}

/// FramebufferUpdate, 1 rectangle at 0,0 sized 1x1, Raw encoding, one 32-bit pixel.
private let screenUpdate: [UInt8] = [0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0] + [0, 0, 255, 0]

private func desktopSizeRequests(_ server: FakeRFBServer) -> [FakeRFBServer.ClientMessage] {
    server.messages.filter { if case .setDesktopSize = $0 { true } else { false } }
}

/// SetDesktopSize for one screen at the origin, keeping the id the server gave it.
private func desktopSizeRequest(width: UInt16, height: UInt16) -> FakeRFBServer.ClientMessage {
    .setDesktopSize(width: width, height: height,
                    screens: [.init(id: FakeRFBServer.screenID, x: 0, y: 0, width: width, height: height)])
}

private func keyEvents(_ server: FakeRFBServer) -> [FakeRFBServer.ClientMessage] {
    server.messages.filter {
        switch $0 {
        case .keyEvent, .qemuKeyEvent: true
        default: false
        }
    }
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

/// Connects and waits for the client's Extended Clipboard caps, its answer to the server's.
@MainActor
private func extendedClipboardSession(to server: FakeRFBServer) async throws -> Session {
    let session = try await connectedSession(to: server)
    try await eventually {
        server.messages.contains {
            if case .extendedClientCutText(let flags, _) = $0 { flags & FakeRFBServer.ClipboardFlag.caps != 0 } else { false }
        }
    }
    return session
}

private func requestCount(_ server: FakeRFBServer) -> Int {
    server.messages.count {
        if case .extendedClientCutText(let flags, _) = $0 {
            flags == FakeRFBServer.ClipboardFlag.request | FakeRFBServer.ClipboardFlag.text
        } else { false }
    }
}

/// The text of every Extended Clipboard provide the client sent.
private func providedTexts(_ server: FakeRFBServer) -> [[UInt8]] {
    server.messages.compactMap { if case .extendedClientCutText(_, let text?) = $0 { text } else { nil } }
}

/// ServerCutText: type 3, 3 bytes of padding, the length, then the Latin-1 text.
private func serverCutText(_ text: [UInt8]) -> [UInt8] {
    [3, 0, 0, 0] + withUnsafeBytes(of: UInt32(text.count).bigEndian, Array.init) + text
}

private func cutTexts(_ server: FakeRFBServer) -> [FakeRFBServer.ClientMessage] {
    server.messages.filter { if case .clientCutText = $0 { true } else { false } }
}

private func pointerEvents(_ server: FakeRFBServer) -> [FakeRFBServer.ClientMessage] {
    server.messages.filter { if case .pointerEvent = $0 { true } else { false } }
}
