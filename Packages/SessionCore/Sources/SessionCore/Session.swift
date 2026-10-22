import CoreGraphics
import Foundation
import Network
import Observation
import RoyalVNCKit
import Synchronization

public struct ScreenSize: Equatable, Sendable {
    public let width: Int
    public let height: Int

    public init(width: Int, height: Int) {
        self.width = width
        self.height = height
    }
}

/// The remote pointer's shape, drawn locally so it moves without waiting for the server.
public struct RemoteCursor: Equatable, Sendable {
    /// Nil when the remote hides its pointer.
    public let image: CGImage?
    /// The point of the image that sits on the pointer's position, in remote pixels from the top left.
    public let hotspot: CGPoint
}

/// The server wants credentials before the Session can connect.
public struct CredentialRequest: Equatable, Sendable {
    /// False when the server only asks for a password (classic VNC authentication).
    public let needsUsername: Bool

    public init(needsUsername: Bool) {
        self.needsUsername = needsUsername
    }
}

/// The server's key differs from the one remembered for its address and port, as when the server was reinstalled or
/// someone is in the middle. The Session waits for `trustServerKey` or `rejectServerKey`.
public struct ServerKeyChange: Equatable, Sendable {
    /// The new key's fingerprint, written like SSH's: `SHA256:` and the unpadded Base64 of the digest.
    public let fingerprint: String
}

/// One live link to a remote computer.
@MainActor @Observable
public final class Session {
    public enum State: Equatable, Sendable {
        case connecting
        case connected
        /// The link dropped and the Session is retrying on its own, still showing the last frame.
        case reconnecting
        /// Nil when the Session ended without a fault, as when the user disconnected or declined to log in.
        case disconnected(Failure?)
    }

    public enum LockMode: Equatable, Sendable {
        case unlocked
        /// Every keystroke goes to the remote and none act on the Mac.
        case locked
        /// Locked, but the window is not focused; becomes locked again when it is.
        case paused
    }

    public enum Failure: Equatable, Sendable {
        /// The address did not resolve, or nothing answered at it.
        case unreachable
        /// The computer answered but nothing listens on the port.
        case refused
        /// The server did not accept the login.
        case authenticationFailed
        /// The server offers no login this app can perform.
        case unsupportedSecurityType
        case other(String)
    }

    public let address: String
    public let port: UInt16
    public private(set) var state: State = .disconnected(nil)
    public private(set) var screenSize: ScreenSize?
    /// The latest picture of the remote screen.
    public private(set) var image: CGImage?
    /// Nil until the server sends a cursor shape; until then it draws its pointer into `image`.
    public private(set) var cursor: RemoteCursor?
    /// Set while the server waits for `submitCredentials` or `cancelCredentials`.
    public private(set) var credentialRequest: CredentialRequest?
    /// Set while the Session waits for the user to accept or refuse a changed server key.
    public private(set) var serverKeyChange: ServerKeyChange?
    /// The server let the Session in without any login (security type None) and the address is not a Tailscale one, so
    /// anyone who can reach the server can control it.
    public private(set) var isUnauthenticatedOutsideTailscale = false
    public private(set) var lockMode = LockMode.unlocked
    /// Text the remote computer put on its clipboard, for the platform to write to the local one. Nil once the local
    /// clipboard has changed since.
    public private(set) var remoteClipboardText: String?
    /// False while the platform cannot capture system shortcuts, as without the Accessibility permission on macOS.
    public var isLockModeAvailable = true {
        didSet { if !isLockModeAvailable && lockMode != .unlocked { leaveLock(to: .unlocked) } }
    }
    /// The modifiers that toggle Lock Mode instead of reaching the remote.
    public var unlockShortcut = UnlockShortcut.default
    /// False to keep both clipboards apart: local text is not sent and the remote's is not offered to the platform.
    /// Turning it off also withdraws the text already offered to an Extended Clipboard server.
    public var isClipboardSyncEnabled = true {
        didSet { if !isClipboardSyncEnabled { link?.clearClipboardText() } }
    }

    @ObservationIgnored private var link: VNCConnection?
    @ObservationIgnored private var linkDelegate: LinkDelegate?
    @ObservationIgnored private var credentialReply: CredentialReply?
    @ObservationIgnored private var serverKeyReply: ServerKeyReply?
    /// Remembers each server's key fingerprint by address and port, trusting the first one seen.
    @ObservationIgnored private let knownServerKeys: UserDefaults
    /// The username given to servers that ask for one, and prefilled in the prompt.
    public private(set) var username: String
    public let keyboardProfile: KeyboardProfile
    public let displaySizing: DisplaySizing
    /// The window's size in pixels, last given to `windowResized`.
    @ObservationIgnored private var windowSize: ScreenSize?
    /// Answers the server's login without asking. Dropped once the server rejects it, so the user is asked instead.
    @ObservationIgnored private var savedPassword: String?
    @ObservationIgnored private var wasAskedForCredentials = false
    /// Remote keys sent down and not yet up, with how many local keys hold each (both ⌥ keys hold Alt_L).
    /// Released on disconnect so none stay stuck (wayvnc #461).
    @ObservationIgnored private var heldKeys: [KeyCode: Int] = [:]
    /// Unlock Shortcut keys pressed and not yet forwarded, since they may turn out to be the shortcut.
    @ObservationIgnored private var shortcutKeys: [KeyCode] = []
    /// The Unlock Shortcut has fired and the rest of its keys are still being released.
    @ObservationIgnored private var isShortcutFired = false
    /// The local clipboard text last sent, until the remote clipboard changes, so the server's echo of it is ignored:
    /// the text itself and with LF line endings over Extended Clipboard, and with `?` for what Latin-1 lacks over plain
    /// cut text.
    @ObservationIgnored private var sentClipboardTexts: Set<String> = []
    /// Scrolling not yet sent, less than one wheel click on each axis.
    @ObservationIgnored private var scrollRemainder = (x: 0.0, y: 0.0)
    /// How long to wait before each retry after the link drops; the Session gives up once they run out.
    @ObservationIgnored private let reconnectDelays: [Duration]
    /// Retries made since the connection dropped.
    @ObservationIgnored private var reconnectAttempts = 0
    @ObservationIgnored private var reconnectTask: Task<Void, Never>?

    /// Backoff adding up to about 30 seconds, long enough for a Mac waking from sleep to get its network back.
    public static let defaultReconnectDelays: [Duration] = [.seconds(1), .seconds(2), .seconds(4), .seconds(8), .seconds(15)]

    public init(address: String, port: UInt16, username: String = "", password: String? = nil,
                keyboardProfile: KeyboardProfile = .default, displaySizing: DisplaySizing = .scaleToFit,
                knownServerKeys: UserDefaults = .standard, reconnectDelays: [Duration] = defaultReconnectDelays) {
        self.address = address
        self.port = port
        self.username = username
        self.keyboardProfile = keyboardProfile
        self.displaySizing = displaySizing
        savedPassword = password
        self.knownServerKeys = knownServerKeys
        self.reconnectDelays = reconnectDelays
    }

    public func connect() {
        guard case .disconnected = state else { return }
        reconnectAttempts = 0
        state = .connecting
        openLink()
    }

    /// Starts a new link to the server, leaving `state` to the caller.
    private func openLink() {
        let settings = VNCConnection.Settings(
            isDebugLoggingEnabled: false,
            hostname: address,
            port: port,
            isShared: true,
            isScalingEnabled: true,
            useDisplayLink: false,
            inputMode: .forwardKeyboardShortcutsIfNotInUseLocally, // .none drops all input; the other modes only matter to RoyalVNCKit's own view
            isClipboardRedirectionEnabled: false,
            colorDepth: .depth24Bit,
            frameEncodings: .default
        )
        let link = VNCConnection(settings: settings)
        let linkDelegate = LinkDelegate(session: self)
        link.delegate = linkDelegate
        self.link = link
        self.linkDelegate = linkDelegate
        wasAskedForCredentials = false
        isUnauthenticatedOutsideTailscale = false
        link.connect()
        requestWindowSize()
    }

    /// The window now shows this many pixels. With Match Window the remote is asked to take that size.
    public func windowResized(width: Int, height: Int) {
        windowSize = ScreenSize(width: width, height: height)
        requestWindowSize()
    }

    private func requestWindowSize() {
        // rfbproto rejects an empty screen, as a collapsed view would give.
        guard displaySizing == .matchWindow, let link, let windowSize, windowSize.width > 0, windowSize.height > 0
        else { return }
        link.setDesktopSize(width: UInt16(clamping: windowSize.width), height: UInt16(clamping: windowSize.height))
    }

    public func disconnect() {
        reconnectTask?.cancel()
        reconnectAttempts = reconnectDelays.count // A link failing while it closes is no drop to retry.
        cancelCredentials()
        rejectServerKey()
        lockMode = .unlocked
        releaseHeldKeys()
        link?.disconnect()
        if state == .reconnecting {
            // No live link is left to report the ending, and a retry link's late reports no longer count.
            linkDelegate?.session = nil
            state = .disconnected(nil)
        }
    }

    /// Turns Lock Mode on, as when the window goes full screen.
    public func lock() {
        guard state == .connected, isLockModeAvailable else { return }
        lockMode = .locked
    }

    public func toggleLockMode() {
        if lockMode == .unlocked { lock() } else { leaveLock(to: .unlocked) }
    }

    public func windowFocusChanged(isFocused: Bool) {
        switch (lockMode, isFocused) {
        case (.locked, false): leaveLock(to: .paused)
        case (.paused, true): lockMode = .locked
        default: break
        }
    }

    private func leaveLock(to mode: LockMode) {
        lockMode = mode
        releaseHeldKeys()
    }

    /// Accepts the changed server key, remembers it in place of the old one and goes on connecting.
    public func trustServerKey() {
        guard let reply = serverKeyReply else { return }
        knownServerKeys.set(reply.fingerprint, forKey: serverKeyDefaultsKey)
        answerServerKeyChange(true)
    }

    /// Refuses the changed server key; the Session disconnects.
    public func rejectServerKey() {
        answerServerKeyChange(false)
    }

    private func answerServerKeyChange(_ isTrusted: Bool) {
        let reply = serverKeyReply
        serverKeyReply = nil
        serverKeyChange = nil
        reply?.send(isTrusted)
    }

    private var serverKeyDefaultsKey: String {
        "ServerKeyFingerprint \(address):\(port)"
    }

    public func submitCredentials(username: String, password: String) {
        guard let credentialRequest else { return }
        // Remembered so retries after a drop log in without asking again.
        self.username = username
        savedPassword = password
        answerCredentialRequest(credentialRequest.needsUsername
            ? VNCUsernamePasswordCredential(username: username, password: password)
            : VNCPasswordCredential(password: password))
    }

    /// Declines to log in; the server then ends the Session.
    public func cancelCredentials() {
        answerCredentialRequest(nil)
    }

    private func answerCredentialRequest(_ credential: VNCCredential?) {
        let reply = credentialReply
        credentialReply = nil
        credentialRequest = nil
        reply?.send(credential)
    }

    /// The Mac's clipboard changed to `text`, nil when it holds no text. `types` are the pasteboard types of the item.
    public func localClipboardChanged(text: String?, types: [String]) {
        guard let link, state == .connected, isClipboardSyncEnabled, text == nil || text != remoteClipboardText
        else { return }
        remoteClipboardText = nil
        sentClipboardTexts = []
        // nspasteboard.org markers: password managers flag secrets as concealed, and transient items are not meant to persist.
        guard let text, !types.contains(where: Self.privateClipboardTypes.contains) else { return }
        let latin1 = text.data(using: .isoLatin1, allowLossyConversion: true).flatMap { String(data: $0, encoding: .isoLatin1) }
        sentClipboardTexts = Set([text, text.replacingOccurrences(of: "\r\n", with: "\n"), latin1].compactMap(\.self))
        link.sendClipboardText(text)
    }

    private static let privateClipboardTypes: Set = ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"]

    public func handle(_ event: InputEvent) {
        guard let link, state == .connected else { return }
        switch event {
        case .key(let key, let isDown):
            handleKey(key, isDown: isDown)
        case .pointerMoved(let x, let y):
            guard let (x, y) = remotePixel(x, y) else { return }
            link.mouseMove(x: x, y: y)
        case .pointerButton(let button, let isDown, let x, let y):
            guard let (x, y) = remotePixel(x, y) else { return }
            // A click means the held-back keys are not the Unlock Shortcut, and ⌃-click needs its ⌃.
            forwardShortcutKeys()
            let button: VNCMouseButton = button == .left ? .left : .right
            if isDown {
                link.mouseButtonDown(button, x: x, y: y)
            } else {
                link.mouseButtonUp(button, x: x, y: y)
            }
        case .scroll(let dx, let dy, let x, let y):
            guard let (x, y) = remotePixel(x, y) else { return }
            // Like a click: ⌃-scroll zooms on Linux, so held-back keys go first.
            forwardShortcutKeys()
            let clicksY = Self.wholeClicks(adding: dy, to: &scrollRemainder.y)
            let clicksX = Self.wholeClicks(adding: dx, to: &scrollRemainder.x)
            if clicksY != 0 { link.mouseWheel(clicksY > 0 ? .up : .down, x: x, y: y, steps: UInt32(abs(clicksY))) }
            if clicksX != 0 { link.mouseWheel(clicksX > 0 ? .left : .right, x: x, y: y, steps: UInt32(abs(clicksX))) }
        }
    }

    /// Adds `delta` to one axis's leftover scrolling and takes out the whole clicks. Turning back drops the leftover, so
    /// the first click the other way takes no longer than any other.
    private static func wholeClicks(adding delta: Double, to remainder: inout Double) -> Double {
        if remainder * delta < 0 { remainder = 0 }
        remainder += delta
        let clicks = remainder.rounded(.towardZero)
        remainder -= clicks
        return clicks
    }

    /// Holds back the Unlock Shortcut's keys pressed with nothing else down: released with no other key in between,
    /// they are the shortcut and never reach the remote; any other key forwards them first.
    private func handleKey(_ key: KeyCode, isDown: Bool) {
        if isDown {
            if unlockShortcut.keys.contains(key), !isShortcutFired, heldKeys.isEmpty, !shortcutKeys.contains(key) {
                shortcutKeys.append(key)
                return
            }
            forwardShortcutKeys()
        } else if shortcutKeys.contains(key) {
            if isShortcutFired || shortcutKeys.count == unlockShortcut.keys.count {
                shortcutKeys.removeAll { $0 == key }
                if isShortcutFired {
                    isShortcutFired = !shortcutKeys.isEmpty
                } else {
                    isShortcutFired = true
                    toggleLockMode()
                }
                return
            }
            forwardShortcutKeys()
        }
        send(key, isDown: isDown)
    }

    private func forwardShortcutKeys() {
        let keys = shortcutKeys
        shortcutKeys = []
        isShortcutFired = false
        keys.forEach { send($0, isDown: true) }
    }

    private func send(_ key: KeyCode, isDown: Bool) {
        guard let link else { return }
        let remoteKey = keyboardProfile.remoteKey(for: key)
        guard let (keysym, scancode) = remoteKey.remote else { return }
        if isDown {
            heldKeys[remoteKey, default: 0] += 1
            if heldKeys[remoteKey] == 1 { link.keyDown(VNCKeyCode(keysym), scancode: scancode) }
        } else if let count = heldKeys[remoteKey] {
            heldKeys[remoteKey] = count > 1 ? count - 1 : nil
            if count == 1 { link.keyUp(VNCKeyCode(keysym), scancode: scancode) }
        }
    }

    private func releaseHeldKeys() {
        for key in heldKeys.keys {
            guard let (keysym, scancode) = key.remote else { continue }
            link?.keyUp(VNCKeyCode(keysym), scancode: scancode)
        }
        heldKeys = [:]
        shortcutKeys = []
        isShortcutFired = false
    }

    private func remotePixel(_ x: Double, _ y: Double) -> (UInt16, UInt16)? {
        guard let screenSize, screenSize.width > 0, screenSize.height > 0 else { return nil }
        let maxX = Double(screenSize.width - 1)
        let maxY = Double(screenSize.height - 1)
        return (UInt16(min(max(x, 0), maxX)), UInt16(min(max(y, 0), maxY)))
    }

    fileprivate func linkStatusChanged(_ status: VNCConnection.Status, failure: Failure?) {
        switch status {
        case .connecting: if state != .reconnecting { state = .connecting }
        case .connected:
            reconnectAttempts = 0
            // Every login RoyalVNCKit performs asks for credentials, so connecting without being asked means None.
            isUnauthenticatedOutsideTailscale = !wasAskedForCredentials && !Self.isTailscaleAddress(address)
            state = .connected
        case .disconnected:
            credentialReply = nil
            credentialRequest = nil
            serverKeyReply = nil
            serverKeyChange = nil
            heldKeys = [:]
            shortcutKeys = []
            isShortcutFired = false
            lockMode = .unlocked
            remoteClipboardText = nil
            sentClipboardTexts = []
            cursor = nil
            scrollRemainder = (0, 0)
            if failure == .authenticationFailed { savedPassword = nil }
            // Retry a drop or a failed retry, but not a login the server turned down or an ending the user chose.
            if state == .connected || state == .reconnecting, let failure, failure != .authenticationFailed,
               failure != .unsupportedSecurityType, reconnectAttempts < reconnectDelays.count {
                let delay = reconnectDelays[reconnectAttempts]
                reconnectAttempts += 1
                state = .reconnecting
                reconnectTask = Task { [weak self] in
                    try? await Task.sleep(for: delay)
                    guard !Task.isCancelled else { return }
                    self?.openLink()
                }
            } else {
                state = .disconnected(failure)
            }
        case .disconnecting: break
        }
    }

    fileprivate func credentialsRequested(_ request: CredentialRequest, reply: CredentialReply) {
        credentialRequest = request
        credentialReply = reply
        wasAskedForCredentials = true
        if let savedPassword { submitCredentials(username: username, password: savedPassword) }
    }

    fileprivate func serverKeyPresented(_ reply: ServerKeyReply) {
        switch knownServerKeys.data(forKey: serverKeyDefaultsKey) {
        case nil:
            knownServerKeys.set(reply.fingerprint, forKey: serverKeyDefaultsKey)
            reply.send(true)
        case reply.fingerprint:
            reply.send(true)
        default:
            let base64 = reply.fingerprint.base64EncodedString().trimmingCharacters(in: ["="])
            serverKeyChange = ServerKeyChange(fingerprint: "SHA256:\(base64)")
            serverKeyReply = reply
        }
    }

    /// Whether the address is an IPv4 literal in Tailscale's 100.64.0.0/10.
    /// shortcut: hostnames are not resolved, so a MagicDNS name still warns; resolve them if that proves noisy.
    static func isTailscaleAddress(_ address: String) -> Bool {
        var ip = in_addr()
        guard inet_pton(AF_INET, address, &ip) == 1 else { return false }
        return UInt32(bigEndian: ip.s_addr) & 0xFFC0_0000 == 0x6440_0000
    }

    fileprivate func remoteClipboardChanged(_ text: String) {
        guard isClipboardSyncEnabled, !sentClipboardTexts.contains(text) else { return }
        sentClipboardTexts = []
        remoteClipboardText = text
    }

    fileprivate func cursorChanged(_ cursor: RemoteCursor) {
        self.cursor = cursor
    }

    fileprivate func framebufferChanged() {
        guard let framebuffer = link?.framebuffer else { return }
        screenSize = ScreenSize(width: Int(framebuffer.size.width), height: Int(framebuffer.size.height))
        if let image = framebuffer.cgImage { self.image = image }
    }
}

/// Receives RoyalVNCKit callbacks on its own queue and hands them to the Session on the main actor. `session` is read
/// there, so clearing it also drops the callbacks already on their way.
private final class LinkDelegate: NSObject, VNCConnectionDelegate, Sendable {
    nonisolated(unsafe) weak var session: Session?
    private let isScheduled = Mutex(false)

    init(session: Session) {
        self.session = session
    }

    func connection(_ connection: VNCConnection, stateDidChange connectionState: VNCConnection.ConnectionState) {
        let status = connectionState.status
        let failure = connectionState.error.flatMap(Session.Failure.init)
        Task { @MainActor [self] in session?.linkStatusChanged(status, failure: failure) }
    }

    func connection(_ connection: VNCConnection,
                    credentialFor authenticationType: VNCAuthenticationType,
                    completion: @escaping (VNCCredential?) -> Void) {
        let request = CredentialRequest(needsUsername: authenticationType.requiresUsername)
        let reply = CredentialReply(send: completion)
        Task { @MainActor [self] in
            guard let session else { return reply.send(nil) }
            session.credentialsRequested(request, reply: reply)
        }
    }

    func connection(_ connection: VNCConnection,
                    shouldTrustServerKey fingerprint: Data,
                    completion: @escaping (Bool) -> Void) {
        let reply = ServerKeyReply(fingerprint: fingerprint, send: completion)
        Task { @MainActor [self] in
            guard let session else { return reply.send(false) }
            session.serverKeyPresented(reply)
        }
    }

    func connection(_ connection: VNCConnection, didCreateFramebuffer framebuffer: VNCFramebuffer) {
        framebufferChanged()
    }

    func connection(_ connection: VNCConnection, didResizeFramebuffer framebuffer: VNCFramebuffer) {
        framebufferChanged()
    }

    func connection(_ connection: VNCConnection,
                    didUpdateFramebuffer framebuffer: VNCFramebuffer,
                    x: UInt16, y: UInt16, width: UInt16, height: UInt16) {
        framebufferChanged()
    }

    func connection(_ connection: VNCConnection, didUpdateCursor cursor: VNCCursor) {
        let cursor = RemoteCursor(image: cursor.cgImage, hotspot: cursor.cgHotspot)
        Task { @MainActor [self] in session?.cursorChanged(cursor) }
    }

    func connection(_ connection: VNCConnection, didReceiveClipboardText text: String) {
        Task { @MainActor [self] in session?.remoteClipboardChanged(text) }
    }

    /// Schedules one render for a burst of changes. The flag is cleared before rendering,
    /// so a change landing during a render schedules another one and is never lost.
    private func framebufferChanged() {
        let alreadyScheduled = isScheduled.withLock { scheduled in
            defer { scheduled = true }
            return scheduled
        }
        guard !alreadyScheduled else { return }
        Task { @MainActor [self] in
            isScheduled.withLock { $0 = false }
            session?.framebufferChanged()
        }
    }
}

/// RoyalVNCKit's credential completion, carried to the main actor and called exactly once from there.
private struct CredentialReply: @unchecked Sendable {
    let send: (VNCCredential?) -> Void
}

/// RoyalVNCKit's server key completion with the key's SHA-256 fingerprint, called exactly once from the main actor.
private struct ServerKeyReply: @unchecked Sendable {
    let fingerprint: Data
    let send: (Bool) -> Void
}

extension Session.Failure {
    /// Sorts RoyalVNCKit's error into the kinds the user is told apart. Nil for endings the user chose.
    init?(_ error: Error) {
        switch error {
        case VNCError.authentication(.noAuthenticationDataProvided), VNCError.authentication(.serverKeyNotTrusted):
            return nil
        case VNCError.authentication(.clientCouldNotDecideOnSecurityType):
            self = .unsupportedSecurityType
        case VNCError.authentication(.securityHandshakingFailed), VNCError.authentication(.ardAuthenticationFailed),
             VNCError.authentication(.rsaAESAuthenticationFailed), VNCError.authentication(.ultraVNCMSLogonIIAuthenticationFailed):
            self = .authenticationFailed
        case VNCError.connection(.failed(let underlying as NWError)):
            switch underlying {
            case .posix(.ECONNREFUSED):
                self = .refused
            case .dns, .posix(.EHOSTUNREACH), .posix(.ENETUNREACH), .posix(.EHOSTDOWN), .posix(.ENETDOWN),
                 .posix(.ETIMEDOUT):
                self = .unreachable
            default:
                self = .other(error.localizedDescription)
            }
        default:
            self = .other(error.localizedDescription)
        }
    }
}
