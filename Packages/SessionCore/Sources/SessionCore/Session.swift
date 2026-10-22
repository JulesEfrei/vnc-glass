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
        /// Nil when the Session ended without a fault, as when the user disconnected or declined to log in.
        case disconnected(Failure?)
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
    /// Set while the server waits for `submitCredentials` or `cancelCredentials`.
    public private(set) var credentialRequest: CredentialRequest?
    /// Set while the Session waits for the user to accept or refuse a changed server key.
    public private(set) var serverKeyChange: ServerKeyChange?
    /// The server let the Session in without any login (security type None) and the address is not a Tailscale one, so
    /// anyone who can reach the server can control it.
    public private(set) var isUnauthenticatedOutsideTailscale = false

    @ObservationIgnored private var link: VNCConnection?
    @ObservationIgnored private var linkDelegate: LinkDelegate?
    @ObservationIgnored private var credentialReply: CredentialReply?
    @ObservationIgnored private var serverKeyReply: ServerKeyReply?
    /// Remembers each server's key fingerprint by address and port, trusting the first one seen.
    @ObservationIgnored private let knownServerKeys: UserDefaults
    /// The username given to servers that ask for one, and prefilled in the prompt.
    public let username: String
    public let keyboardProfile: KeyboardProfile
    /// Answers the server's login without asking. Dropped once the server rejects it, so the user is asked instead.
    @ObservationIgnored private var savedPassword: String?
    @ObservationIgnored private var wasAskedForCredentials = false
    /// Remote keys sent down and not yet up, with how many local keys hold each (both ⌥ keys hold Alt_L).
    /// Released on disconnect so none stay stuck (wayvnc #461).
    @ObservationIgnored private var heldKeys: [KeyCode: Int] = [:]

    public init(address: String, port: UInt16, username: String = "", password: String? = nil,
                keyboardProfile: KeyboardProfile = .default, knownServerKeys: UserDefaults = .standard) {
        self.address = address
        self.port = port
        self.username = username
        self.keyboardProfile = keyboardProfile
        savedPassword = password
        self.knownServerKeys = knownServerKeys
    }

    public func connect() {
        guard case .disconnected = state else { return }
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
        state = .connecting
        wasAskedForCredentials = false
        isUnauthenticatedOutsideTailscale = false
        link.connect()
    }

    public func disconnect() {
        cancelCredentials()
        rejectServerKey()
        releaseHeldKeys()
        link?.disconnect()
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

    public func handle(_ event: InputEvent) {
        guard let link, state == .connected else { return }
        switch event {
        case .key(let key, let isDown):
            let remoteKey = keyboardProfile.remoteKey(for: key)
            guard let (keysym, scancode) = remoteKey.remote else { return }
            if isDown {
                heldKeys[remoteKey, default: 0] += 1
                if heldKeys[remoteKey] == 1 { link.keyDown(VNCKeyCode(keysym), scancode: scancode) }
            } else if let count = heldKeys[remoteKey] {
                heldKeys[remoteKey] = count > 1 ? count - 1 : nil
                if count == 1 { link.keyUp(VNCKeyCode(keysym), scancode: scancode) }
            }
        case .pointerMoved(let x, let y):
            guard let (x, y) = remotePixel(x, y) else { return }
            link.mouseMove(x: x, y: y)
        case .pointerButton(let button, let isDown, let x, let y):
            guard let (x, y) = remotePixel(x, y) else { return }
            let button: VNCMouseButton = button == .left ? .left : .right
            if isDown {
                link.mouseButtonDown(button, x: x, y: y)
            } else {
                link.mouseButtonUp(button, x: x, y: y)
            }
        }
    }

    private func releaseHeldKeys() {
        for key in heldKeys.keys {
            guard let (keysym, scancode) = key.remote else { continue }
            link?.keyUp(VNCKeyCode(keysym), scancode: scancode)
        }
        heldKeys = [:]
    }

    private func remotePixel(_ x: Double, _ y: Double) -> (UInt16, UInt16)? {
        guard let screenSize, screenSize.width > 0, screenSize.height > 0 else { return nil }
        let maxX = Double(screenSize.width - 1)
        let maxY = Double(screenSize.height - 1)
        return (UInt16(min(max(x, 0), maxX)), UInt16(min(max(y, 0), maxY)))
    }

    fileprivate func linkStatusChanged(_ status: VNCConnection.Status, failure: Failure?) {
        switch status {
        case .connecting: state = .connecting
        case .connected:
            // Every login RoyalVNCKit performs asks for credentials, so connecting without being asked means None.
            isUnauthenticatedOutsideTailscale = !wasAskedForCredentials && !Self.isTailscaleAddress(address)
            state = .connected
        case .disconnected:
            credentialReply = nil
            credentialRequest = nil
            serverKeyReply = nil
            serverKeyChange = nil
            heldKeys = [:]
            if failure == .authenticationFailed { savedPassword = nil }
            state = .disconnected(failure)
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

    fileprivate func framebufferChanged() {
        guard let framebuffer = link?.framebuffer else { return }
        screenSize = ScreenSize(width: Int(framebuffer.size.width), height: Int(framebuffer.size.height))
        if let image = framebuffer.cgImage { self.image = image }
    }
}

/// Receives RoyalVNCKit callbacks on its own queue and hands them to the Session on the main actor.
private final class LinkDelegate: NSObject, VNCConnectionDelegate, Sendable {
    nonisolated(unsafe) weak var session: Session?
    private let isScheduled = Mutex(false)

    init(session: Session) {
        self.session = session
    }

    func connection(_ connection: VNCConnection, stateDidChange connectionState: VNCConnection.ConnectionState) {
        let status = connectionState.status
        let failure = connectionState.error.flatMap(Session.Failure.init)
        Task { @MainActor [weak session] in session?.linkStatusChanged(status, failure: failure) }
    }

    func connection(_ connection: VNCConnection,
                    credentialFor authenticationType: VNCAuthenticationType,
                    completion: @escaping (VNCCredential?) -> Void) {
        let request = CredentialRequest(needsUsername: authenticationType.requiresUsername)
        let reply = CredentialReply(send: completion)
        Task { @MainActor [weak session] in
            guard let session else { return reply.send(nil) }
            session.credentialsRequested(request, reply: reply)
        }
    }

    func connection(_ connection: VNCConnection,
                    shouldTrustServerKey fingerprint: Data,
                    completion: @escaping (Bool) -> Void) {
        let reply = ServerKeyReply(fingerprint: fingerprint, send: completion)
        Task { @MainActor [weak session] in
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

    func connection(_ connection: VNCConnection, didUpdateCursor cursor: VNCCursor) {}

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
