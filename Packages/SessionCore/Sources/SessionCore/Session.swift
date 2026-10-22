import CoreGraphics
import Foundation
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
        case disconnected(error: String?)
    }

    public let address: String
    public let port: UInt16
    public private(set) var state: State = .disconnected(error: nil)
    public private(set) var screenSize: ScreenSize?
    /// The latest picture of the remote screen.
    public private(set) var image: CGImage?
    /// Set while the server waits for `submitCredentials` or `cancelCredentials`.
    public private(set) var credentialRequest: CredentialRequest?
    /// Set while the Session waits for the user to accept or refuse a changed server key.
    public private(set) var serverKeyChange: ServerKeyChange?

    @ObservationIgnored private var link: VNCConnection?
    @ObservationIgnored private var linkDelegate: LinkDelegate?
    @ObservationIgnored private var credentialReply: CredentialReply?
    @ObservationIgnored private var serverKeyReply: ServerKeyReply?
    /// Remembers each server's key fingerprint by address and port, trusting the first one seen.
    @ObservationIgnored private let knownServerKeys: UserDefaults

    public init(address: String, port: UInt16, knownServerKeys: UserDefaults = .standard) {
        self.address = address
        self.port = port
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
        link.connect()
    }

    public func disconnect() {
        cancelCredentials()
        rejectServerKey()
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
            // shortcut: only keys with a fixed unmodified keysym are sent; Keyboard Profiles (#4) replace this.
            guard let keysym = key.keysym else { return }
            if isDown {
                link.keyDown(VNCKeyCode(keysym))
            } else {
                link.keyUp(VNCKeyCode(keysym))
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

    private func remotePixel(_ x: Double, _ y: Double) -> (UInt16, UInt16)? {
        guard let screenSize, screenSize.width > 0, screenSize.height > 0 else { return nil }
        let maxX = Double(screenSize.width - 1)
        let maxY = Double(screenSize.height - 1)
        return (UInt16(min(max(x, 0), maxX)), UInt16(min(max(y, 0), maxY)))
    }

    fileprivate func linkStatusChanged(_ status: VNCConnection.Status, error: String?) {
        switch status {
        case .connecting: state = .connecting
        case .connected: state = .connected
        case .disconnected:
            credentialReply = nil
            credentialRequest = nil
            serverKeyReply = nil
            serverKeyChange = nil
            state = .disconnected(error: error)
        case .disconnecting: break
        }
    }

    fileprivate func credentialsRequested(_ request: CredentialRequest, reply: CredentialReply) {
        credentialRequest = request
        credentialReply = reply
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
        let error = connectionState.error.map { ($0 as NSError).localizedDescription }
        Task { @MainActor [weak session] in session?.linkStatusChanged(status, error: error) }
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
