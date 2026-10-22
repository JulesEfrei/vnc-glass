import SessionCore
import SwiftUI

struct SessionWindow: View {
    let connection: Connection
    @State private var session: Session
    @State private var isUnauthenticatedWarningDismissed = false

    init(connection: Connection, password: String?) {
        self.connection = connection
        _session = State(initialValue: Session(address: connection.address, port: connection.port,
                                               username: connection.username, password: password,
                                               keyboardProfile: connection.keyboardProfile,
                                               displaySizing: connection.displaySizing))
    }

    var body: some View {
        FramebufferView(session: session)
            .background(.black)
            .overlay {
                if let status {
                    VStack(spacing: 12) {
                        Text(status)
                        if case .disconnected = session.state {
                            Button("Reconnect", systemImage: "arrow.clockwise", action: session.connect)
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.vertical, 12)
                    .glassEffect(in: .rect(cornerRadius: 16))
                }
            }
            .overlay(alignment: .top) {
                if session.isUnauthenticatedOutsideTailscale && !isUnauthenticatedWarningDismissed {
                    UnauthenticatedWarning(address: connection.address) { isUnauthenticatedWarningDismissed = true }
                        .padding()
                }
            }
            .navigationTitle(connection.name)
            .navigationSubtitle("\(connection.address):\(connection.port)")
            .toolbar {
                if session.state == .connected {
                    LockModeButton(session: session)
                }
                if session.state == .connected || session.state == .reconnecting {
                    Button("Disconnect", systemImage: "xmark", action: session.disconnect)
                }
            }
            .sheet(isPresented: Binding(
                get: { session.credentialRequest != nil },
                set: { if !$0 { session.cancelCredentials() } }
            )) {
                CredentialsForm(session: session, address: connection.address)
            }
            .alert("The server's identity has changed", isPresented: Binding(
                get: { session.serverKeyChange != nil },
                set: { if !$0 { session.rejectServerKey() } }
            )) {
                Button("Disconnect", role: .cancel, action: session.rejectServerKey)
                Button("Trust New Key", role: .destructive, action: session.trustServerKey)
            } message: {
                Text("""
                \(connection.address) sent a different key than last time. This happens when the server is \
                reinstalled or its key is replaced, but it can also mean someone is intercepting the connection.

                New key: \(session.serverKeyChange?.fingerprint ?? "")
                """)
            }
            .task(id: session.state == .connected) {
                if session.state == .connected { await sendLocalClipboard() }
            }
            .onChange(of: session.remoteClipboardText) { _, text in
                guard let text else { return }
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
            .onAppear(perform: session.connect)
            .onDisappear(perform: session.disconnect)
    }

    /// Hands every change of the Mac's clipboard text to the Session, starting with what is on it now. The pasteboard
    /// has no change notification, so it is polled until the task is cancelled.
    private func sendLocalClipboard() async {
        var changeCount: Int?
        while !Task.isCancelled {
            let pasteboard = NSPasteboard.general
            if pasteboard.changeCount != changeCount {
                changeCount = pasteboard.changeCount
                session.localClipboardChanged(text: pasteboard.string(forType: .string),
                                              types: pasteboard.types?.map(\.rawValue) ?? [])
            }
            try? await Task.sleep(for: .milliseconds(500))
        }
    }

    private var status: String? {
        switch session.state {
        case .connecting: "Connecting…"
        case .connected: nil
        case .reconnecting: "Reconnecting…"
        case .disconnected(nil): "Disconnected"
        case .disconnected(.unreachable?):
            "\(connection.address) could not be reached. Check the address and that the computer is online."
        case .disconnected(.refused?):
            "\(connection.address) refused to connect. Check the port and that its VNC server is running."
        case .disconnected(.authenticationFailed?): "The username or password was not accepted."
        case .disconnected(.unsupportedSecurityType?):
            "The server only offers login methods VNC Glass does not support."
        case .disconnected(.other(let message)?): "Disconnected: \(message)"
        }
    }
}

/// Shows the Session's Lock Mode and turns it on and off, or explains the missing permission.
private struct LockModeButton: View {
    let session: Session
    @State private var isExplainingPermission = false

    var body: some View {
        Button {
            if session.isLockModeAvailable { session.toggleLockMode() } else { isExplainingPermission = true }
        } label: {
            if !session.isLockModeAvailable {
                Label("Lock Mode Unavailable", systemImage: "lock.trianglebadge.exclamationmark")
            } else {
                switch session.lockMode {
                case .unlocked: Label("Unlocked", systemImage: "lock.open")
                case .locked: Label("Locked", systemImage: "lock.fill")
                case .paused: Label("Paused", systemImage: "lock")
                }
            }
        }
        .labelStyle(.titleAndIcon)
        .help("Lock Mode sends every shortcut, like ⌘Tab and ⌘Q, to the remote computer. Press and release left ⌃⌥ to turn it on or off.")
        .alert("Lock Mode needs the Accessibility permission", isPresented: $isExplainingPermission) {
            Button("Open System Settings") {
                // Asking adds VNC Glass to the Accessibility list, so the user only has to turn it on. The key is
                // kAXTrustedCheckOptionPrompt, which Swift 6 rejects as a mutable global.
                AXIsProcessTrustedWithOptions(["AXTrustedCheckOptionPrompt": true] as CFDictionary)
                NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("To send shortcuts like ⌘Tab and ⌘Space to the remote computer instead of the Mac, turn on VNC Glass in Privacy & Security › Accessibility.")
        }
    }
}

/// Tells the user that the server let them in without any login while not on a Tailscale address.
private struct UnauthenticatedWarning: View {
    let address: String
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: "exclamationmark.shield.fill")
                .foregroundStyle(.yellow)
            VStack(alignment: .leading, spacing: 2) {
                Text("This server asks for no login")
                    .font(.headline)
                Text("Anyone who can reach \(address) can control this computer, and the session is not encrypted.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Button("Dismiss", systemImage: "xmark", action: dismiss)
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .frame(maxWidth: 520)
        .glassEffect(in: .rect(cornerRadius: 16))
    }
}

/// Asks for the login the server requires when the Connection has no saved password, or the saved one was rejected.
private struct CredentialsForm: View {
    let session: Session
    let address: String
    @State private var username: String
    @State private var password = ""

    init(session: Session, address: String) {
        self.session = session
        self.address = address
        _username = State(initialValue: session.username)
    }

    var body: some View {
        Form {
            Section("Log in to \(address)") {
                if session.credentialRequest?.needsUsername == true {
                    TextField("Username", text: $username)
                        .textContentType(.username)
                }
                SecureField("Password", text: $password)
                    .textContentType(.password)
            }
        }
        .formStyle(.grouped)
        .frame(width: 360)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel", action: session.cancelCredentials)
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Log In") {
                    session.submitCredentials(username: username, password: password)
                }
            }
        }
    }
}
