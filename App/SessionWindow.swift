import SessionCore
import SwiftUI

struct SessionWindow: View {
    let target: SessionTarget
    @State private var session: Session

    init(target: SessionTarget) {
        self.target = target
        _session = State(initialValue: Session(address: target.address, port: target.port))
    }

    var body: some View {
        FramebufferView(session: session)
            .background(.black)
            .overlay {
                if let status {
                    Text(status)
                        .padding(.horizontal, 20)
                        .padding(.vertical, 12)
                        .glassEffect()
                }
            }
            .navigationTitle("\(target.address):\(target.port)")
            .toolbar {
                if session.state == .connected {
                    Button("Disconnect", systemImage: "xmark", action: session.disconnect)
                } else if case .disconnected = session.state {
                    Button("Connect", systemImage: "arrow.clockwise", action: session.connect)
                }
            }
            .sheet(isPresented: Binding(
                get: { session.credentialRequest != nil },
                set: { if !$0 { session.cancelCredentials() } }
            )) {
                CredentialsForm(session: session, target: target)
            }
            .onAppear(perform: session.connect)
            .onDisappear(perform: session.disconnect)
    }

    private var status: String? {
        switch session.state {
        case .connecting: "Connecting…"
        case .connected: nil
        case .disconnected(let error): error.map { "Disconnected: \($0)" } ?? "Disconnected"
        }
    }
}

/// Asks for the login the server requires. Nothing is saved; Keychain storage comes with saved Connections.
private struct CredentialsForm: View {
    let session: Session
    let target: SessionTarget
    @State private var username = ""
    @State private var password = ""

    var body: some View {
        Form {
            Section("Log in to \(target.address)") {
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
