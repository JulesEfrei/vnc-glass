import SwiftUI

/// The remote computer a Session window is opened for.
struct SessionTarget: Codable, Hashable {
    var address: String
    var port: UInt16
}

@main
struct VNCGlassApp: App {
    var body: some Scene {
        Window("Connect", id: "connect") {
            ConnectView()
        }
        .windowResizability(.contentSize)

        WindowGroup(for: SessionTarget.self) { $target in
            if let target {
                SessionWindow(target: target)
            }
        }
        .defaultSize(width: 1280, height: 800)
    }
}

struct ConnectView: View {
    @Environment(\.openWindow) private var openWindow
    @State private var address = ""
    @State private var port = "5900"

    var body: some View {
        Form {
            TextField("Address", text: $address, prompt: Text("100.64.0.1"))
            TextField("Port", text: $port)
        }
        .formStyle(.grouped)
        .frame(width: 360)
        .toolbar {
            Button("Connect", systemImage: "play.fill", action: connect)
                .disabled(target == nil)
                .keyboardShortcut(.defaultAction)
        }
    }

    private var target: SessionTarget? {
        let address = address.trimmingCharacters(in: .whitespaces)
        guard !address.isEmpty, let port = UInt16(port) else { return nil }
        return SessionTarget(address: address, port: port)
    }

    private func connect() {
        if let target { openWindow(value: target) }
    }
}
