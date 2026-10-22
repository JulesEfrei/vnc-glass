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
