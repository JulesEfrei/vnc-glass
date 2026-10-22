import SessionCore
import SwiftUI

@main
struct VNCGlassApp: App {
    @State private var store = ConnectionStore()

    var body: some Scene {
        Window("Connections", id: "connections") {
            ConnectionsView(store: store)
        }
        .defaultSize(width: 720, height: 460)

        WindowGroup(for: Connection.ID.self) { $id in
            if let connection = store.connections.first(where: { $0.id == id }) {
                SessionWindow(connection: connection, password: store.password(for: connection.id))
            }
        }
        .defaultSize(width: 1280, height: 800)
        .windowToolbarStyle(.unifiedCompact)

        Settings {
            SettingsView()
        }
    }
}
