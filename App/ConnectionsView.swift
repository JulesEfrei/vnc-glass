import SessionCore
import SwiftUI

/// The saved Connections in a sidebar, with the selected one's editor beside it.
struct ConnectionsView: View {
    let store: ConnectionStore
    @Environment(\.openWindow) private var openWindow
    @State private var selection: Connection.ID?

    var body: some View {
        NavigationSplitView {
            List(store.connections, selection: $selection) { connection in
                Label(connection.name, systemImage: "desktopcomputer")
            }
            .contextMenu(forSelectionType: Connection.ID.self) { ids in
                Button("Connect") { ids.forEach { openWindow(value: $0) } }
                Button("Delete", role: .destructive) { delete(ids) }
            } primaryAction: { ids in
                ids.forEach { openWindow(value: $0) }
            }
            .onDeleteCommand { delete([selection].compactMap(\.self)) }
            .navigationSplitViewColumnWidth(min: 180, ideal: 220)
            .toolbar {
                Button("Add Connection", systemImage: "plus", action: add)
            }
        } detail: {
            if let connection = store.connections.first(where: { $0.id == selection }) {
                ConnectionEditor(store: store, connection: connection)
                    .id(connection.id)
            } else {
                ContentUnavailableView("No Connection Selected", systemImage: "desktopcomputer",
                                       description: Text("Add a computer to connect to with the + button."))
            }
        }
    }

    private func add() {
        let connection = Connection(name: "New Connection", address: "", port: 5900, username: "")
        // An empty password touches nothing in Keychain, so this cannot fail.
        try? store.save(connection, password: "")
        selection = connection.id
    }

    private func delete(_ ids: some Sequence<Connection.ID>) {
        for id in ids {
            if let connection = store.connections.first(where: { $0.id == id }) { store.delete(connection) }
        }
    }
}

/// Edits one Connection. Changes are kept on Save or Connect.
private struct ConnectionEditor: View {
    let store: ConnectionStore
    @Environment(\.openWindow) private var openWindow
    @State private var draft: Connection
    @State private var port: String
    @State private var password: String
    @State private var saveError: String?

    init(store: ConnectionStore, connection: Connection) {
        self.store = store
        _draft = State(initialValue: connection)
        _port = State(initialValue: String(connection.port))
        _password = State(initialValue: store.password(for: connection.id) ?? "")
    }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $draft.name)
                TextField("Address", text: $draft.address, prompt: Text("100.64.0.1"))
                TextField("Port", text: $port)
            }
            Section {
                TextField("Username", text: $draft.username, prompt: Text("Only if the server asks for one"))
                    .textContentType(.username)
                SecureField("Password", text: $password, prompt: Text("Asked for when connecting if empty"))
                    .textContentType(.password)
            } header: {
                Text("Login")
            } footer: {
                Text("The password is kept in your Keychain.")
            }
            Section {
                Picker("Keyboard Profile", selection: $draft.keyboardProfile) {
                    Text("Default").tag(KeyboardProfile.default)
                    Text("Mac-style").tag(KeyboardProfile.macStyle)
                }
            } footer: {
                switch draft.keyboardProfile {
                case .default: Text("⌘ sends Super, ⌃ sends Ctrl, ⌥ sends Alt.")
                case .macStyle: Text("⌘ sends Ctrl, so ⌘C copies on the remote. ⌃ sends Ctrl, ⌥ sends Alt.")
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle(draft.name)
        .toolbar {
            Button("Save", systemImage: "checkmark") { _ = save() }
                .disabled(validated == nil)
            Button("Connect", systemImage: "play.fill") {
                if save() { openWindow(value: draft.id) }
            }
            .disabled(validated == nil)
            .keyboardShortcut(.defaultAction)
        }
        .alert("The Connection could not be saved", isPresented: Binding(
            get: { saveError != nil },
            set: { if !$0 { saveError = nil } }
        )) {} message: {
            Text(saveError ?? "")
        }
    }

    /// The draft with its port applied, or nil while the address or port is not usable.
    private var validated: Connection? {
        var connection = draft
        connection.address = draft.address.trimmingCharacters(in: .whitespaces)
        connection.username = draft.username.trimmingCharacters(in: .whitespaces)
        guard !connection.address.isEmpty, let port = UInt16(port) else { return nil }
        connection.port = port
        return connection
    }

    private func save() -> Bool {
        guard let connection = validated else { return false }
        do {
            try store.save(connection, password: password)
            return true
        } catch {
            saveError = error.localizedDescription
            return false
        }
    }
}
