import Foundation
import SessionCore
import Testing

@MainActor
struct ConnectionStoreTests {
    private let defaults = UserDefaults(suiteName: "ConnectionStoreTests.\(UUID().uuidString)")!
    private let keychain = Keychain(service: "com.julesefrei.vncglass.tests.\(UUID().uuidString)")

    @Test func savedConnectionsAreThereForTheNextLaunch() throws {
        let store = ConnectionStore(defaults: defaults, keychain: keychain)
        var desk = Connection(name: "Desk", address: "100.64.0.1", port: 5900, username: "jane")
        try store.save(desk, password: "")
        try store.save(Connection(name: "Laptop", address: "laptop.local", port: 5901, username: ""), password: "")
        desk.port = 5902
        try store.save(desk, password: "")

        let relaunched = ConnectionStore(defaults: defaults, keychain: keychain)

        #expect(relaunched.connections.map(\.name) == ["Desk", "Laptop"])
        #expect(relaunched.connections.first?.port == 5902)

        relaunched.delete(desk)
        #expect(ConnectionStore(defaults: defaults, keychain: keychain).connections.map(\.name) == ["Laptop"])
    }

    @Test func passwordsLiveInKeychainNotInTheStore() throws {
        let store = ConnectionStore(defaults: defaults, keychain: keychain)
        let desk = Connection(name: "Desk", address: "100.64.0.1", port: 5900, username: "jane")
        defer { store.delete(desk) }

        try store.save(desk, password: "hunter2-secret")

        #expect(ConnectionStore(defaults: defaults, keychain: keychain).password(for: desk.id) == "hunter2-secret")
        let stored = defaults.dictionaryRepresentation().values.compactMap { $0 as? Data }
        #expect(!stored.isEmpty)
        #expect(stored.allSatisfy { !String(decoding: $0, as: UTF8.self).contains("hunter2") })

        try store.save(desk, password: "changed")
        #expect(store.password(for: desk.id) == "changed")

        store.delete(desk)
        #expect(store.password(for: desk.id) == nil)
    }

    @Test func anEmptyPasswordRemovesTheSavedOne() throws {
        let store = ConnectionStore(defaults: defaults, keychain: keychain)
        let desk = Connection(name: "Desk", address: "100.64.0.1", port: 5900, username: "")
        try store.save(desk, password: "secret")

        try store.save(desk, password: "")

        #expect(store.password(for: desk.id) == nil)
    }
}
