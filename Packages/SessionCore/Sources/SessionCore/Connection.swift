import Foundation
import Observation
import Security

/// A saved remote computer the user can connect to. Its password is kept in Keychain, not here.
public struct Connection: Codable, Hashable, Identifiable, Sendable {
    public var id = UUID()
    public var name: String
    public var address: String
    public var port: UInt16
    /// Empty when the server asks for a password only.
    public var username: String
    public var keyboardProfile: KeyboardProfile = .default

    public init(name: String, address: String, port: UInt16, username: String) {
        self.name = name
        self.address = address
        self.port = port
        self.username = username
    }

    // Connections saved before Keyboard Profiles existed have none; without this they would all fail to load.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        address = try container.decode(String.self, forKey: .address)
        port = try container.decode(UInt16.self, forKey: .port)
        username = try container.decode(String.self, forKey: .username)
        keyboardProfile = try container.decodeIfPresent(KeyboardProfile.self, forKey: .keyboardProfile) ?? .default
    }
}

/// The user's saved Connections, kept in UserDefaults, with their passwords in Keychain.
@MainActor @Observable
public final class ConnectionStore {
    public private(set) var connections: [Connection]

    @ObservationIgnored private let defaults: UserDefaults
    @ObservationIgnored private let keychain: Keychain
    private static let defaultsKey = "Connections"

    public init(defaults: UserDefaults = .standard, keychain: Keychain = Keychain()) {
        self.defaults = defaults
        self.keychain = keychain
        connections = defaults.data(forKey: Self.defaultsKey)
            .flatMap { try? JSONDecoder().decode([Connection].self, from: $0) } ?? []
    }

    /// Adds the Connection or replaces the one with its id. An empty password removes the saved one.
    public func save(_ connection: Connection, password: String) throws {
        try keychain.setPassword(password, for: connection.id)
        if let index = connections.firstIndex(where: { $0.id == connection.id }) {
            connections[index] = connection
        } else {
            connections.append(connection)
        }
        persist()
    }

    public func delete(_ connection: Connection) {
        try? keychain.setPassword("", for: connection.id)
        connections.removeAll { $0.id == connection.id }
        persist()
    }

    public func password(for id: Connection.ID) -> String? {
        keychain.password(for: id)
    }

    private func persist() {
        defaults.set(try? JSONEncoder().encode(connections), forKey: Self.defaultsKey)
    }
}

/// Generic passwords in the user's Keychain, one per Connection.
public struct Keychain: Sendable {
    public let service: String

    public init(service: String = "com.julesefrei.vncglass") {
        self.service = service
    }

    public func password(for id: Connection.ID) -> String? {
        var query = query(for: id)
        query[kSecReturnData] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// Saves the password, or removes it when empty.
    public func setPassword(_ password: String, for id: Connection.ID) throws {
        let query = query(for: id)
        var status: OSStatus
        if password.isEmpty {
            status = SecItemDelete(query as CFDictionary)
        } else {
            let data = Data(password.utf8)
            status = SecItemUpdate(query as CFDictionary, [kSecValueData: data] as CFDictionary)
            if status == errSecItemNotFound {
                status = SecItemAdd(query.merging([kSecValueData: data, kSecAttrLabel: "VNC Glass"]) { $1 } as CFDictionary, nil)
            }
        }
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError(status: status) }
    }

    private func query(for id: Connection.ID) -> [CFString: Any] {
        [kSecClass: kSecClassGenericPassword, kSecAttrService: service, kSecAttrAccount: id.uuidString]
    }
}

public struct KeychainError: LocalizedError {
    public let status: OSStatus

    public var errorDescription: String? {
        SecCopyErrorMessageString(status, nil) as String? ?? "Keychain error \(status)."
    }
}
