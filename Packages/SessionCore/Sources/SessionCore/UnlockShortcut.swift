/// The modifier keys that, pressed together and released with no other key in between, toggle Lock Mode and never reach
/// the remote. Only modifiers, so holding one back until it proves not to be the shortcut never delays typing.
public struct UnlockShortcut: Hashable, Sendable {
    public let keys: Set<KeyCode>

    /// Nil unless `keys` holds two or more keys, all of them modifiers: a lone modifier tap, like ⌘ for the Linux
    /// launcher, must still reach the remote.
    public init?(keys: Set<KeyCode>) {
        guard keys.count >= 2, keys.allSatisfy({ (0xE0...0xE7).contains($0.hidUsage) }) else { return nil }
        self.keys = keys
    }

    public static let `default` = UnlockShortcut(keys: [KeyCode(hidUsage: 0xE0), KeyCode(hidUsage: 0xE2)])! // left ⌃⌥
}

/// Stored as the keys' HID usages, comma separated, as `@AppStorage` keeps it.
extension UnlockShortcut: RawRepresentable {
    public init?(rawValue: String) {
        let parts = rawValue.split(separator: ",")
        let usages = parts.compactMap { UInt16($0) }
        guard usages.count == parts.count else { return nil }
        self.init(keys: Set(usages.map(KeyCode.init(hidUsage:))))
    }

    public var rawValue: String {
        keys.map(\.hidUsage).sorted().map(String.init).joined(separator: ",")
    }
}

extension UnlockShortcut: CustomStringConvertible {
    /// Each side's symbols in the Mac's order, as in "left ⌃⌥" or "left ⇧ right ⌘".
    public var description: String {
        [("left", 0xE0 as UInt16), ("right", 0xE4)].compactMap { side, first in
            let symbols = zip(["⌃", "⌥", "⇧", "⌘"], [0, 2, 1, 3])
                .filter { keys.contains(KeyCode(hidUsage: first + $1)) }
                .map(\.0)
            return symbols.isEmpty ? nil : "\(side) \(symbols.joined())"
        }.joined(separator: " ")
    }
}
