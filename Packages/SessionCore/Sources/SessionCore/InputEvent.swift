/// A physical key, identified by its USB HID usage (keyboard page) so macOS and iPadOS share one code.
public struct KeyCode: Hashable, Sendable {
    public let hidUsage: UInt16

    public init(hidUsage: UInt16) {
        self.hidUsage = hidUsage
    }

    /// The X11 keysym this key sends with no modifiers, and its XT (set 1) scancode with E0-prefixed keys as 0xE0xx.
    /// Nil for keys the Session does not send.
    var remote: (keysym: UInt32, scancode: UInt16)? {
        switch hidUsage {
        case 0x04...0x1D: (0x61 + UInt32(hidUsage - 0x04), letterScancodes[Int(hidUsage - 0x04)]) // a-z
        case 0x1E...0x26: (0x31 + UInt32(hidUsage - 0x1E), 0x02 + hidUsage - 0x1E) // 1-9
        case 0x27: (0x30, 0x0B) // 0
        case 0x28: (0xFF0D, 0x1C) // Return
        case 0x29: (0xFF1B, 0x01) // Escape
        case 0x2A: (0xFF08, 0x0E) // BackSpace
        case 0x2B: (0xFF09, 0x0F) // Tab
        case 0x2C: (0x20, 0x39) // space
        case 0x2D: (0x2D, 0x0C) // minus
        case 0x2E: (0x3D, 0x0D) // equal
        case 0x2F: (0x5B, 0x1A) // bracketleft
        case 0x30: (0x5D, 0x1B) // bracketright
        case 0x31: (0x5C, 0x2B) // backslash
        case 0x33: (0x3B, 0x27) // semicolon
        case 0x34: (0x27, 0x28) // apostrophe
        case 0x35: (0x60, 0x29) // grave
        case 0x36: (0x2C, 0x33) // comma
        case 0x37: (0x2E, 0x34) // period
        case 0x38: (0x2F, 0x35) // slash
        case 0x3A...0x43: (0xFFBE + UInt32(hidUsage - 0x3A), 0x3B + hidUsage - 0x3A) // F1-F10
        case 0x44: (0xFFC8, 0x57) // F11
        case 0x45: (0xFFC9, 0x58) // F12
        case 0x49: (0xFF63, 0xE052) // Insert
        case 0x4A: (0xFF50, 0xE047) // Home
        case 0x4B: (0xFF55, 0xE049) // Prior
        case 0x4C: (0xFFFF, 0xE053) // Delete
        case 0x4D: (0xFF57, 0xE04F) // End
        case 0x4E: (0xFF56, 0xE051) // Next
        case 0x4F: (0xFF53, 0xE04D) // Right
        case 0x50: (0xFF51, 0xE04B) // Left
        case 0x51: (0xFF54, 0xE050) // Down
        case 0x52: (0xFF52, 0xE048) // Up
        case 0x64: (0x3C, 0x56) // less, the ISO key beside left Shift
        case 0xE0: (0xFFE3, 0x1D) // Control_L
        case 0xE1: (0xFFE1, 0x2A) // Shift_L
        case 0xE2: (0xFFE9, 0x38) // Alt_L
        case 0xE3: (0xFFEB, 0xE05B) // Super_L
        case 0xE4: (0xFFE4, 0xE01D) // Control_R
        case 0xE5: (0xFFE2, 0x36) // Shift_R
        case 0xE6: (0xFFEA, 0xE038) // Alt_R
        case 0xE7: (0xFFEC, 0xE05C) // Super_R
        default: nil
        }
    }
}

/// XT scancodes of a-z, in HID order.
private let letterScancodes: [UInt16] = [
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
    0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
]

/// The rule set for translating local modifier keys to remote ones, chosen per Connection.
/// Both ⌥ keys send Alt in every profile, since Linux layouts often turn the right one into AltGr.
public enum KeyboardProfile: String, Codable, CaseIterable, Sendable {
    /// Cmd → Super, ⌃ → Ctrl, ⌥ → Alt.
    case `default`
    /// Cmd → Ctrl, ⌃ → Ctrl, ⌥ → Alt.
    case macStyle

    /// The key to press on the remote for this local key.
    func remoteKey(for key: KeyCode) -> KeyCode {
        switch (self, key.hidUsage) {
        case (_, 0xE6): KeyCode(hidUsage: 0xE2) // right ⌥ → left Alt
        case (.macStyle, 0xE3): KeyCode(hidUsage: 0xE0) // left Cmd → left Ctrl
        case (.macStyle, 0xE7): KeyCode(hidUsage: 0xE4) // right Cmd → right Ctrl
        default: key
        }
    }
}

public enum PointerButton: Sendable {
    case left
    case right
}

/// Local input, independent of the platform it came from.
/// Pointer positions are in remote screen pixels, origin at the top left.
public enum InputEvent: Sendable {
    case key(KeyCode, isDown: Bool)
    case pointerMoved(x: Double, y: Double)
    case pointerButton(PointerButton, isDown: Bool, x: Double, y: Double)
}
