/// A physical key, identified by its USB HID usage (keyboard page) so macOS and iPadOS share one code.
public struct KeyCode: Hashable, Sendable {
    public let hidUsage: UInt16

    public init(hidUsage: UInt16) {
        self.hidUsage = hidUsage
    }

    /// The X11 keysym this key sends with no modifiers, if the Session knows it.
    var keysym: UInt32? {
        switch hidUsage {
        case 0x04...0x1D: 0x61 + UInt32(hidUsage - 0x04) // a-z
        case 0x1E...0x26: 0x31 + UInt32(hidUsage - 0x1E) // 1-9
        case 0x27: 0x30 // 0
        case 0x28: 0xFF0D // Return
        case 0x29: 0xFF1B // Escape
        case 0x2A: 0xFF08 // BackSpace
        case 0x2B: 0xFF09 // Tab
        case 0x2C: 0x20 // space
        default: nil
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
