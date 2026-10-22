import AppKit
import Carbon.HIToolbox
import SessionCore
import SwiftUI

/// Shows the remote screen scaled to fit and turns AppKit mouse and key events into Session input.
struct FramebufferView: NSViewRepresentable {
    let session: Session

    func makeNSView(context: Context) -> FramebufferNSView {
        FramebufferNSView(session: session)
    }

    func updateNSView(_ view: FramebufferNSView, context: Context) {
        view.layer?.contents = session.image
        view.isCapturingSystemShortcuts = session.lockMode == .locked
    }
}

final class FramebufferNSView: NSView {
    private let session: Session

    init(session: Session) {
        self.session = session
        super.init(frame: .zero)
        wantsLayer = true
        layer?.contentsGravity = .resizeAspect
        layer?.magnificationFilter = .linear
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError() }

    /// AppKit drops the key-up of a key released while Cmd is down, which would leave it held on the remote.
    private var keyUpMonitor: Any?

    override var acceptsFirstResponder: Bool { true }

    override func viewDidMoveToWindow() {
        window?.makeFirstResponder(self)
        if let keyUpMonitor { NSEvent.removeMonitor(keyUpMonitor) }
        keyUpMonitor = nil
        NotificationCenter.default.removeObserver(self)
        guard window != nil else {
            isCapturingSystemShortcuts = false
            return
        }
        session.isLockModeAvailable = AXIsProcessTrusted()
        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(windowDidBecomeKey), name: NSWindow.didBecomeKeyNotification, object: window)
        center.addObserver(self, selector: #selector(windowDidResignKey), name: NSWindow.didResignKeyNotification, object: window)
        center.addObserver(self, selector: #selector(windowDidEnterFullScreen), name: NSWindow.didEnterFullScreenNotification,
                           object: window)
        keyUpMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyUp) { [weak self] event in
            guard let self, event.modifierFlags.contains(.command), event.window === window,
                  window?.firstResponder === self else { return event }
            forwardKey(event, isDown: false)
            return nil
        }
    }

    // Checked on every focus, so a permission granted in System Settings works once the user comes back.
    @objc private func windowDidBecomeKey() {
        session.isLockModeAvailable = AXIsProcessTrusted()
        session.windowFocusChanged(isFocused: true)
    }

    @objc private func windowDidResignKey() { session.windowFocusChanged(isFocused: false) }
    @objc private func windowDidEnterFullScreen() { session.lock() }

    /// While Locked, an active event tap takes every key before macOS acts on it, so ⌘Tab, ⌘Space and ⌘Q reach the
    /// remote instead (ADR-0001). Needs the Accessibility permission.
    var isCapturingSystemShortcuts: Bool {
        get { keyTap != nil }
        set {
            guard newValue != isCapturingSystemShortcuts else { return }
            if newValue { startKeyTap() } else { stopKeyTap() }
        }
    }

    private var keyTap: CFMachPort?
    private var keyTapSource: CFRunLoopSource?

    private func startKeyTap() {
        let types: [CGEventType] = [.keyDown, .keyUp, .flagsChanged]
        let mask = types.reduce(CGEventMask(0)) { $0 | 1 << $1.rawValue }
        // The view outlives the tap: the tap stops when Lock Mode ends or the view leaves its window.
        guard let tap = CGEvent.tapCreate(tap: .cgSessionEventTap, place: .headInsertEventTap, options: .defaultTap,
                                          eventsOfInterest: mask, callback: { _, type, event, view in
            // The tap's run loop source is on the main run loop.
            nonisolated(unsafe) let event = event
            let isSwallowed = MainActor.assumeIsolated {
                Unmanaged<FramebufferNSView>.fromOpaque(view!).takeUnretainedValue().tapped(type, event)
            }
            return isSwallowed ? nil : Unmanaged.passUnretained(event)
        }, userInfo: Unmanaged.passUnretained(self).toOpaque()) else {
            // Refused, as when the permission was revoked since the last check; the Session then unlocks.
            session.isLockModeAvailable = false
            return
        }
        keyTap = tap
        keyTapSource = CFMachPortCreateRunLoopSource(nil, tap, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), keyTapSource, .commonModes)
    }

    private func stopKeyTap() {
        guard let keyTap else { return }
        CGEvent.tapEnable(tap: keyTap, enable: false)
        CFRunLoopRemoveSource(CFRunLoopGetMain(), keyTapSource, .commonModes)
        CFMachPortInvalidate(keyTap)
        self.keyTap = nil
        keyTapSource = nil
    }

    /// Hands a tapped key to the Session. True when macOS should not see it.
    private func tapped(_ type: CGEventType, _ event: CGEvent) -> Bool {
        switch type {
        case .tapDisabledByTimeout, .tapDisabledByUserInput:
            if let keyTap { CGEvent.tapEnable(tap: keyTap, enable: true) }
            return false
        case .keyDown: NSEvent(cgEvent: event).map { forwardKey($0, isDown: true) }
        case .keyUp: NSEvent(cgEvent: event).map { forwardKey($0, isDown: false) }
        case .flagsChanged: NSEvent(cgEvent: event).map(flagsChanged)
        default: return false
        }
        return true
    }

    override func updateTrackingAreas() {
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(rect: .zero, options: [.mouseMoved, .activeInKeyWindow, .inVisibleRect], owner: self))
        super.updateTrackingAreas()
    }

    override func mouseMoved(with event: NSEvent) { pointerMoved(event) }
    override func mouseDragged(with event: NSEvent) { pointerMoved(event) }
    override func rightMouseDragged(with event: NSEvent) { pointerMoved(event) }
    override func mouseDown(with event: NSEvent) { pointerButton(.left, isDown: true, event) }
    override func mouseUp(with event: NSEvent) { pointerButton(.left, isDown: false, event) }
    override func rightMouseDown(with event: NSEvent) { pointerButton(.right, isDown: true, event) }
    override func rightMouseUp(with event: NSEvent) { pointerButton(.right, isDown: false, event) }

    override func keyDown(with event: NSEvent) { forwardKey(event, isDown: true) }
    override func keyUp(with event: NSEvent) { forwardKey(event, isDown: false) }

    /// Modifier keys arrive here, not as key-down and key-up; the device-dependent flag bit tells which side is down.
    override func flagsChanged(with event: NSEvent) {
        guard let (usage, deviceFlag) = modifierKeys[Int(event.keyCode)] else { return }
        let isDown = event.modifierFlags.rawValue & deviceFlag != 0
        session.handle(.key(KeyCode(hidUsage: usage), isDown: isDown))
    }

    private func pointerMoved(_ event: NSEvent) {
        guard let (x, y) = remotePoint(event) else { return }
        session.handle(.pointerMoved(x: x, y: y))
    }

    private func pointerButton(_ button: PointerButton, isDown: Bool, _ event: NSEvent) {
        guard let (x, y) = remotePoint(event) else { return }
        session.handle(.pointerButton(button, isDown: isDown, x: x, y: y))
    }

    private func forwardKey(_ event: NSEvent, isDown: Bool) {
        // The remote handles auto-repeat itself.
        guard !event.isARepeat, let usage = hidUsage(forKeyCode: Int(event.keyCode)) else { return }
        session.handle(.key(KeyCode(hidUsage: usage), isDown: isDown))
    }

    /// Maps a window point to remote pixels through the aspect-fit rectangle the layer draws in.
    private func remotePoint(_ event: NSEvent) -> (Double, Double)? {
        guard let size = session.screenSize, size.width > 0, size.height > 0 else { return nil }
        let point = convert(event.locationInWindow, from: nil)
        let scale = min(bounds.width / CGFloat(size.width), bounds.height / CGFloat(size.height))
        let drawn = CGSize(width: CGFloat(size.width) * scale, height: CGFloat(size.height) * scale)
        let origin = CGPoint(x: (bounds.width - drawn.width) / 2, y: (bounds.height - drawn.height) / 2)
        // AppKit's origin is bottom left, the remote's is top left.
        return ((point.x - origin.x) / scale, (origin.y + drawn.height - point.y) / scale)
    }
}

/// The USB HID usage of a macOS virtual key code, as the key's position on a PC keyboard.
private func hidUsage(forKeyCode keyCode: Int) -> UInt16? {
    // Apple ISO keyboards swap the key left of 1 and the key beside left Shift relative to PC ones.
    if KBGetLayoutType(Int16(LMGetKbdType())) == kKeyboardISO {
        switch keyCode {
        case kVK_ISO_Section: return 0x35
        case kVK_ANSI_Grave: return 0x64
        default: break
        }
    }
    return hidUsages[keyCode]
}

/// macOS virtual key codes to USB HID usages, for the keys the Session can send.
private let hidUsages: [Int: UInt16] = [
    kVK_ANSI_A: 0x04, kVK_ANSI_B: 0x05, kVK_ANSI_C: 0x06, kVK_ANSI_D: 0x07, kVK_ANSI_E: 0x08,
    kVK_ANSI_F: 0x09, kVK_ANSI_G: 0x0A, kVK_ANSI_H: 0x0B, kVK_ANSI_I: 0x0C, kVK_ANSI_J: 0x0D,
    kVK_ANSI_K: 0x0E, kVK_ANSI_L: 0x0F, kVK_ANSI_M: 0x10, kVK_ANSI_N: 0x11, kVK_ANSI_O: 0x12,
    kVK_ANSI_P: 0x13, kVK_ANSI_Q: 0x14, kVK_ANSI_R: 0x15, kVK_ANSI_S: 0x16, kVK_ANSI_T: 0x17,
    kVK_ANSI_U: 0x18, kVK_ANSI_V: 0x19, kVK_ANSI_W: 0x1A, kVK_ANSI_X: 0x1B, kVK_ANSI_Y: 0x1C,
    kVK_ANSI_Z: 0x1D,
    kVK_ANSI_1: 0x1E, kVK_ANSI_2: 0x1F, kVK_ANSI_3: 0x20, kVK_ANSI_4: 0x21, kVK_ANSI_5: 0x22,
    kVK_ANSI_6: 0x23, kVK_ANSI_7: 0x24, kVK_ANSI_8: 0x25, kVK_ANSI_9: 0x26, kVK_ANSI_0: 0x27,
    kVK_Return: 0x28, kVK_Escape: 0x29, kVK_Delete: 0x2A, kVK_Tab: 0x2B, kVK_Space: 0x2C,
    kVK_ANSI_Minus: 0x2D, kVK_ANSI_Equal: 0x2E, kVK_ANSI_LeftBracket: 0x2F, kVK_ANSI_RightBracket: 0x30,
    kVK_ANSI_Backslash: 0x31, kVK_ANSI_Semicolon: 0x33, kVK_ANSI_Quote: 0x34, kVK_ANSI_Grave: 0x35,
    kVK_ANSI_Comma: 0x36, kVK_ANSI_Period: 0x37, kVK_ANSI_Slash: 0x38, kVK_ISO_Section: 0x64,
    kVK_F1: 0x3A, kVK_F2: 0x3B, kVK_F3: 0x3C, kVK_F4: 0x3D, kVK_F5: 0x3E, kVK_F6: 0x3F,
    kVK_F7: 0x40, kVK_F8: 0x41, kVK_F9: 0x42, kVK_F10: 0x43, kVK_F11: 0x44, kVK_F12: 0x45,
    kVK_Help: 0x49, kVK_Home: 0x4A, kVK_PageUp: 0x4B, kVK_ForwardDelete: 0x4C, kVK_End: 0x4D,
    kVK_PageDown: 0x4E, kVK_RightArrow: 0x4F, kVK_LeftArrow: 0x50, kVK_DownArrow: 0x51, kVK_UpArrow: 0x52,
]

/// Modifier virtual key codes to their HID usage and device-dependent flag bit (IOKit's NX_DEVICE*KEYMASK).
/// shortcut: Caps Lock is left out, since macOS reports it as a toggle; send it once Lock Mode needs it.
private let modifierKeys: [Int: (UInt16, UInt)] = [
    kVK_Control: (0xE0, 0x0001), kVK_Shift: (0xE1, 0x0002), kVK_Option: (0xE2, 0x0020), kVK_Command: (0xE3, 0x0008),
    kVK_RightControl: (0xE4, 0x2000), kVK_RightShift: (0xE5, 0x0004), kVK_RightOption: (0xE6, 0x0040),
    kVK_RightCommand: (0xE7, 0x0010),
]
