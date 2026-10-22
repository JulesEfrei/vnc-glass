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

    override var acceptsFirstResponder: Bool { true }

    override func viewDidMoveToWindow() {
        window?.makeFirstResponder(self)
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
        guard !event.isARepeat, let usage = hidUsages[Int(event.keyCode)] else { return }
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

/// macOS virtual key codes to USB HID usages, for the keys the Session can send so far.
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
]
