#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Connect/Disconnect
public extension VNCConnection {
#if canImport(ObjectiveC)
	@objc
#endif
	func connect() {
		beginConnecting()
	}

#if canImport(ObjectiveC)
    @objc
#endif
	func disconnect() {
		// Let messages already queued, such as key releases, reach the server before closing.
		if connectionState.status == .connected, sendTask != nil {
			state.disconnectWhenQueueIsEmpty = true
			// A server that stops reading would otherwise keep the queue from ever emptying.
			Task {
				try await Task.sleep(seconds: 1)
				beginDisconnecting()
			}
		} else {
			beginDisconnecting()
		}
	}
}

public extension VNCConnection {
#if canImport(ObjectiveC)
    @objc
#endif
	func updateColorDepth(_ colorDepth: Settings.ColorDepth) {
		guard let framebuffer = framebuffer else { return }

		let newPixelFormat = VNCProtocol.PixelFormat(depth: colorDepth.rawValue)

		state.pixelFormat = newPixelFormat

		let sendPixelFormatMessage = VNCProtocol.SetPixelFormat(pixelFormat: newPixelFormat)

		clientToServerMessageQueue.enqueue(sendPixelFormatMessage)

		recreateFramebuffer(size: framebuffer.size,
							screens: framebuffer.screens,
							pixelFormat: newPixelFormat)
	}
}

// MARK: - Mouse Input
public extension VNCConnection {
#if canImport(ObjectiveC)
    @objc
#endif
    func mouseMove(x: UInt16, y: UInt16) {
        enqueueMouseEvent(nonNormalizedX: x,
                          nonNormalizedY: y)
    }

#if canImport(ObjectiveC)
    @objc
#endif
    func mouseButtonDown(_ button: VNCMouseButton,
                         x: UInt16, y: UInt16) {
        updateMouseButtonState(button: button,
                               isDown: true)

        enqueueMouseEvent(nonNormalizedX: x,
                          nonNormalizedY: y)
    }

#if canImport(ObjectiveC)
    @objc
#endif
    func mouseButtonUp(_ button: VNCMouseButton,
                       x: UInt16, y: UInt16) {
        updateMouseButtonState(button: button,
                               isDown: false)

        enqueueMouseEvent(nonNormalizedX: x,
                          nonNormalizedY: y)
    }

#if canImport(ObjectiveC)
    @objc
#endif
    func mouseWheel(_ wheel: VNCMouseWheel,
                    x: UInt16, y: UInt16,
                    steps: UInt32) {
        for _ in 0..<steps {
            updateMouseButtonState(wheel: wheel,
                                   isDown: true)

            enqueueMouseEvent(nonNormalizedX: x,
                              nonNormalizedY: y)

            updateMouseButtonState(wheel: wheel,
                                   isDown: false)

            // Servers that act on mask changes, like wayvnc, ignore a second press without this release.
            enqueueMouseEvent(nonNormalizedX: x,
                              nonNormalizedY: y)
        }
    }
}

extension VNCConnection {
    func updateMouseButtonState(button: VNCMouseButton,
                                isDown: Bool) {
        updateMouseButtonState(mousePointerButton: button.mousePointerButton,
                               isDown: isDown)
    }

    func updateMouseButtonState(wheel: VNCMouseWheel,
                                isDown: Bool) {
        updateMouseButtonState(mousePointerButton: wheel.mousePointerButton,
                               isDown: isDown)
    }

    func updateMouseButtonState(mousePointerButton: VNCProtocol.MousePointerButton,
                                isDown: Bool) {
        if isDown {
            mouseButtonState.insert(mousePointerButton)
        } else {
            mouseButtonState.remove(mousePointerButton)
        }
    }
}

// MARK: - Keyboard Input
public extension VNCConnection {
	func keyDown(_ key: VNCKeyCode) {
		enqueueKeyEvent(key: key,
						isDown: true)
	}

#if canImport(ObjectiveC)
	@objc(keyDown:)
#endif
	func _objc_keyDown(_ key: UInt32) {
		keyDown(.init(key))
	}

	func keyUp(_ key: VNCKeyCode) {
		enqueueKeyEvent(key: key,
						isDown: false)
	}

#if canImport(ObjectiveC)
	@objc(keyUp:)
#endif
	func _objc_keyUp(_ key: UInt32) {
		keyUp(.init(key))
	}

	/// Sends the key as a QEMU Extended Key Event when the server supports one, as a plain key event otherwise.
	/// `scancode` is the XT (set 1) scancode, E0-prefixed keys as 0xE0xx.
	func keyDown(_ key: VNCKeyCode, scancode: UInt16) {
		enqueueKeyEvent(key: key, scancode: scancode, isDown: true)
	}

	func keyUp(_ key: VNCKeyCode, scancode: UInt16) {
		enqueueKeyEvent(key: key, scancode: scancode, isDown: false)
	}
}

// MARK: - Clipboard
public extension VNCConnection {
	/// Offers the text to the server over Extended Clipboard in UTF-8 when the server takes it, otherwise sends it as
	/// ClientCutText in Latin-1, with characters Latin-1 lacks replaced.
#if canImport(ObjectiveC)
    @objc
#endif
	func sendClipboardText(_ text: String) {
		let isExtended = clipboardState.withLock { state in
			state.text = text

			return state.isExtendedTextSupported
		}

		if isExtended {
			enqueueExtendedClipboardMessage(.init(flags: [.notify, .text]))
		} else {
			enqueueClientCutTextMessage(text)
		}
	}

	/// Forgets the text last given to `sendClipboardText(_:)`, so a server asking for it over Extended Clipboard gets
	/// nothing.
#if canImport(ObjectiveC)
    @objc
#endif
	func clearClipboardText() {
		clipboardState.withLock { $0.text = nil }
	}
}
