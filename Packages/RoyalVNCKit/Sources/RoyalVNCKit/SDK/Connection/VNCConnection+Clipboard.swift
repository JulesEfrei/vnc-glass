#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCConnection {
	struct ClipboardState {
		/// The server's Extended Clipboard caps take notified and provided text, so local text goes that way.
		var isExtendedTextSupported = false

		/// The local text last given to `sendClipboardText`, provided when the server asks for it.
		var text: String?
	}

	func handleExtendedClipboardMessage(_ message: VNCProtocol.ExtendedClipboard) {
		let flags = message.flags

		if flags.contains(.caps) {
			let isSupported = flags.isSuperset(of: [.text, .notify, .provide])

			let text = clipboardState.withLock { state in
				state.isExtendedTextSupported = isSupported

				return state.text
			}

			enqueueExtendedClipboardMessage(.clientCaps)

			// Text sent before the caps arrived went as Latin-1, which may have lost characters.
			if isSupported, text != nil {
				enqueueExtendedClipboardMessage(.init(flags: [.notify, .text]))
			}
		} else if flags.contains(.request) {
			guard flags.contains(.text),
				  let text = clipboardState.withLock({ $0.text }) else { return }

			enqueueExtendedClipboardMessage(.init(flags: [.provide, .text], text: text))
		} else if flags.contains(.peek) {
			let hasText = clipboardState.withLock { $0.text != nil }

			enqueueExtendedClipboardMessage(.init(flags: hasText ? [.notify, .text] : [.notify]))
		} else if flags.contains(.notify) {
			guard flags.contains(.text) else { return }

			enqueueExtendedClipboardMessage(.init(flags: [.request, .text]))
		} else if flags.contains(.provide), let text = message.text {
			receivedClipboardText(text)
		}
	}

	func receivedClipboardText(_ text: String) {
		guard settings.isClipboardRedirectionEnabled else {
			notifyDelegateAboutClipboardText(text)

			return
		}

		clipboard.text = text
	}
}
