#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCConnection {
	struct DesktopSizeState {
		/// The id of the server's first screen, set by its first ExtendedDesktopSize rectangle, which shows it takes
		/// SetDesktopSize.
		var screenID: UInt32?

		/// The size last given to `setDesktopSize`, sent once the server takes SetDesktopSize.
		var requestedSize: VNCSize?
	}

	func receivedExtendedDesktopSize(screenID: UInt32) {
		let pendingSize = desktopSizeState.withLock { state in
			defer { state.screenID = screenID }

			return state.screenID == nil ? state.requestedSize : nil
		}

		if let pendingSize {
			enqueueClientToServerMessage(VNCProtocol.SetDesktopSize(width: pendingSize.width,
																	height: pendingSize.height,
																	screenID: screenID))
		}
	}
}

public extension VNCConnection {
	/// Asks the server to resize its desktop to one screen of this size. A request made before the server has shown
	/// that it supports ExtendedDesktopSize is held until it does; servers that never do are never asked.
	func setDesktopSize(width: UInt16, height: UInt16) {
		let screenID = desktopSizeState.withLock { state in
			state.requestedSize = .init(width: width, height: height)

			return state.screenID
		}

		if let screenID {
			enqueueClientToServerMessage(VNCProtocol.SetDesktopSize(width: width, height: height, screenID: screenID))
		}
	}
}
