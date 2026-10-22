#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	/// Announced by the server with an empty rectangle when it accepts QEMU Extended Key Events.
	struct QEMUExtendedKeyEventEncoding: VNCReceivablePseudoEncoding {
		let encodingType = VNCPseudoEncodingType.qemuExtendedKeyEvent.rawValue
		let state: VNCConnection.State
	}
}

extension VNCProtocol.QEMUExtendedKeyEventEncoding {
	func receive(_ rectangle: VNCProtocol.Rectangle,
				 framebuffer: VNCFramebuffer,
				 connection: NetworkConnectionReading,
				 logger: VNCLogger) async throws {
		state.isQEMUExtendedKeyEventSupported = true
	}
}
