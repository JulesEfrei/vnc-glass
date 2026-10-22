#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	/// Asks a server that sent an ExtendedDesktopSize rectangle to resize its desktop to one screen of this size.
	struct SetDesktopSize: VNCSendableMessage {
		let messageType: UInt8 = 251

		let width: UInt16
		let height: UInt16

		/// The server's id for its screen, which the request keeps.
		let screenID: UInt32
	}
}

extension VNCProtocol.SetDesktopSize {
	var data: Data {
		let length = 24

		var data = Data(capacity: length)

		data.append(messageType)
		data.append(UInt8(0)) // padding
		data.append(width, bigEndian: true)
		data.append(height, bigEndian: true)
		data.append(UInt8(1)) // number of screens
		data.append(UInt8(0)) // padding

		// The screen at the origin: wayvnc moves a multi-monitor output there anyway (wayvnc #453).
		data.append(screenID, bigEndian: true)
		data.append(UInt16(0), bigEndian: true)
		data.append(UInt16(0), bigEndian: true)
		data.append(width, bigEndian: true)
		data.append(height, bigEndian: true)
		data.append(UInt32(0), bigEndian: true) // flags

		guard data.count == length else {
			fatalError("VNCProtocol.SetDesktopSize data.count (\(data.count)) != \(length)")
		}

		return data
	}

	func send(connection: NetworkConnectionWriting) async throws {
		try await connection.write(data: data)
	}
}
