#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	/// A key event carrying the physical key's XT scancode as well as its keysym.
	struct QEMUExtendedKeyEvent: VNCSendableMessage {
		let messageType: UInt8 = 255
		let subMessageType: UInt8 = 0

		let isDown: Bool
		let key: UInt32
		/// XT (set 1) scancode, E0-prefixed keys as 0xE0xx.
		let scancode: UInt16
	}
}

extension VNCProtocol.QEMUExtendedKeyEvent {
	/// The keycode as QEMU sends it: E0-prefixed keys become 0x80 | the low byte.
	var keycode: UInt32 {
		scancode & 0xFF00 == 0xE000 ? 0x80 | UInt32(scancode & 0x7F) : UInt32(scancode)
	}

	var data: Data {
		let length = 12

		var data = Data(capacity: length)

		data.append(messageType)
		data.append(subMessageType)
		data.append(UInt16(isDown ? 1 : 0), bigEndian: true)
		data.append(key, bigEndian: true)
		data.append(keycode, bigEndian: true)

		guard data.count == length else {
			fatalError("VNCProtocol.QEMUExtendedKeyEvent data.count (\(data.count)) != \(length)")
		}

		return data
	}

	func send(connection: NetworkConnectionWriting) async throws {
		try await connection.write(data: data)
	}

	var description: String {
		"\(VNCKeyCode(key).description) scancode \(String(scancode, radix: 16)) \(isDown ? "↓" : "↑")"
	}
}
