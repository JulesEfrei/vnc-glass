// swiftlint:disable nesting

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
    struct ServerCutText: VNCReceivableMessage {
        static let messageType: UInt8 = 3

		static let stringEncoding: String.Encoding = .isoLatin1

        let messageType: UInt8
        let text: String

		let extended: ExtendedClipboard?
    }
}

extension VNCProtocol.ServerCutText {
    static func receive(connection: NetworkConnectionReading,
                        logger: VNCLogger) async throws -> Self {
        try await connection.readPadding(length: 3)

		let length = try await receiveLength(connection: connection,
											 logger: logger)

		if length >= 0 { // Standard Message
			let text = try await connection.readString(encoding: Self.stringEncoding,
													   length: .init(length))

			return .init(messageType: Self.messageType,
						 text: text,
						 extended: nil)
		} else { // Extended Message
			let extendedLength = Int(length.magnitude)

			guard extendedLength <= VNCProtocol.ExtendedClipboard.maximumLength else {
				throw VNCError.protocol(.invalidData)
			}

			let extended = try VNCProtocol.ExtendedClipboard(payload: try await connection.read(length: extendedLength))

			return .init(messageType: Self.messageType,
						 text: "",
						 extended: extended)
		}
    }
}

private extension VNCProtocol.ServerCutText {
	static func receiveLength(connection: NetworkConnectionReading,
							  logger: VNCLogger) async throws -> Int {
		let lengthDataLength = MemoryLayout<UInt32>.size
		let lengthData = try await connection.read(length: lengthDataLength)

		guard lengthData.count == lengthDataLength else {
			throw VNCError.protocol(.invalidData)
		}

		let bigEndianUnsignedLength = lengthData.withUnsafeBytes {
			$0.load(as: UInt32.self)
		}

        let endianess = Endianness.current

        var length = endianess == .little
			? Int(UInt32(bigEndian: bigEndianUnsignedLength))
			: Int(bigEndianUnsignedLength)

		// TODO: Is that the correct check?
		if length > Int32.max {
			let bigEndianSignedLength = lengthData.withUnsafeBytes {
				$0.load(as: Int32.self)
			}

			length = endianess == .little
				? Int(Int32(bigEndian: bigEndianSignedLength))
				: Int(bigEndianSignedLength)
		}

		return length
	}
}

// swiftlint:enable nesting
