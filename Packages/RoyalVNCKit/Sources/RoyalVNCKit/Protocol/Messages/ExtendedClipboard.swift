#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_implementationOnly import Z

extension VNCProtocol {
	/// An Extended Clipboard message: ClientCutText or ServerCutText with a negative length (rfbproto, pseudo-encoding
	/// 0xC0A1E5CE). Only the text format is used: UTF-8 with CRLF line endings and a terminating null.
	struct ExtendedClipboard {
		struct Flags: OptionSet {
			let rawValue: UInt32

			static let text = Self(rawValue: 1)

			/// The other bits are the formats and actions the sender accepts, followed by each format's size limit.
			static let caps = Self(rawValue: 1 << 24)
			static let request = Self(rawValue: 1 << 25)
			static let peek = Self(rawValue: 1 << 26)
			static let notify = Self(rawValue: 1 << 27)
			static let provide = Self(rawValue: 1 << 28)
		}

		/// The largest message and the largest text accepted from the server, as rfbproto's default text limit.
		static let maximumLength = 20 * 1024 * 1024

		let flags: Flags

		/// A provide's text, with LF line endings.
		var text: String?
	}
}

extension VNCProtocol.ExtendedClipboard {
	/// What the client accepts: text, unsolicited only up to 0 bytes so every change comes as a notify, as rfbproto
	/// recommends.
	static let clientCaps = Self(flags: [.caps, .request, .peek, .notify, .provide, .text])

	/// Parses a message's payload, the bytes after its length. A provide whose text cannot be read has no text.
	init(payload: Data) throws {
		guard payload.count >= 4 else { throw VNCError.protocol(.invalidData) }

		let flags = Flags(rawValue: Self.bigEndianUInt32(payload))

		self.flags = flags

		// Caps carry the provide bit too, as an action the sender accepts.
		guard !flags.contains(.caps), flags.isSuperset(of: [.provide, .text]) else { return }

		// Each format's size and data in flag order; text is the first format.
		guard let plain = try? ZlibStream().decompressedData(compressedData: payload.dropFirst(4),
															 maximumLength: Self.maximumLength),
			  plain.count >= 4 else { return }

		let size = Int(Self.bigEndianUInt32(plain))

		guard size <= plain.count - 4 else { return }

		let bytes = plain.dropFirst(4).prefix(size)

		text = String(decoding: bytes.last == 0 ? bytes.dropLast() : bytes, as: UTF8.self)
			.replacingOccurrences(of: "\r\n", with: "\n")
	}

	var payload: Data {
		var data = Data()

		data.append(flags.rawValue, bigEndian: true)

		if flags.contains(.caps) {
			data.append(UInt32(0), bigEndian: true) // the text size limit
		} else if flags.contains(.provide), let text {
			let bytes = Data(text.replacingOccurrences(of: "\r\n", with: "\n")
				.replacingOccurrences(of: "\n", with: "\r\n").utf8) + [0]

			var plain = Data()

			plain.append(UInt32(bytes.count), bigEndian: true)
			plain.append(bytes)

			data.append(Self.compressed(plain))
		}

		return data
	}

	/// The first four bytes, read without DataStream, whose bounds checks only run in debug builds.
	private static func bigEndianUInt32(_ data: Data) -> UInt32 {
		data.prefix(4).reduce(0) { $0 << 8 | UInt32($1) }
	}

	/// One complete zlib stream, as each provide carries.
	private static func compressed(_ data: Data) -> Data {
		var length = compressBound(uLong(data.count))
		var output = Data(count: Int(length))

		let status = output.withUnsafeMutableBytes { destination in
			data.withUnsafeBytes { source in
				compress2(destination.bindMemory(to: Bytef.self).baseAddress!, &length,
						  source.bindMemory(to: Bytef.self).baseAddress!, uLong(data.count), Z_DEFAULT_COMPRESSION)
			}
		}

		// compress2 only fails without memory or with a buffer smaller than compressBound.
		precondition(status == Z_OK, "compress2 failed (\(status))")

		output.count = Int(length)

		return output
	}
}

extension VNCProtocol {
	struct ExtendedClientCutText: VNCSendableMessage {
		let messageType: UInt8 = 6

		let message: ExtendedClipboard
	}
}

extension VNCProtocol.ExtendedClientCutText {
	var data: Data {
		let payload = message.payload

		var data = Data(capacity: 8 + payload.count)

		data.append(messageType)
		data.appendPadding(length: 3)
		data.append(-Int32(payload.count), bigEndian: true)
		data.append(payload)

		return data
	}

	func send(connection: NetworkConnectionWriting) async throws {
		try await connection.write(data: data)
	}
}
