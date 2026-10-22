#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

/// The RFB byte stream over a network connection. Bytes pass straight through until `startEncryption`, after which
/// they travel in RSA-AES frames in both directions, below every RFB message.
/// Reads come from one task at a time (the handshake, then the receive loop), and so do writes (the handshake, then the
/// send loop), so each direction's cipher state needs no lock.
final class RFBStream: NetworkConnectionReading, NetworkConnectionWriting {
	/// Plaintext per outgoing frame. neatvnc drops a client whose frame does not fit its 8192-byte read buffer.
	private static let maximumFrameLength = 4096

	private let base: any NetworkConnection
	private var encryptor: RSAAESFrameCipher?
	private var decryptor: RSAAESFrameCipher?
	private var plaintext = [UInt8]()
	private var plaintextOffset = 0

	init(base: any NetworkConnection) {
		self.base = base
	}

	var isReady: Bool {
		base.isReady
	}

	func setStatusUpdateHandler(_ statusUpdateHandler: NetworkConnectionStatusUpdateHandler?) {
		base.setStatusUpdateHandler(statusUpdateHandler)
	}

	func start(queue: DispatchQueue) {
		base.start(queue: queue)
	}

	func cancel() {
		base.cancel()
	}

	func startEncryption(sendKey: [UInt8], receiveKey: [UInt8]) throws {
		encryptor = try RSAAESFrameCipher(key: sendKey)
		decryptor = try RSAAESFrameCipher(key: receiveKey)
	}

	func read(minimumLength: Int,
			  maximumLength: Int) async throws -> Data {
		guard decryptor != nil else {
			return try await base.read(minimumLength: minimumLength,
									   maximumLength: maximumLength)
		}

		while plaintext.count - plaintextOffset < minimumLength {
			let length = try await base.readUInt16()
			let body = try await base.readBuffered(length: Int(length) + 16)

			plaintext.removeFirst(plaintextOffset)
			plaintextOffset = 0
			plaintext += try decryptor!.open(length: length, body: [UInt8](body))
		}

		let count = min(plaintext.count - plaintextOffset, maximumLength)
		defer { plaintextOffset += count }

		return Data(plaintext[plaintextOffset..<plaintextOffset + count])
	}

	func write(data: Data) async throws {
		guard encryptor != nil else {
			return try await base.write(data: data)
		}

		let bytes = [UInt8](data)
		var frames = [UInt8]()

		for start in stride(from: 0, to: bytes.count, by: Self.maximumFrameLength) {
			frames += try encryptor!.seal(Array(bytes[start..<min(start + Self.maximumFrameLength, bytes.count)]))
		}

		try await base.write(data: Data(frames))
	}
}
