import Foundation
@testable import RoyalVNCKit
import Testing

struct ExtendedClipboardTests {
	// TigerVNC ends each provide's zlib stream with a sync flush instead of finishing it. Bytes from Python's zlib:
	// compressobj().compress(plain) + flush(Z_SYNC_FLUSH), plain = the text's length and "héllo 🎉\r\nx\0".
	@Test func readsAProvideEndedWithASyncFlush() throws {
		let payload = Data([0x10, 0x00, 0x00, 0x01]) + Data([
			0x78, 0x9C, 0x62, 0x60, 0x60, 0xE0, 0xCF, 0x38, 0xBC, 0x32, 0x27, 0x27, 0x5F, 0xE1, 0xC3, 0xFC,
			0xBE, 0x4E, 0x5E, 0xAE, 0x0A, 0x06, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
		])

		let message = try VNCProtocol.ExtendedClipboard(payload: payload)

		#expect(message.text == "héllo 🎉\nx")
	}

	@Test func dropsProvidedTextLargerThanTheLimit() throws {
		let huge = String(repeating: "a", count: VNCProtocol.ExtendedClipboard.maximumLength)
		let payload = VNCProtocol.ExtendedClipboard(flags: [.provide, .text], text: huge).payload
		#expect(payload.count < 100_000) // compresses well, so only the inflated size can catch it

		let message = try VNCProtocol.ExtendedClipboard(payload: payload)

		#expect(message.flags == [.provide, .text])
		#expect(message.text == nil)
	}
}
