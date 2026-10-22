import Foundation
@testable import RoyalVNCKit
import Testing

// Expected frames computed independently with pycryptodome's AES-EAX:
// nonce = message index as 16 little-endian bytes, associated data = the 2-byte big-endian length.
struct RSAAESFrameCipherTests {
	@Test func sealsFramesWithAnIncrementingMessageIndex() throws {
		var cipher = try RSAAESFrameCipher(key: Array(0..<16))

		#expect(try cipher.seal(Array("hello".utf8)) == bytes("000510f92a33a721ccbc272bcb96040554d71643980f50"))
		#expect(try cipher.seal(Array("RFB 003.008\n".utf8))
			== bytes("000cb242d2c1bfe2ffb19275ee2033696d0d6f0e158946cbaf861036530d"))
	}

	@Test func sealsWithAnAES256Key() throws {
		var cipher = try RSAAESFrameCipher(key: Array(0..<32))

		#expect(try cipher.seal([UInt8](repeating: 0, count: 40)) == bytes(
			"0028d55de5a5a4a9d7308eb0573944cc194083cfcd37a3988c1bb2537df949cc6c01768b4cc6c90b2b397579d5e804a8ad651c2561669d904153"))
	}

	@Test func opensFramesAndRejectsTamperedOnes() throws {
		var cipher = try RSAAESFrameCipher(key: Array(0..<16))
		let frame = bytes("000510f92a33a721ccbc272bcb96040554d71643980f50")

		var tampered = frame
		tampered[3] ^= 1
		#expect(throws: VNCError.self) { try cipher.open(length: 5, body: Array(tampered.dropFirst(2))) }
		// A failed frame does not use up the message index.
		#expect(try cipher.open(length: 5, body: Array(frame.dropFirst(2))) == Array("hello".utf8))
	}
}

// Expected keystreams from pycryptodome's AES-CTR with a 128-bit counter, key 00 01 … 0f, all-zero input.
@Test(arguments: [
	(counter: "0000000000000000ffffffffffffffff",
	 keystream: "39a7ef0a0a5852a8bfd2032344bf941213189a6ae4ab07ae70a3aabd30be99de8f9429444c8f4b3599421235b510df3d"),
	(counter: "ffffffffffffffffffffffffffffffff",
	 keystream: "3c441f32ce07822364d7a2990e50bb13c6a13b37878f5b826f4f8162a1c8d8797346139595c0b41e497bbde365f42d0a"),
])
func counterCarriesAcrossAll128Bits(counter: String, keystream: String) throws {
	#expect(try aesCTR([UInt8](repeating: 0, count: 48), key: Array(0..<16), counter: bytes(counter)) == bytes(keystream))
}

private func bytes(_ hex: String) -> [UInt8] {
	stride(from: 0, to: hex.count, by: 2).map {
		let start = hex.index(hex.startIndex, offsetBy: $0)
		return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
	}
}
