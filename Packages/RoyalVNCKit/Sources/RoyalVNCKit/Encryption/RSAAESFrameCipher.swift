#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import CommonCrypto

/// One direction of the RSA-AES encrypted stream (rfbproto "RSA-AES Security Type"): each frame is a 2-byte big-endian
/// length, the AES-EAX ciphertext and a 16-byte MAC. The nonce is the frame's index as 16 little-endian bytes, the
/// associated data is the length header.
/// AES comes from CommonCrypto: it carries the whole RFB session, and CryptoSwift's AES only manages about 10 MB/s.
struct RSAAESFrameCipher {
	private let key: [UInt8]
	private let cmacSubkeys: (complete: [UInt8], padded: [UInt8])
	private var messageIndex: UInt64 = 0

	/// 16 bytes for RSA-AES (type 5), 32 bytes for RSA-AES-256 (type 129).
	init(key: [UInt8]) throws {
		guard key.count == kCCKeySizeAES128 || key.count == kCCKeySizeAES256 else {
			throw VNCError.authentication(.rsaAESAuthenticationFailed)
		}

		self.key = key

		// RFC 4493 subkey generation.
		let k1 = try doubled(aes(kCCOptionECBMode, key: key, [UInt8](repeating: 0, count: 16)))
		cmacSubkeys = (k1, doubled(k1))
	}

	mutating func seal(_ plaintext: [UInt8]) throws -> [UInt8] {
		let header = [ UInt8(plaintext.count >> 8), UInt8(plaintext.count & 0xFF) ]
		let nonceMAC = try omac(0, nonce)
		let ciphertext = try aesCTR(plaintext, key: key, counter: nonceMAC)
		let mac = try xor(xor(nonceMAC, omac(1, header)), omac(2, ciphertext))

		messageIndex += 1

		return header + ciphertext + mac
	}

	/// `body` is the ciphertext followed by the MAC. A frame that fails authentication leaves the cipher unchanged.
	mutating func open(length: UInt16, body: [UInt8]) throws -> [UInt8] {
		guard body.count == Int(length) + 16 else {
			throw VNCError.authentication(.rsaAESAuthenticationFailed)
		}

		let header = [ UInt8(length >> 8), UInt8(length & 0xFF) ]
		let ciphertext = Array(body[..<Int(length)])
		let nonceMAC = try omac(0, nonce)
		let mac = try xor(xor(nonceMAC, omac(1, header)), omac(2, ciphertext))

		guard mac == Array(body[Int(length)...]) else {
			throw VNCError.authentication(.rsaAESAuthenticationFailed)
		}

		messageIndex += 1

		return try aesCTR(ciphertext, key: key, counter: nonceMAC)
	}
}

private extension RSAAESFrameCipher {
	var nonce: [UInt8] {
		withUnsafeBytes(of: messageIndex.littleEndian, Array.init) + [UInt8](repeating: 0, count: 8)
	}

	/// EAX's tweaked CMAC: CMAC over a block holding `tweak` in its last byte, followed by `data`.
	func omac(_ tweak: UInt8, _ data: [UInt8]) throws -> [UInt8] {
		var message = [UInt8](repeating: 0, count: 15) + [ tweak ] + data
		let lastBlock = (message.count - 1) / 16 * 16

		if message.count % 16 == 0 {
			message[lastBlock...] = ArraySlice(xor(Array(message[lastBlock...]), cmacSubkeys.complete))
		} else {
			message += [ 0x80 ] + [UInt8](repeating: 0, count: 15 - message.count % 16)
			message[lastBlock...] = ArraySlice(xor(Array(message[lastBlock...]), cmacSubkeys.padded))
		}

		// CBC with a zero IV; the last ciphertext block is the MAC.
		return Array(try aes(0, key: key, message).suffix(16))
	}

	func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
		zip(a, b).map { $0 ^ $1 }
	}
}

/// AES-CTR with the full 128-bit big-endian counter EAX needs. CommonCrypto's CTR only carries within the low 64 bits,
/// so the input is split where they wrap.
func aesCTR(_ input: [UInt8], key: [UInt8], counter: [UInt8]) throws -> [UInt8] {
	let low = counter[8...].reduce(0) { $0 << 8 | UInt64($1) }
	let blocksAfterFirst = UInt64((max(input.count, 1) - 1) / 16)

	guard UInt64.max - low >= blocksAfterFirst else {
		let split = Int(UInt64.max - low + 1) * 16
		var next = Array(counter[..<8]) + [UInt8](repeating: 0, count: 8)

		for i in (0..<8).reversed() {
			next[i] &+= 1
			if next[i] != 0 { break }
		}

		return try aesCTR(Array(input[..<split]), key: key, counter: counter)
			+ aesCTR(Array(input[split...]), key: key, counter: next)
	}

	guard !input.isEmpty else { return [] }

	var cryptor: CCCryptorRef?
	var status = CCCryptorCreateWithMode(CCOperation(kCCEncrypt), CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES),
										 CCPadding(ccNoPadding), counter, key, key.count, nil, 0, 0,
										 CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
	defer { CCCryptorRelease(cryptor) }

	var output = [UInt8](repeating: 0, count: input.count)
	var moved = 0

	if status == kCCSuccess {
		status = CCCryptorUpdate(cryptor, input, input.count, &output, output.count, &moved)
	}

	guard status == kCCSuccess, moved == input.count else {
		throw VNCError.authentication(.encryptionFailed)
	}

	return output
}

/// AES over block-aligned `input`: ECB with `kCCOptionECBMode`, otherwise CBC with a zero IV.
private func aes(_ options: Int, key: [UInt8], _ input: [UInt8]) throws -> [UInt8] {
	var output = [UInt8](repeating: 0, count: input.count)
	var moved = 0
	let status = CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(options),
						 key, key.count, [UInt8](repeating: 0, count: 16),
						 input, input.count, &output, output.count, &moved)

	guard status == kCCSuccess, moved == input.count else {
		throw VNCError.authentication(.encryptionFailed)
	}

	return output
}

/// Multiplication by x in GF(2^128), as CMAC's subkey generation needs.
private func doubled(_ block: [UInt8]) -> [UInt8] {
	var result = [UInt8](repeating: 0, count: 16)

	for i in 0..<16 {
		result[i] = block[i] << 1 | (i < 15 ? block[i + 1] >> 7 : 0)
	}

	if block[0] & 0x80 != 0 {
		result[15] ^= 0x87
	}

	return result
}
