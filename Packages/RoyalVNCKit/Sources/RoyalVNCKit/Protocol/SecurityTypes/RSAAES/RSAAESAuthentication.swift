#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import CryptoKit
import Security

/// rfbproto "RSA-AES Security Type" (5) and "RSA-AES-256 Security Type" (129).
extension VNCProtocol {
	struct RSAAESAuthentication {
		/// SHA-1 and AES-128 for type 5, SHA-256 and AES-256 for type 129.
		let is256: Bool

		/// The session key length, and the random length neatvnc uses (rfbproto says 16 bytes for both types, but
		/// neatvnc's RSA-AES-256 sends and expects 32).
		var keyLength: Int { is256 ? 32 : 16 }

		func hash(_ data: [UInt8]) -> [UInt8] {
			is256 ? Array(SHA256.hash(data: data)) : Array(Insecure.SHA1.hash(data: data))
		}
	}
}

extension VNCProtocol.RSAAESAuthentication {
	/// A public key as rfbproto sends it: the key length in bits, then modulus and exponent, each as long as the modulus.
	struct PublicKey {
		let message: [UInt8]
		let key: SecKey

		/// SHA-256 of the key message, which identifies the server across connections.
		var fingerprint: Data {
			Data(SHA256.hash(data: message))
		}

		static func receive(connection: NetworkConnectionReading) async throws -> Self {
			let bits = try await connection.readUInt32()

			// Below 1024 bits the key protects nothing; above 8192 it is not a key a server would use.
			guard (1024...8192).contains(bits) else {
				throw VNCError.authentication(.rsaAESAuthenticationFailed)
			}

			let length = (Int(bits) + 7) / 8
			let modulusAndExponent = [UInt8](try await connection.readBuffered(length: length * 2))
			let der = derSequence(derInteger(modulusAndExponent[..<length]) + derInteger(modulusAndExponent[length...]))
			let attributes = [ kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic ] as CFDictionary

			guard let key = SecKeyCreateWithData(Data(der) as CFData, attributes, nil) else {
				throw VNCError.authentication(.rsaAESAuthenticationFailed)
			}

			return .init(message: be32(bits) + modulusAndExponent, key: key)
		}
	}

	/// The client's own key pair, made for this connection only.
	struct ClientKey {
		let privateKey: SecKey
		let message: [UInt8]

		init() throws {
			let attributes = [ kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048 ] as CFDictionary

			// Security exports RSA public keys as PKCS#1 DER: SEQUENCE { INTEGER modulus, INTEGER exponent }.
			guard let privateKey = SecKeyCreateRandomKey(attributes, nil),
				  let publicKey = SecKeyCopyPublicKey(privateKey),
				  let der = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
				throw VNCError.authentication(.rsaAESAuthenticationFailed)
			}

			var bytes = ArraySlice(der)

			guard var sequence = derContents(&bytes),
				  let modulus = derContents(&sequence)?.drop(while: { $0 == 0 }),
				  let exponent = derContents(&sequence)?.drop(while: { $0 == 0 }) else {
				throw VNCError.authentication(.rsaAESAuthenticationFailed)
			}

			self.privateKey = privateKey
			message = be32(UInt32(modulus.count * 8)) + modulus + [UInt8](repeating: 0, count: modulus.count - exponent.count) + exponent
		}
	}

	static func encrypt(_ data: [UInt8], for key: SecKey) throws -> [UInt8] {
		guard let encrypted = SecKeyCreateEncryptedData(key, .rsaEncryptionPKCS1, Data(data) as CFData, nil) as Data? else {
			throw VNCError.authentication(.rsaAESAuthenticationFailed)
		}

		return [UInt8](encrypted)
	}

	static func decrypt(_ data: Data, with key: SecKey) throws -> [UInt8] {
		guard let decrypted = SecKeyCreateDecryptedData(key, .rsaEncryptionPKCS1, data as CFData, nil) as Data? else {
			throw VNCError.authentication(.rsaAESAuthenticationFailed)
		}

		return [UInt8](decrypted)
	}

	static func randomBytes(_ count: Int) throws -> [UInt8] {
		var bytes = [UInt8](repeating: 0, count: count)

		guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
			throw VNCError.authentication(.rsaAESAuthenticationFailed)
		}

		return bytes
	}

	/// The plaintext credentials message: length-prefixed UTF-8 username (empty for password-only), then password.
	static func credentialsMessage(username: String, password: String) throws -> [UInt8] {
		let username = Array(username.utf8)
		let password = Array(password.utf8)

		guard username.count <= UInt8.max, password.count <= UInt8.max else {
			throw VNCError.authentication(.rsaAESAuthenticationFailed)
		}

		return [ UInt8(username.count) ] + username + [ UInt8(password.count) ] + password
	}
}

private func be32(_ value: UInt32) -> [UInt8] {
	[ UInt8(value >> 24), UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF) ]
}

/// Reads one DER element and returns its contents.
private func derContents(_ bytes: inout ArraySlice<UInt8>) -> ArraySlice<UInt8>? {
	guard bytes.count >= 2 else { return nil }

	bytes.removeFirst()
	var length = Int(bytes.removeFirst())

	if length & 0x80 != 0 {
		let lengthBytes = length & 0x7F

		guard lengthBytes <= 2, bytes.count >= lengthBytes else { return nil }

		length = bytes.prefix(lengthBytes).reduce(0) { $0 << 8 | Int($1) }
		bytes.removeFirst(lengthBytes)
	}

	guard bytes.count >= length else { return nil }

	defer { bytes.removeFirst(length) }

	return bytes.prefix(length)
}

private func derInteger(_ value: ArraySlice<UInt8>) -> [UInt8] {
	let trimmed = Array(value.drop(while: { $0 == 0 }))

	// A leading zero keeps the INTEGER positive.
	return derElement(tag: 0x02, (trimmed.first ?? 0x80) & 0x80 != 0 ? [ 0 ] + trimmed : trimmed)
}

private func derSequence(_ contents: [UInt8]) -> [UInt8] {
	derElement(tag: 0x30, contents)
}

private func derElement(tag: UInt8, _ contents: [UInt8]) -> [UInt8] {
	let count = contents.count
	let length: [UInt8] = count < 0x80 ? [ UInt8(count) ]
		: count < 0x100 ? [ 0x81, UInt8(count) ]
		: [ 0x82, UInt8(count >> 8), UInt8(count & 0xFF) ]

	return [ tag ] + length + contents
}
