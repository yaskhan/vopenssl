module vopenssl

// Импорты подмодулей
import rsa
import ecc
import ed25519

// VOpenSSL - High-level cryptographic library for V
//
// This library provides OpenSSL-style functionality built on top of V's
// built-in crypto module. It offers convenient wrappers and high-level APIs
// for common cryptographic operations.
//
// Example:
// ```v
// import vopenssl.hash
// import vopenssl.cipher
// import vopenssl.rand
// import vopenssl.rsa
//
// // Hash a file
// hash := hash.sha256_file('document.pdf')!
// println('SHA-256: ${hash.hex()}')
//
// // Encrypt data
// key := rand.generate_key(256)!
// encrypted := cipher.encrypt_aes_256_gcm(key, plaintext)!
//
// // Generate RSA key pair
// key_pair := rsa.generate_key_pair(.bits2048)!
// ```
//
// Available modules:
// - vopenssl.rand: Random number generation
// - vopenssl.hash: Hashing algorithms (SHA, BLAKE, MD5)
// - vopenssl.mac: HMAC and message authentication
// - vopenssl.cipher: Symmetric encryption (AES with GCM, CBC, CTR modes)
// - vopenssl.rsa: RSA asymmetric cryptography
// - vopenssl.ecc: Elliptic Curve cryptography (ECDSA, ECDH)
// - vopenssl.ed25519: Ed25519 signatures (wrapper over crypto.ed25519)
// - vopenssl.utils: Utilities (padding, hex encoding, etc.)

// Re-export common types and functions for convenience

// RSA types
pub type RSAPublicKey = rsa.RSAPublicKey
pub type RSAPrivateKey = rsa.RSAPrivateKey
pub type RSAKeyPair = rsa.RSAKeyPair
pub type RSAKeySize = rsa.RSAKeySize
pub type PaddingScheme = rsa.PaddingScheme

// ECC types
pub type ECPublicKey = ecc.ECPublicKey
pub type ECPrivateKey = ecc.ECPrivateKey
pub type ECKeyPair = ecc.ECKeyPair
pub type ECDSASignature = ecc.ECDSASignature
pub type EllipticCurve = ecc.EllipticCurve

// Ed25519 types (use []u8 directly since they are type aliases)
pub type Ed25519PublicKey = []u8
pub type Ed25519PrivateKey = []u8
pub type Ed25519KeyPair = ed25519.KeyPair

// Common enums
pub type HashAlgorithm = rsa.HashAlgorithm

// Re-export RSA functions
pub fn generate_rsa_key_pair(size RSAKeySize) !RSAKeyPair {
	kp := rsa.generate_key_pair(size)!
	return RSAKeyPair(kp)
}

pub fn rsa_encrypt(pub_key RSAPublicKey, data []u8, padding PaddingScheme) ![]u8 {
	return rsa.encrypt(pub_key, data, padding)
}

pub fn rsa_decrypt(priv_key RSAPrivateKey, data []u8, padding PaddingScheme) ![]u8 {
	return rsa.decrypt(priv_key, data, padding)
}

pub fn rsa_sign(priv_key RSAPrivateKey, data []u8, hash_alg HashAlgorithm, padding PaddingScheme) ![]u8 {
	return rsa.sign(priv_key, data, hash_alg, padding)
}

pub fn rsa_verify(pub_key RSAPublicKey, data []u8, signature []u8, hash_alg HashAlgorithm, padding PaddingScheme) !bool {
	return rsa.verify(pub_key, data, signature, hash_alg, padding)
}

// Re-export ECC functions
pub fn generate_ecc_key_pair(curve EllipticCurve) !ECKeyPair {
	kp := ecc.generate_key_pair(curve)!
	return ECKeyPair(kp)
}

pub fn ecdsa_sign(priv_key ECPrivateKey, data []u8, hash_alg HashAlgorithm) !ECDSASignature {
	// Convert HashAlgorithm to ecc.HashAlgorithm
	ecc_hash_alg := match hash_alg {
		.sha1 { ecc.HashAlgorithm.sha1 }
		.sha224 { ecc.HashAlgorithm.sha224 }
		.sha256 { ecc.HashAlgorithm.sha256 }
		.sha384 { ecc.HashAlgorithm.sha384 }
		.sha512 { ecc.HashAlgorithm.sha512 }
		.md5 { ecc.HashAlgorithm.md5 }
		else { ecc.HashAlgorithm.sha256 } // default
	}
	sig := ecc.ecdsa_sign(priv_key, data, ecc_hash_alg)!
	return ECDSASignature(sig)
}

pub fn ecdsa_verify(pub_key ECPublicKey, data []u8, signature ECDSASignature, hash_alg HashAlgorithm) !bool {
	// Convert HashAlgorithm to ecc.HashAlgorithm
	ecc_hash_alg := match hash_alg {
		.sha1 { ecc.HashAlgorithm.sha1 }
		.sha224 { ecc.HashAlgorithm.sha224 }
		.sha256 { ecc.HashAlgorithm.sha256 }
		.sha384 { ecc.HashAlgorithm.sha384 }
		.sha512 { ecc.HashAlgorithm.sha512 }
		.md5 { ecc.HashAlgorithm.md5 }
		else { ecc.HashAlgorithm.sha256 } // default
	}
	return ecc.ecdsa_verify(pub_key, data, signature, ecc_hash_alg)
}

pub fn ecdh(priv_key ECPrivateKey, other_pub_key ECPublicKey) ![]u8 {
	return ecc.ecdh(priv_key, other_pub_key)
}

// Re-export Ed25519 functions
pub fn generate_ed25519_key_pair() !Ed25519KeyPair {
	kp := ed25519.generate_key_pair()!
	return Ed25519KeyPair(kp)
}

pub fn ed25519_sign(private_key Ed25519PrivateKey, message []u8) ![]u8 {
	return ed25519.sign(private_key, message)
}

pub fn ed25519_verify(public_key Ed25519PublicKey, message []u8, signature []u8) !bool {
	return ed25519.verify(public_key, message, signature)
}
