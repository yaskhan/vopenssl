module vopenssl

// Импорты подмодулей
import rsa
import ecc
import ed25519
import x509

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
// - vopenssl.x509: X.509 certificates, CSRs, and validation
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

// X.509 types
pub type X509Certificate = x509.X509Certificate
pub type X509Name = x509.X509Name
pub type X509Validity = x509.X509Validity
pub type X509Extension = x509.X509Extension
pub type CSR = x509.CSR
pub type ValidationOptions = x509.ValidationOptions
pub type ValidationResult = x509.ValidationResult
pub type KeyUsage = x509.KeyUsage
pub type CertificateType = x509.CertificateType
pub type CertificateFormat = x509.CertificateFormat
pub type BasicConstraints = x509.BasicConstraints

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

// Re-export X.509 functions
pub fn parse_x509_certificate(der_data []u8) !X509Certificate {
	return x509.parse_certificate(der_data)
}

pub fn parse_pem_x509_certificate(pem_str string) !X509Certificate {
	return x509.parse_pem_certificate(pem_str)
}

pub fn load_x509_certificate(path string) !X509Certificate {
	return x509.load_certificate(path)
}

pub fn create_csr(subject X509Name, public_key []u8, private_key []u8, signature_alg []int) !CSR {
	return x509.create_csr(subject, public_key, private_key, signature_alg)
}

pub fn parse_csr(der_data []u8) !CSR {
	return x509.parse_csr(der_data)
}

pub fn parse_pem_csr(pem_str string) !CSR {
	return x509.parse_pem_csr(pem_str)
}

pub fn load_csr(path string) !CSR {
	return x509.load_csr(path)
}

pub fn validate_x509_certificate(cert X509Certificate, intermediates []X509Certificate, opts ValidationOptions) !ValidationResult {
	return x509.validate_certificate(cert, intermediates, opts)
}

pub fn verify_x509_signature(cert X509Certificate, issuer_cert X509Certificate) bool {
	return x509.verify_signature(cert, issuer_cert)
}

pub fn validate_x509_host(cert X509Certificate, host string) !bool {
	return x509.validate_host(cert, host)
}

pub fn sign_x509_csr(csr CSR, issuer_cert X509Certificate, issuer_priv_key []u8, validity X509Validity) !X509Certificate {
	return x509.sign_csr(csr, issuer_cert, issuer_priv_key, validity)
}
