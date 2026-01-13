module vopenssl

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
//
// // Hash a file
// hash := hash.sha256_file('document.pdf')!
// println('SHA-256: ${hash.hex()}')
//
// // Encrypt data
// key := rand.generate_key(256)!
// encrypted := cipher.encrypt_aes_256_gcm(key, plaintext)!
// ```
//
// Available modules:
// - vopenssl.rand: Random number generation
// - vopenssl.hash: Hashing algorithms (SHA, BLAKE, MD5)
// - vopenssl.mac: HMAC and message authentication
// - vopenssl.cipher: Symmetric encryption (AES with GCM, CBC, CTR modes)
// - vopenssl.utils: Utilities (padding, hex encoding, etc.)
