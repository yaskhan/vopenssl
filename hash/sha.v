module hash

import crypto.sha256 as crypto_sha256
import crypto.sha512 as crypto_sha512
import crypto.sha1 as crypto_sha1

// sha256 computes the SHA-256 hash of data.
pub fn sha256(data []u8) []u8 {
	return crypto_sha256.sum256(data)
}

// sha224 computes the SHA-224 hash of data.
pub fn sha224(data []u8) []u8 {
	return crypto_sha256.sum224(data)
}

// sha512 computes the SHA-512 hash of data.
pub fn sha512(data []u8) []u8 {
	return crypto_sha512.sum512(data)
}

// sha384 computes the SHA-384 hash of data.
pub fn sha384(data []u8) []u8 {
	return crypto_sha512.sum384(data)
}

// sha1 computes the SHA-1 hash of data.
pub fn sha1(data []u8) []u8 {
	return crypto_sha1.sum(data)
}

// sha256_file computes the SHA-256 hash of a file.
pub fn sha256_file(path string) ![]u8 {
	return hash_file(path, .sha256)
}

// sha512_file computes the SHA-512 hash of a file.
pub fn sha512_file(path string) ![]u8 {
	return hash_file(path, .sha512)
}
