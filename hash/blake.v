module hash

import crypto.blake2b as crypto_blake2b
import crypto.blake2s as crypto_blake2s

// blake2b_256 computes the BLAKE2b-256 hash of data.
pub fn blake2b_256(data []u8) ![]u8 {
	return crypto_blake2b.sum256(data)
}

// blake2b_512 computes the BLAKE2b-512 hash of data.
pub fn blake2b_512(data []u8) ![]u8 {
	return crypto_blake2b.sum512(data)
}

// blake2s_256 computes the BLAKE2s-256 hash of data.
pub fn blake2s_256(data []u8) ![]u8 {
	return crypto_blake2s.sum256(data)
}
