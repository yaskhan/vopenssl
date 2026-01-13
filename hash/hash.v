module hash

import os

// HashAlgorithm represents supported hash algorithms
pub enum HashAlgorithm {
	sha1
	sha256
	sha512
	blake2b_256
	blake2b_512
	blake2s_256
	blake3
	md5
}

// Hasher is the interface for incremental hashing
pub interface Hasher {
	// write adds data to the hash
	write(data []u8)
	// sum returns the final hash and resets the hasher
	sum() []u8
	// reset resets the hasher to its initial state
	reset()
	// size returns the hash size in bytes
	size() int
}

// hash_bytes computes the hash of data using the specified algorithm.
//
// Example:
// ```v
// data := 'Hello, World!'.bytes()
// hash := hash.hash_bytes(data, .sha256)
// println('Hash: ${hash.hex()}')
// ```
pub fn hash_bytes(data []u8, algorithm HashAlgorithm) []u8 {
	return match algorithm {
		.sha1 { sha1(data) }
		.sha256 { sha256(data) }
		.sha512 { sha512(data) }
		.blake2b_256 { blake2b(data, 32) or { panic(err) } }
		.blake2b_512 { blake2b(data, 64) or { panic(err) } }
		.blake2s_256 { blake2s(data, 32) or { panic(err) } }
		.blake3 { blake3(data) }
		.md5 { md5(data) }
	}
}

// hash_string computes the hash of a string using the specified algorithm.
//
// Example:
// ```v
// hash := hash.hash_string('Hello, World!', .sha256)
// ```
pub fn hash_string(s string, algorithm HashAlgorithm) []u8 {
	return hash_bytes(s.bytes(), algorithm)
}

// hash_file computes the hash of a file using the specified algorithm.
//
// Example:
// ```v
// hash := hash.hash_file('document.pdf', .sha256)!
// println('File hash: ${hash.hex()}')
// ```
pub fn hash_file(path string, algorithm HashAlgorithm) ![]u8 {
	if !os.exists(path) {
		return error('file does not exist: ${path}')
	}

	data := os.read_bytes(path)!
	return hash_bytes(data, algorithm)
}

// verify_hash verifies that the hash of data matches the expected hash.
// Uses constant-time comparison to prevent timing attacks.
//
// Example:
// ```v
// is_valid := hash.verify_hash(data, expected_hash, .sha256)
// ```
pub fn verify_hash(data []u8, expected_hash []u8, algorithm HashAlgorithm) bool {
	computed_hash := hash_bytes(data, algorithm)
	if computed_hash.len != expected_hash.len {
		return false
	}
	// Use constant-time comparison
	return constant_time_compare(computed_hash, expected_hash)
}

// constant_time_compare compares two byte slices in constant time.
// Returns true if they are equal, false otherwise.
fn constant_time_compare(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut result := u8(0)
	for i in 0 .. a.len {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
