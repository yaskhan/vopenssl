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
	md5
}

// hash_bytes computes the hash of data using the specified algorithm.
pub fn hash_bytes(data []u8, algorithm HashAlgorithm) []u8 {
	return match algorithm {
		.sha1 { sha1(data) }
		.sha256 { sha256(data) }
		.sha512 { sha512(data) }
		.blake2b_256 { blake2b_256(data) or { panic(err) } }
		.blake2b_512 { blake2b_512(data) or { panic(err) } }
		.blake2s_256 { blake2s_256(data) or { panic(err) } }
		.md5 { md5(data) }
	}
}

// hash_string computes the hash of a string using the specified algorithm.
pub fn hash_string(s string, algorithm HashAlgorithm) []u8 {
	return hash_bytes(s.bytes(), algorithm)
}

// hash_file computes the hash of a file using the specified algorithm.
pub fn hash_file(path string, algorithm HashAlgorithm) ![]u8 {
	if !os.exists(path) {
		return error('file does not exist: ${path}')
	}
	
	data := os.read_bytes(path)!
	return hash_bytes(data, algorithm)
}

// verify_hash verifies that the hash of data matches the expected hash.
pub fn verify_hash(data []u8, expected_hash []u8, algorithm HashAlgorithm) bool {
	computed_hash := hash_bytes(data, algorithm)
	if computed_hash.len != expected_hash.len {
		return false
	}
	return constant_time_compare(computed_hash, expected_hash)
}

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
