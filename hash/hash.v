module hash

import crypto.sha256 as vsha256
import crypto.sha512 as vsha512
import crypto.sha1 as vsha1
import crypto.md5 as vmd5
import crypto.blake2b
import crypto.blake2s
import os

// HashAlgorithm represents supported hash algorithms
pub enum HashAlgorithm {
	sha1
	sha224
	sha256
	sha384
	sha512
	blake2b_256
	blake2b_512
	blake2s_256
	md5
}

// hash_bytes computes the hash of data using the specified algorithm.
pub fn hash_bytes(data []u8, algorithm HashAlgorithm) []u8 {
	return match algorithm {
		.sha1 { vsha1.sum(data) }
		.sha224 { []u8{} /* TODO: sha224 not in vlib? */ }
		.sha256 { vsha256.sum256(data) }
		.sha384 { vsha512.sum384(data) }
		.sha512 { vsha512.sum512(data) }
		.blake2b_256 { blake2b.sum256(data) }
		.blake2b_512 { blake2b.sum512(data) }
		.blake2s_256 { blake2s.sum256(data) }
		.md5 { vmd5.sum(data) }
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

// Hasher interface defines the methods for incremental hashing.
pub interface Hasher {
mut:
	write(p []u8) !int
	checksum() []u8
	reset()
	block_size() int
	size() int
	free()
}

// new_hasher creates a new streaming Hasher for the specified algorithm.
pub fn new_hasher(algorithm HashAlgorithm) !Hasher {
	return match algorithm {
		.sha1 { new_sha1_hasher() }
		.sha256 { new_sha256_hasher() }
		.sha384 { new_sha384_hasher() }
		.sha512 { new_sha512_hasher() }
		.md5 { new_md5_hasher() }
		// Blake2b/s generic streaming support might vary in vlib, 
		// for now we only support the standard NIST + MD5 ones fully.
		// If Blake2b implies .blake2b_256, we can try to wrap it.
		// For now, return error for unsupported streaming algs if not ready.
		else { error('streaming not yet implemented for ${algorithm}') }
	}
}
