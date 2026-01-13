module mac

import crypto.hmac
import crypto.sha256
import crypto.sha512
import crypto.sha1
import crypto.md5
import hash


// hmac_sha256 computes the HMAC-SHA256 of a message with the given key.
//
// Example:
// ```v
// key := 'secret-key'.bytes()
// message := 'Important message'.bytes()
// mac := mac.hmac_sha256(key, message)
// ```
pub fn hmac_sha256(key []u8, message []u8) []u8 {
	mut h := hmac.new(key, sha256.sum256, sha256.block_size)
	h.write(message) or { panic(err) }
	return h.sum([])
}

// hmac_sha512 computes the HMAC-SHA512 of a message with the given key.
//
// Example:
// ```v
// mac := mac.hmac_sha512(key, message)
// ```
pub fn hmac_sha512(key []u8, message []u8) []u8 {
	mut h := hmac.new(key, sha512.sum512, sha512.block_size)
	h.write(message) or { panic(err) }
	return h.sum([])
}

// hmac_sha1 computes the HMAC-SHA1 of a message with the given key.
// Note: SHA-1 is deprecated for security-critical applications.
//
// Example:
// ```v
// mac := mac.hmac_sha1(key, message)
// ```
pub fn hmac_sha1(key []u8, message []u8) []u8 {
	mut h := hmac.new(key, sha1.sum, sha1.block_size)
	h.write(message) or { panic(err) }
	return h.sum([])
}

// hmac_md5 computes the HMAC-MD5 of a message with the given key.
// WARNING: MD5 is cryptographically broken. Use HMAC-SHA256 instead.
//
// Example:
// ```v
// mac := mac.hmac_md5(key, message)
// ```
pub fn hmac_md5(key []u8, message []u8) []u8 {
	mut h := hmac.new(key, md5.sum, md5.block_size)
	h.write(message) or { panic(err) }
	return h.sum([])
}

// hmac computes the HMAC of a message using the specified hash algorithm.
//
// Example:
// ```v
// mac := mac.hmac(key, message, .sha256)
// ```
pub fn hmac_hash(key []u8, message []u8, algorithm hash.HashAlgorithm) []u8 {
	return match algorithm {
		.sha1 { hmac_sha1(key, message) }
		.sha256 { hmac_sha256(key, message) }
		.sha512 { hmac_sha512(key, message) }
		.md5 { hmac_md5(key, message) }
		else { panic('HMAC not supported for algorithm: ${algorithm}') }
	}
}

// verify_hmac verifies that the HMAC of a message matches the expected MAC.
// Uses constant-time comparison to prevent timing attacks.
//
// Example:
// ```v
// is_valid := mac.verify_hmac(message, expected_mac, key, .sha256)
// if is_valid {
//     println('HMAC is valid')
// }
// ```
pub fn verify_hmac(message []u8, expected_mac []u8, key []u8, algorithm hash.HashAlgorithm) bool {
	computed_mac := hmac_hash(key, message, algorithm)
	if computed_mac.len != expected_mac.len {
		return false
	}
	return constant_time_compare(computed_mac, expected_mac)
}

// verify_hmac_sha256 verifies HMAC-SHA256 in constant time.
//
// Example:
// ```v
// is_valid := mac.verify_hmac_sha256(message, expected_mac, key)
// ```
pub fn verify_hmac_sha256(message []u8, expected_mac []u8, key []u8) bool {
	return verify_hmac(message, expected_mac, key, .sha256)
}

// verify_hmac_sha512 verifies HMAC-SHA512 in constant time.
//
// Example:
// ```v
// is_valid := mac.verify_hmac_sha512(message, expected_mac, key)
// ```
pub fn verify_hmac_sha512(message []u8, expected_mac []u8, key []u8) bool {
	return verify_hmac(message, expected_mac, key, .sha512)
}

// constant_time_compare compares two byte slices in constant time.
// Returns true if they are equal, false otherwise.
// This prevents timing attacks when verifying MACs.
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

// HMACHasher provides incremental HMAC computation
pub struct HMACHasher {
mut:
	hmac hmac.Hmac
}

// new_hmac_sha256 creates a new HMAC-SHA256 hasher for incremental computation.
//
// Example:
// ```v
// mut hasher := mac.new_hmac_sha256(key)
// hasher.write('Part 1'.bytes())
// hasher.write('Part 2'.bytes())
// result := hasher.sum()
// ```
pub fn new_hmac_sha256(key []u8) HMACHasher {
	return HMACHasher{
		hmac: hmac.new(key, sha256.sum256, sha256.block_size)
	}
}

// new_hmac_sha512 creates a new HMAC-SHA512 hasher for incremental computation.
//
// Example:
// ```v
// mut hasher := mac.new_hmac_sha512(key)
// hasher.write('Part 1'.bytes())
// hasher.write('Part 2'.bytes())
// result := hasher.sum()
// ```
pub fn new_hmac_sha512(key []u8) HMACHasher {
	return HMACHasher{
		hmac: hmac.new(key, sha512.sum512, sha512.block_size)
	}
}

// write adds data to the HMAC
pub fn (mut h HMACHasher) write(data []u8) {
	h.hmac.write(data) or { panic(err) }
}

// sum returns the final HMAC
pub fn (mut h HMACHasher) sum() []u8 {
	return h.hmac.sum([])
}

// reset resets the HMAC to its initial state
pub fn (mut h HMACHasher) reset() {
	h.hmac.reset()
}
