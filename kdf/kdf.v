module kdf

import hash
import mac
import encoding.binary

// PBKDF2 (Password-Based Key Derivation Function 2)
// Defined in RFC 2898 (PKCS #5 v2.0) and RFC 8018 (PKCS #5 v2.1)

// PBKDF2Parameters contains the parameters for PBKDF2 derivation
pub struct PBKDF2Parameters {
pub:
	salt       []u8
	iterations int
	key_length int
	algorithm  hash.HashAlgorithm
}

// pbkdf2 derives a key using the PBKDF2 algorithm
pub fn pbkdf2(password []u8, params PBKDF2Parameters) []u8 {
	return pbkdf2_hash(password, params.salt, params.iterations, params.key_length, params.algorithm)
}

// pbkdf2_string derives a key from a password string using PBKDF2
pub fn pbkdf2_string(password string, params PBKDF2Parameters) []u8 {
	return pbkdf2(password.bytes(), params)
}

// pbkdf2_hash derives a key using PBKDF2 with the specified hash algorithm
pub fn pbkdf2_hash(password []u8, salt []u8, iterations int, key_length int, algorithm hash.HashAlgorithm) []u8 {
	mut derived := []u8{cap: key_length}
	h_len := match algorithm {
		.sha1 { 20 }
		.sha256 { 32 }
		.sha512 { 64 }
		.md5 { 16 }
		else { 32 } // Default to 32 for unknown
	}
	
	block_count := (key_length + h_len - 1) / h_len
	
	for i in 1 .. block_count + 1 {
		mut u := []u8{cap: salt.len + 4}
		u << salt
		u << u8((i >> 24) & 0xff)
		u << u8((i >> 16) & 0xff)
		u << u8((i >> 8) & 0xff)
		u << u8(i & 0xff)
		
		u = mac.hmac_hash(password, u, algorithm)
		mut t := u.clone()
		
		for _ in 1 .. iterations {
			u = mac.hmac_hash(password, u, algorithm)
			for k in 0 .. u.len {
				t[k] ^= u[k]
			}
		}
		
		derived << t
	}
	
	if derived.len > key_length {
		return derived[..key_length]
	}
	return derived
}

// Convenience wrappers for common hash algorithms
pub fn pbkdf2_hmac_sha1(password []u8, salt []u8, iterations int, key_length int) []u8 {
	return pbkdf2_hash(password, salt, iterations, key_length, .sha1)
}

pub fn pbkdf2_hmac_sha256(password []u8, salt []u8, iterations int, key_length int) []u8 {
	return pbkdf2_hash(password, salt, iterations, key_length, .sha256)
}

pub fn pbkdf2_hmac_sha512(password []u8, salt []u8, iterations int, key_length int) []u8 {
	return pbkdf2_hash(password, salt, iterations, key_length, .sha512)
}

// Verification functions
pub fn pbkdf2_verify(password []u8, derived_key []u8, params PBKDF2Parameters) bool {
	computed := pbkdf2(password, params)
	if computed.len != derived_key.len {
		return false
	}
	return constant_time_compare(computed, derived_key)
}

pub fn pbkdf2_verify_string(password string, derived_key []u8, params PBKDF2Parameters) bool {
	return pbkdf2_verify(password.bytes(), derived_key, params)
}

// Recommended parameters
pub fn recommended_pbkdf2_iterations() map[string]int {
	return {
		'sha1':   1000
		'sha256': 600000
		'sha512': 210000
	}
}

pub fn default_pbkdf2_parameters() PBKDF2Parameters {
	return PBKDF2Parameters{
		salt:       []u8{len: 16, init: 0}
		iterations: 10000
		key_length: 32
		algorithm:  .sha256
	}
}

// Internal constant time comparison
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
