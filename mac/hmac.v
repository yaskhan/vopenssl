module mac

import crypto.hmac
import crypto.sha256
import crypto.sha512
import crypto.sha1
import crypto.md5
import hash

// Wrappers for hash functions to match fn([]u8) []u8 signature
fn sha256_sum(d []u8) []u8 { return sha256.sum256(d) }
fn sha512_sum(d []u8) []u8 { return sha512.sum512(d) }
fn sha1_sum(d []u8) []u8 { return sha1.sum(d) }
fn md5_sum(d []u8) []u8 { return md5.sum(d) }

pub fn hmac_sha256(key []u8, message []u8) []u8 {
	return hmac.new(key, message, sha256_sum, 64)
}

pub fn hmac_sha512(key []u8, message []u8) []u8 {
	return hmac.new(key, message, sha512_sum, 128)
}

pub fn hmac_sha1(key []u8, message []u8) []u8 {
	return hmac.new(key, message, sha1_sum, 64)
}

pub fn hmac_md5(key []u8, message []u8) []u8 {
	return hmac.new(key, message, md5_sum, 64)
}

pub fn hmac_hash(key []u8, message []u8, algorithm hash.HashAlgorithm) []u8 {
	return match algorithm {
		.sha1 { hmac_sha1(key, message) }
		.sha256 { hmac_sha256(key, message) }
		.sha512 { hmac_sha512(key, message) }
		.md5 { hmac_md5(key, message) }
		else { panic('HMAC not supported for algorithm: ${algorithm}') }
	}
}

pub fn verify_hmac(message []u8, expected_mac []u8, key []u8, algorithm hash.HashAlgorithm) bool {
	computed_mac := hmac_hash(key, message, algorithm)
	if computed_mac.len != expected_mac.len {
		return false
	}
	return constant_time_compare(computed_mac, expected_mac)
}

pub fn verify_hmac_sha256(message []u8, expected_mac []u8, key []u8) bool {
	return verify_hmac(message, expected_mac, key, .sha256)
}

pub fn verify_hmac_sha512(message []u8, expected_mac []u8, key []u8) bool {
	return verify_hmac(message, expected_mac, key, .sha512)
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
