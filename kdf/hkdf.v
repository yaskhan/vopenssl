module kdf

import mac
import hash

// HKDFParameters contains the parameters for HKDF key derivation
pub struct HKDFParameters {
	algorithm hash.HashAlgorithm
	salt      []u8 // optional salt (can be empty)
	info      []u8 // optional context/application info
}

// HKDF implements HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869)
// It's suitable for deriving keys from a master secret or key material

// hkdf_extract performs the extract phase of HKDF
fn hkdf_extract(salt []u8, ikm []u8, algorithm hash.HashAlgorithm) []u8 {
	if ikm.len == 0 {
		panic('input key material (ikm) cannot be empty')
	}
	// If salt is not provided, use a string of hash length zeros
	actual_salt := if salt.len == 0 { [u8(0)].repeat(hash_length(algorithm)) } else { salt }
	return mac.hmac_hash(actual_salt, ikm, algorithm)
}

// hkdf_expand performs the expand phase of HKDF
fn hkdf_expand(prk []u8, info []u8, l int, algorithm hash.HashAlgorithm) []u8 {
	hash_len := hash_length(algorithm)
	if prk.len < hash_len {
		panic('pseudo-random key (prk) must be at least hash length')
	}
	if l > 255 * hash_len {
		panic('output length (l) too large')
	}

	mut okm := []u8{cap: l}
	mut t := []u8{}
	mut n := u8(1)

	for okm.len < l {
		// T(i) = HMAC(PRK, T(i-1) | info | i)
		mut hmac_input := []u8{cap: t.len + info.len + 1}
		hmac_input << t
		hmac_input << info
		hmac_input << n

		t = mac.hmac_hash(prk, hmac_input, algorithm)
		bytes_to_append := if l - okm.len < t.len { l - okm.len } else { t.len }
		okm << t[..bytes_to_append]
		n++
	}

	return okm
}

// hkdf derives a key using HKDF-Extract-and-Expand
pub fn hkdf(ikm []u8, l int, params HKDFParameters) []u8 {
	// Extract phase: PRK = HMAC-Hash(salt, IKM)
	prk := hkdf_extract(params.salt, ikm, params.algorithm)
	// Expand phase: OKM = HMAC-Hash-Expand(PRK, info, L)
	return hkdf_expand(prk, params.info, l, params.algorithm)
}

// hkdf_extract_only performs only the HKDF-Extract phase
pub fn hkdf_extract_only(salt []u8, ikm []u8, algorithm hash.HashAlgorithm) []u8 {
	return hkdf_extract(salt, ikm, algorithm)
}

// hkdf_expand_only performs only the HKDF-Expand phase
pub fn hkdf_expand_only(prk []u8, info []u8, l int, algorithm hash.HashAlgorithm) []u8 {
	return hkdf_expand(prk, info, l, algorithm)
}

// hkdf_sha256 derives a key using HKDF-HMAC-SHA256
pub fn hkdf_sha256(ikm []u8, l int, salt []u8, info []u8) []u8 {
	return hkdf(ikm, l, HKDFParameters{ algorithm: .sha256, salt: salt, info: info })
}

// hkdf_sha512 derives a key using HKDF-HMAC-SHA512
pub fn hkdf_sha512(ikm []u8, l int, salt []u8, info []u8) []u8 {
	return hkdf(ikm, l, HKDFParameters{ algorithm: .sha512, salt: salt, info: info })
}

// hkdf_sha1 derives a key using HKDF-HMAC-SHA1
pub fn hkdf_sha1(ikm []u8, l int, salt []u8, info []u8) []u8 {
	return hkdf(ikm, l, HKDFParameters{ algorithm: .sha1, salt: salt, info: info })
}

// hkdf_string derives a key from a string input using HKDF
pub fn hkdf_string(ikm string, l int, params HKDFParameters) []u8 {
	return hkdf(ikm.bytes(), l, params)
}

// hkdf_string_sha256 derives a key from a string input using HKDF-HMAC-SHA256
pub fn hkdf_string_sha256(ikm string, l int, salt []u8, info []u8) []u8 {
	return hkdf_sha256(ikm.bytes(), l, salt, info)
}

// hkdf_derive_keys derives multiple keys of different lengths from a single secret
pub fn hkdf_derive_keys(secret []u8, key_lengths []int, params HKDFParameters) [][]u8 {
	total_length := 0
	for length in key_lengths {
		total_length += length
	}

	derived := hkdf(secret, total_length, params)
	mut keys := [][]u8{cap: key_lengths.len}
	mut offset := 0

	for length in key_lengths {
		keys << derived[offset..offset + length]
		offset += length
	}

	return keys
}

// hkdf_expand_label is a helper for TLS 1.3 style HKDF expand with labels
// This is useful for TLS key derivation and similar protocols
pub fn hkdf_expand_label(secret []u8, label string, context []u8, length int, algorithm hash.HashAlgorithm) []u8 {
	// Construct HkdfLabel structure
	mut hkdf_label := []u8{}

	// Length (2 bytes)
	hkdf_label << u8((length >> 8) & 0xFF)
	hkdf_label << u8(length & 0xFF)

	// Label: "tls13 " + label + 0x00
	label_prefix := 'tls13 '
	label_with_prefix := label_prefix + label
	hkdf_label << label_with_prefix.bytes()
	hkdf_label << u8(0)

	// Context
	hkdf_label << context

	return hkdf_expand(secret, hkdf_label, length, algorithm)
}

// hash_length returns the output length of a hash algorithm in bytes
fn hash_length(algorithm hash.HashAlgorithm) int {
	return match algorithm {
		.sha1 { 20 }
		.sha256 { 32 }
		.sha512 { 64 }
		.blake2b_256 { 32 }
		.blake2b_512 { 64 }
		.blake2s_256 { 32 }
		.md5 { 16 }
	}
}

// default_hkdf_parameters returns default HKDF parameters
pub fn default_hkdf_parameters() HKDFParameters {
	return HKDFParameters{
		algorithm: .sha256
		salt:      []
		info:      []
	}
}
