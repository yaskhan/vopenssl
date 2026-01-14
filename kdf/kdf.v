module kdf

import hash

// Import submodules
import pbkdf2
import hkdf
import scrypt
import argon2

// Key Derivation Functions (KDF) module
// This module provides various key derivation functions including:
// - PBKDF2 (RFC 2898): Password-based key derivation
// - HKDF (RFC 5869): HMAC-based extract-and-expand key derivation
// - Scrypt (RFC 7914): Memory-hard key derivation
// - Argon2 (RFC 9106): Memory-hard password hashing (winner of PHC)

// Re-export all types and functions for convenience

// PBKDF2 types
pub type PBKDF2Parameters = pbkdf2.PBKDF2Parameters

// HKDF types
pub type HKDFParameters = hkdf.HKDFParameters

// Scrypt types
pub type ScryptParameters = scrypt.ScryptParameters

// Argon2 types
pub type Argon2Type = argon2.Argon2Type
pub type Argon2Version = argon2.Argon2Version
pub type Argon2Parameters = argon2.Argon2Parameters

// Re-export PBKDF2 functions
pub fn pbkdf2(password []u8, params PBKDF2Parameters) []u8 {
	return pbkdf2.pbkdf2(password, params)
}

pub fn pbkdf2_hmac_sha1(password []u8, salt []u8, iterations int, key_length int) []u8 {
	return pbkdf2.pbkdf2_hmac_sha1(password, salt, iterations, key_length)
}

pub fn pbkdf2_hmac_sha256(password []u8, salt []u8, iterations int, key_length int) []u8 {
	return pbkdf2.pbkdf2_hmac_sha256(password, salt, iterations, key_length)
}

pub fn pbkdf2_hmac_sha512(password []u8, salt []u8, iterations int, key_length int) []u8 {
	return pbkdf2.pbkdf2_hmac_sha512(password, salt, iterations, key_length)
}

pub fn pbkdf2_string(password string, params PBKDF2Parameters) []u8 {
	return pbkdf2.pbkdf2_string(password, params)
}

pub fn pbkdf2_string_sha256(password string, salt []u8, iterations int, key_length int) []u8 {
	return pbkdf2.pbkdf2_string_sha256(password, salt, iterations, key_length)
}

pub fn pbkdf2_verify(password []u8, derived_key []u8, params PBKDF2Parameters) bool {
	return pbkdf2.pbkdf2_verify(password, derived_key, params)
}

pub fn pbkdf2_verify_string(password string, derived_key []u8, params PBKDF2Parameters) bool {
	return pbkdf2.pbkdf2_verify_string(password, derived_key, params)
}

pub fn recommended_pbkdf2_iterations() map[string]int {
	return pbkdf2.recommended_iterations()
}

pub fn default_pbkdf2_parameters() PBKDF2Parameters {
	return pbkdf2.default_pbkdf2_parameters()
}

// Re-export HKDF functions
pub fn hkdf(ikm []u8, l int, params HKDFParameters) []u8 {
	return hkdf.hkdf(ikm, l, params)
}

pub fn hkdf_extract_only(salt []u8, ikm []u8, algorithm hash.HashAlgorithm) []u8 {
	return hkdf.hkdf_extract_only(salt, ikm, algorithm)
}

pub fn hkdf_expand_only(prk []u8, info []u8, l int, algorithm hash.HashAlgorithm) []u8 {
	return hkdf.hkdf_expand_only(prk, info, l, algorithm)
}

pub fn hkdf_sha256(ikm []u8, l int, salt []u8, info []u8) []u8 {
	return hkdf.hkdf_sha256(ikm, l, salt, info)
}

pub fn hkdf_sha512(ikm []u8, l int, salt []u8, info []u8) []u8 {
	return hkdf.hkdf_sha512(ikm, l, salt, info)
}

pub fn hkdf_sha1(ikm []u8, l int, salt []u8, info []u8) []u8 {
	return hkdf.hkdf_sha1(ikm, l, salt, info)
}

pub fn hkdf_string(ikm string, l int, params HKDFParameters) []u8 {
	return hkdf.hkdf_string(ikm, l, params)
}

pub fn hkdf_string_sha256(ikm string, l int, salt []u8, info []u8) []u8 {
	return hkdf.hkdf_string_sha256(ikm, l, salt, info)
}

pub fn hkdf_derive_keys(secret []u8, key_lengths []int, params HKDFParameters) [][]u8 {
	return hkdf.hkdf_derive_keys(secret, key_lengths, params)
}

pub fn hkdf_expand_label(secret []u8, label string, context []u8, length int, algorithm hash.HashAlgorithm) []u8 {
	return hkdf.hkdf_expand_label(secret, label, context, length, algorithm)
}

pub fn default_hkdf_parameters() HKDFParameters {
	return hkdf.default_hkdf_parameters()
}

// Re-export Scrypt functions
pub fn scrypt(password []u8, salt []u8, params ScryptParameters, key_length int) []u8 {
	return scrypt.scrypt(password, salt, params, key_length)
}

pub fn scrypt_string(password string, salt []u8, params ScryptParameters, key_length int) []u8 {
	return scrypt.scrypt_string(password, salt, params, key_length)
}

pub fn scrypt_verify(password []u8, derived_key []u8, salt []u8, params ScryptParameters) bool {
	return scrypt.scrypt_verify(password, derived_key, salt, params)
}

pub fn scrypt_verify_string(password string, derived_key []u8, salt []u8, params ScryptParameters) bool {
	return scrypt.scrypt_verify_string(password, derived_key, salt, params)
}

pub fn recommended_scrypt_parameters(level string) !ScryptParameters {
	return scrypt.recommended_scrypt_parameters(level)
}

pub fn default_scrypt_parameters() ScryptParameters {
	return scrypt.default_scrypt_parameters()
}

// Re-export Argon2 functions
pub fn argon2(password []u8, key_length int, params Argon2Parameters) []u8 {
	return argon2.argon2(password, key_length, params)
}

pub fn argon2_string(password string, key_length int, params Argon2Parameters) []u8 {
	return argon2.argon2_string(password, key_length, params)
}

pub fn argon2_verify(password []u8, derived_key []u8, params Argon2Parameters) bool {
	return argon2.argon2_verify(password, derived_key, params)
}

pub fn argon2_verify_string(password string, derived_key []u8, params Argon2Parameters) bool {
	return argon2.argon2_verify_string(password, derived_key, params)
}

pub fn recommended_argon2_parameters(algorithm_type Argon2Type, level string) !Argon2Parameters {
	return argon2.recommended_argon2_parameters(algorithm_type, level)
}

pub fn default_argon2_parameters() Argon2Parameters {
	return argon2.default_argon2_parameters()
}

pub fn argon2id_default(password []u8, salt []u8, key_length int) []u8 {
	return argon2.argon2id_default(password, salt, key_length)
}
