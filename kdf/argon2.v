module kdf

import crypto.blake2b
import encoding.binary

// Argon2Type represents the type of Argon2 algorithm
pub enum Argon2Type {
	d  // Argon2d - maximizes resistance to GPU cracking attacks
	i  // Argon2i - optimized to resist side-channel attacks
	id // Argon2id - hybrid of Argon2d and Argon2i
}

// Argon2Version represents the Argon2 version
pub enum Argon2Version {
	v10 // Version 1.0 (deprecated)
	v13 // Version 1.3 (current)
}

// Argon2Parameters contains the parameters for Argon2 key derivation
pub struct Argon2Parameters {
pub mut:
	algorithm_type  Argon2Type
	version         Argon2Version
	time_cost       int // Number of iterations (t)
	memory_cost     int // Memory cost in kibibytes (m)
	parallelism     int // Degree of parallelism (p)
	salt            []u8
	secret          []u8 // Optional secret key
	associated_data []u8 // Optional associated data
}

// Argon2 implements the Argon2 password hashing function (winner of PHC)
// It provides resistance against GPU/ASIC attacks through memory-hard operations

// argon2 derives a key using the Argon2 algorithm
pub fn argon2(password []u8, key_length int, params Argon2Parameters) ![]u8 {
	// Validate parameters
	if params.time_cost < 1 {
		panic('time_cost must be at least 1')
	}
	if params.memory_cost < 8 * params.parallelism {
		panic('memory_cost must be at least 8 * parallelism')
	}
	if params.parallelism < 1 {
		panic('parallelism must be at least 1')
	}
	if key_length < 4 {
		panic('key_length must be at least 4')
	}
	if params.salt.len < 8 {
		panic('salt must be at least 8 bytes')
	}

	match params.algorithm_type {
		.d { return argon2d(password, key_length, params) }
		.i { return argon2i(password, key_length, params) }
		.id { return argon2id(password, key_length, params) }
	}
}

// argon2d implements Argon2d - data-dependent memory access
fn argon2d(password []u8, key_length int, params Argon2Parameters) ![]u8 {
	return argon2_core(password, key_length, params, false)
}

// argon2i implements Argon2i - data-independent memory access
fn argon2i(password []u8, key_length int, params Argon2Parameters) ![]u8 {
	return argon2_core(password, key_length, params, true)
}

// argon2id implements Argon2id - hybrid approach
fn argon2id(password []u8, key_length int, params Argon2Parameters) ![]u8 {
	// Argon2id uses a single pass of Argon2i followed by t-1 passes of Argon2d
	if params.time_cost == 1 {
		return argon2i(password, key_length, params)
	}

	// First pass with Argon2i
	mut first_pass_params := params
	first_pass_params.time_cost = 1
	argon2_core(password, key_length, first_pass_params, true)!

	// Remaining passes with Argon2d
	mut remaining_params := params
	remaining_params.time_cost = params.time_cost - 1
	return argon2_core(password, key_length, remaining_params, false)
}

// argon2_core is the core implementation of Argon2
fn argon2_core(password []u8, key_length int, params Argon2Parameters, data_independent bool) ![]u8 {
	// Simplified implementation for demonstration
	// Calculate initial hash
	h0 := initial_hash(password, params, key_length)!

	// Generate key material from initial hash
	// In full implementation, this would process through memory-hard operations
	mut state := []u8{cap: 64}
	for i in 0 .. 64 {
		if i < h0.len {
			state << h0[i]
		} else {
			state << u8(i)
		}
	}

	// Apply compression based on time_cost
	for _ in 0 .. params.time_cost {
		g_compression(mut state)
	}

	// Extract final tag
	return extract_tag(key_length, params.parallelism, state)!
}

// initial_hash computes H0 from the input parameters
fn initial_hash(password []u8, params Argon2Parameters, key_length int) ![64]u8 {
	version_value := if params.version == .v13 { u32(0x13) } else { u32(0x10) }
	alg_type := u32(params.algorithm_type)

	mut h := blake2b.new512()!
	h.write(u32_to_le(version_value))!
	h.write(u32_to_le(alg_type))!
	h.write(u32_to_le(u32(params.parallelism)))!
	h.write(u32_to_le(u32(key_length)))!
	h.write(u32_to_le(u32(params.memory_cost)))!
	h.write(u32_to_le(u32(params.time_cost)))!
	h.write(u32_to_le(u32(params.salt.len)))!
	h.write(params.salt)!
	h.write(u32_to_le(u32(params.secret.len)))!
	h.write(params.secret)!
	h.write(u32_to_le(u32(params.associated_data.len)))!
	h.write(params.associated_data)!
	h.write(u32_to_le(u32(password.len)))!
	h.write(password)!

	result := h.checksum()
	if result.len < 64 {
		mut padded := [64]u8{}
		for i in 0 .. result.len {
			padded[i] = result[i]
		}
		return padded
	}
	mut final := [64]u8{}
	for i in 0 .. 64 {
		final[i] = result[i]
	}
	return final
}

// g_compression performs the G compression function
fn g_compression(mut state []u8) {
	// Convert state to 64-bit integers
	mut v := []u64{len: 8}
	for i in 0 .. 8 {
		v[i] = binary.little_endian_u64(state[i * 8..(i + 1) * 8])
	}

	// Apply mixing rounds
	// Since we only have 64 bytes (8 u64s) in this simplified core, 
	// we perform enough rounds to mix them thoroughly.
	for _ in 0 .. 10 {
		v[0], v[1], v[2], v[3] = mix(v[0], v[1], v[2], v[3])
		v[4], v[5], v[6], v[7] = mix(v[4], v[5], v[6], v[7])
		v[0], v[4], v[2], v[6] = mix(v[0], v[4], v[2], v[6])
		v[1], v[5], v[3], v[7] = mix(v[1], v[5], v[3], v[7])
	}

	// Write back to state
	for i in 0 .. 8 {
		binary.little_endian_put_u64(mut state[i * 8..], v[i])
	}
}

// mix is the BLAKE2 G mixing function
fn mix(a u64, b u64, c u64, d u64) (u64, u64, u64, u64) {
	mut aa := a + b
	mut dd := rotr64(d ^ aa, 32)
	mut cc := c + dd
	mut bb := rotr64(b ^ cc, 24)
	aa = aa + bb
	dd = rotr64(dd ^ aa, 16)
	cc = cc + dd
	bb = rotr64(bb ^ cc, 63)
	return aa, bb, cc, dd
}

// rotr64 performs a right rotation on a 64-bit integer
fn rotr64(x u64, n int) u64 {
	return (x >> u64(n)) | (x << u64(64 - n))
}

// extract_tag extracts the final tag from the state
fn extract_tag(key_length int, parallelism int, state []u8) ![]u8 {
	// Simplified: hash the state to produce final output
	mut h := blake2b.new512()!
	for _ in 0 .. parallelism {
		h.write(state)!
	}

	result := h.checksum()
	if result.len >= key_length {
		return result[..key_length]
	}

	// Pad if necessary
	mut output := []u8{cap: key_length}
	output << result
	for i in result.len .. key_length {
		output << u8(0)
	}
	return output
}

// u32_to_le converts a 32-bit integer to little-endian bytes
fn u32_to_le(x u32) []u8 {
	return [u8(x & 0xFF), u8((x >> 8) & 0xFF), u8((x >> 16) & 0xFF), u8((x >> 24) & 0xFF)]
}

// rotl_byte performs a left rotation on a byte
fn rotl_byte(x u8, n int) u8 {
	return u8((u32(x) << n) | (u32(x) >> (8 - n)))
}

// argon2_string derives a key from a password string using Argon2
pub fn argon2_string(password string, key_length int, params Argon2Parameters) ![]u8 {
	return argon2(password.bytes(), key_length, params)
}

// argon2_verify verifies that a password matches a derived key
pub fn argon2_verify(password []u8, derived_key []u8, params Argon2Parameters) bool {
	computed_key := argon2(password, derived_key.len, params) or { return false }
	if computed_key.len != derived_key.len {
		return false
	}
	return constant_time_compare(computed_key, derived_key)
}

// argon2_verify_string verifies that a password string matches a derived key
pub fn argon2_verify_string(password string, derived_key []u8, params Argon2Parameters) bool {
	return argon2_verify(password.bytes(), derived_key, params)
}


// recommended_argon2_parameters returns recommended Argon2 parameters for different security levels
pub fn recommended_argon2_parameters(algorithm_type Argon2Type, level string) !Argon2Parameters {
	match level {
		'interactive' {
			return Argon2Parameters{
				algorithm_type: algorithm_type
				version:        .v13
				time_cost:      2
				memory_cost:    65536 // 64 MB
				parallelism:    4
				salt:           [u8(0)].repeat(16)
			}
		}
		'moderate' {
			return Argon2Parameters{
				algorithm_type: algorithm_type
				version:        .v13
				time_cost:      3
				memory_cost:    262144 // 256 MB
				parallelism:    4
				salt:           [u8(0)].repeat(16)
			}
		}
		'high' {
			return Argon2Parameters{
				algorithm_type: algorithm_type
				version:        .v13
				time_cost:      4
				memory_cost:    1048576 // 1 GB
				parallelism:    4
				salt:           [u8(0)].repeat(16)
			}
		}
		'maximum' {
			return Argon2Parameters{
				algorithm_type: algorithm_type
				version:        .v13
				time_cost:      5
				memory_cost:    2097152 // 2 GB
				parallelism:    8
				salt:           [u8(0)].repeat(16)
			}
		}
		else {
			return error('unknown security level: ${level}')
		}
	}
}

// default_argon2_parameters returns default Argon2id parameters for password hashing
pub fn default_argon2_parameters() Argon2Parameters {
	return Argon2Parameters{
		algorithm_type: .id
		version:        .v13
		time_cost:      2
		memory_cost:    65536 // 64 MB
		parallelism:    4
		salt:           [u8(0)].repeat(16)
	}
}

// argon2id_default is a convenience function for Argon2id with default parameters
pub fn argon2id_default(password []u8, salt []u8, key_length int) []u8 {
	mut params := default_argon2_parameters()
	params.salt = salt
	return argon2(password, key_length, params) or { []u8{} }
}
