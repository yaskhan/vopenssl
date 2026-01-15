module scrypt

import crypto.sha256
import hash
import vopenssl.mac
import encoding.binary

// ScryptParameters contains the parameters for Scrypt key derivation
// Based on RFC 7914
pub struct ScryptParameters {
	n int // CPU/memory cost parameter (must be a power of 2 > 1)
	r int // Block size parameter
	p int // Parallelization parameter
}

// Scrypt implements the scrypt key derivation function (RFC 7914)
// It's designed to be memory-hard to resist GPU/ASIC attacks

// scrypt derives a key using the scrypt algorithm
pub fn scrypt(password []u8, salt []u8, params ScryptParameters, key_length int) []u8 {
	// Validate parameters
	if !is_power_of_two(params.n) || params.n < 2 {
		panic('N must be a power of 2 greater than 1')
	}
	if params.r < 1 {
		panic('r must be at least 1')
	}
	if params.p < 1 {
		panic('p must be at least 1')
	}
	if key_length < 1 {
		panic('key_length must be at least 1')
	}

	mut b := pbkdf2_hmac_sha256(password, salt, 1, params.p * 128 * params.r)
	
	mut v := []u32{len: 32 * params.n * params.r}
	mut xy := []u32{len: 64 * params.r}
	
	for i in 0 .. params.p {
		smix(mut b[i * 128 * params.r..(i + 1) * 128 * params.r], params.r, params.n, mut v, mut xy)
	}
	
	return pbkdf2_hmac_sha256(password, b, 1, key_length)
}

fn smix(mut b []u8, r int, n int, mut v []u32, mut xy []u32) {
	mut x := xy[0..32 * r]
	mut y := xy[32 * r..]
	
	// Convert B to 32-bit integers
	for i in 0 .. 32 * r {
		x[i] = binary.little_endian_u32(b[i * 4..(i + 1) * 4])
	}
	
	for i in 0 .. n {
		// Copy X to V[i]
		for k in 0 .. 32 * r {
			v[i * 32 * r + k] = x[k]
		}
		block_mix(mut x, mut y, r)
	}
	
	for i in 0 .. n {
		mut j := int(x[32 * r - 16] & u32(n - 1))
		for k in 0 .. 32 * r {
			x[k] ^= v[j * 32 * r + k]
		}
		block_mix(mut x, mut y, r)
	}
	
	// Convert X back to B
	for i in 0 .. 32 * r {
		binary.little_endian_put_u32(mut b, i * 4, x[i])
	}
}

fn block_mix(mut b []u32, mut y []u32, r int) {
	mut x := []u32{len: 16}
	for i in 0 .. 16 {
		x[i] = b[32 * r - 16 + i]
	}
	
	for i in 0 .. 2 * r {
		for j in 0 .. 16 {
			x[j] ^= b[i * 16 + j]
		}
		salsa20_8(mut x)
		
		// Map into Y
		if i % 2 == 0 {
			for j in 0 .. 16 {
				y[i / 2 * 16 + j] = x[j]
			}
		} else {
			for j in 0 .. 16 {
				y[(r + i / 2) * 16 + j] = x[j]
			}
		}
	}
	
	for i in 0 .. 32 * r {
		b[i] = y[i]
	}
}

fn salsa20_8(mut b []u32) {
	mut x := b.clone()
	for i in 0 .. 4 { // 8 rounds / 2
		x[4] ^=  rotl((x[0] + x[12]), 7)
		x[8] ^=  rotl((x[4] + x[0]), 9)
		x[12] ^= rotl((x[8] + x[4]), 13)
		x[0] ^=  rotl((x[12] + x[8]), 18)
		
		x[9] ^=  rotl((x[5] + x[1]), 7)
		x[13] ^= rotl((x[9] + x[5]), 9)
		x[1] ^=  rotl((x[13] + x[9]), 13)
		x[5] ^=  rotl((x[1] + x[13]), 18)
		
		x[14] ^= rotl((x[10] + x[6]), 7)
		x[2] ^=  rotl((x[14] + x[10]), 9)
		x[6] ^=  rotl((x[2] + x[14]), 13)
		x[10] ^= rotl((x[6] + x[2]), 18)
		
		x[3] ^=  rotl((x[15] + x[11]), 7)
		x[7] ^=  rotl((x[3] + x[15]), 9)
		x[11] ^= rotl((x[7] + x[3]), 13)
		x[15] ^= rotl((x[11] + x[7]), 18)
		
		x[1] ^=  rotl((x[0] + x[3]), 7)
		x[2] ^=  rotl((x[1] + x[0]), 9)
		x[3] ^=  rotl((x[2] + x[1]), 13)
		x[0] ^=  rotl((x[3] + x[2]), 18)
		
		x[6] ^=  rotl((x[5] + x[4]), 7)
		x[7] ^=  rotl((x[6] + x[5]), 9)
		x[4] ^=  rotl((x[7] + x[6]), 13)
		x[5] ^=  rotl((x[4] + x[7]), 18)
		
		x[11] ^= rotl((x[10] + x[9]), 7)
		x[8] ^=  rotl((x[11] + x[10]), 9)
		x[9] ^=  rotl((x[8] + x[11]), 13)
		x[10] ^= rotl((x[9] + x[8]), 18)
		
		x[12] ^= rotl((x[15] + x[14]), 7)
		x[13] ^= rotl((x[12] + x[15]), 9)
		x[14] ^= rotl((x[13] + x[12]), 13)
		x[15] ^= rotl((x[14] + x[13]), 18)
	}
	for i in 0 .. 16 {
		b[i] += x[i]
	}
}

fn rotl(a u32, b int) u32 {
	return (a << b) | (a >> (32 - b))
}

fn pbkdf2_hmac_sha256(password []u8, salt []u8, iterations int, key_length int) []u8 {
	mut derived := []u8{cap: key_length}
	block_count := (key_length + 31) / 32
	
	for i in 1 .. block_count + 1 {
		mut u := []u8{}
		u << salt
		u << u8((i >> 24) & 0xff)
		u << u8((i >> 16) & 0xff)
		u << u8((i >> 8) & 0xff)
		u << u8(i & 0xff)
		
		u = vopenssl.mac.hmac_sha256(password, u)
		mut t := u.clone()
		
		for _ in 1 .. iterations {
			u = vopenssl.mac.hmac_sha256(password, u)
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

// scrypt_string derives a key from a password string using scrypt
pub fn scrypt_string(password string, salt []u8, params ScryptParameters, key_length int) []u8 {
	return scrypt(password.bytes(), salt, params, key_length)
}

// scrypt_verify verifies that a password matches a derived key
pub fn scrypt_verify(password []u8, derived_key []u8, salt []u8, params ScryptParameters) bool {
	computed_key := scrypt(password, salt, params, derived_key.len)
	if computed_key.len != derived_key.len {
		return false
	}
	return constant_time_compare(computed_key, derived_key)
}

// scrypt_verify_string verifies that a password string matches a derived key
pub fn scrypt_verify_string(password string, derived_key []u8, salt []u8, params ScryptParameters) bool {
	return scrypt_verify(password.bytes(), derived_key, salt, params)
}

// constant_time_compare compares two byte slices in constant time
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

// is_power_of_two checks if a number is a power of two
fn is_power_of_two(n int) bool {
	return n > 0 && (n & (n - 1)) == 0
}

// recommended_scrypt_parameters returns recommended scrypt parameters for different security levels
pub fn recommended_scrypt_parameters(level string) !ScryptParameters {
	return match level {
		'interactive' {
			ScryptParameters{
				n: 32768
				r: 8
				p: 1
			}
		} // ~100ms on modern hardware
		'moderate' {
			ScryptParameters{
				n: 262144
				r: 8
				p: 1
			}
		} // ~800ms on modern hardware
		'high' {
			ScryptParameters{
				n: 1048576
				r: 8
				p: 1
			}
		} // ~3s on modern hardware
		'maximum' {
			ScryptParameters{
				n: 16777216
				r: 8
				p: 1
			}
		} // ~30s on modern hardware
		else {
			error('unknown security level: ${level}')
		}
	}
}

// default_scrypt_parameters returns default scrypt parameters for password hashing
pub fn default_scrypt_parameters() ScryptParameters {
	return ScryptParameters{
		n: 32768
		r: 8
		p: 1
	}
}
