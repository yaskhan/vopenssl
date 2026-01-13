module rand

import crypto.rand as crypto_rand

// bytes generates n cryptographically secure random bytes.
//
// Example:
// ```v
// random_data := rand.bytes(32)!
// ```
pub fn bytes(n int) ![]u8 {
	if n <= 0 {
		return error('number of bytes must be positive')
	}
	return crypto_rand.bytes(n)!
}

// int_in_range generates a cryptographically secure random integer in the range [min, max).
//
// Example:
// ```v
// dice_roll := rand.int_in_range(1, 7)! // 1-6
// ```
pub fn int_in_range(min int, max int) !int {
	if min >= max {
		return error('min must be less than max')
	}
	range := u32(max - min)
	random_bytes := crypto_rand.bytes(4)!
	random_u32 := u32(random_bytes[0]) | (u32(random_bytes[1]) << 8) | (u32(random_bytes[2]) << 16) | (u32(random_bytes[3]) << 24)
	return min + int(random_u32 % range)
}

// generate_key generates a cryptographic key of the specified bit length.
// Common sizes: 128, 192, 256 for AES.
//
// Example:
// ```v
// aes_key := rand.generate_key(256)! // 256-bit AES key
// ```
pub fn generate_key(bits int) ![]u8 {
	if bits <= 0 || bits % 8 != 0 {
		return error('key size must be a positive multiple of 8')
	}
	return bytes(bits / 8)!
}

// generate_iv generates an initialization vector of the specified size in bytes.
// Common sizes: 16 bytes for AES, 12 bytes for GCM.
//
// Example:
// ```v
// iv := rand.generate_iv(16)! // 16-byte IV for AES-CBC
// gcm_nonce := rand.generate_iv(12)! // 12-byte nonce for AES-GCM
// ```
pub fn generate_iv(size int) ![]u8 {
	if size <= 0 {
		return error('IV size must be positive')
	}
	return bytes(size)!
}

// read fills the provided buffer with cryptographically secure random bytes.
// This is useful when you want to reuse a buffer.
//
// Example:
// ```v
// mut buffer := []u8{len: 32}
// rand.read(mut buffer)!
// ```
pub fn read(mut buf []u8) ! {
	if buf.len == 0 {
		return
	}
	random_bytes := crypto_rand.bytes(buf.len)!
	copy(mut buf, random_bytes)
}
