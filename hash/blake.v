module hash

import crypto.blake2b as crypto_blake2b
import crypto.blake2s as crypto_blake2s
import crypto.blake3 as crypto_blake3

// blake2b computes the BLAKE2b hash of data with the specified output size.
// size must be between 1 and 64 bytes.
//
// Example:
// ```v
// hash := hash.blake2b('Hello'.bytes(), 32)! // 256-bit hash
// ```
pub fn blake2b(data []u8, size int) ![]u8 {
	if size < 1 || size > 64 {
		return error('BLAKE2b size must be between 1 and 64 bytes')
	}
	mut hasher := crypto_blake2b.new(size: size)!
	hasher.write(data)!
	return hasher.checksum()
}

// blake2b_256 computes the BLAKE2b-256 hash of data (32 bytes output).
//
// Example:
// ```v
// hash := hash.blake2b_256('Hello'.bytes())!
// ```
pub fn blake2b_256(data []u8) ![]u8 {
	return blake2b(data, 32)
}

// blake2b_512 computes the BLAKE2b-512 hash of data (64 bytes output).
//
// Example:
// ```v
// hash := hash.blake2b_512('Hello'.bytes())!
// ```
pub fn blake2b_512(data []u8) ![]u8 {
	return blake2b(data, 64)
}

// blake2s computes the BLAKE2s hash of data with the specified output size.
// size must be between 1 and 32 bytes.
//
// Example:
// ```v
// hash := hash.blake2s('Hello'.bytes(), 32)! // 256-bit hash
// ```
pub fn blake2s(data []u8, size int) ![]u8 {
	if size < 1 || size > 32 {
		return error('BLAKE2s size must be between 1 and 32 bytes')
	}
	mut hasher := crypto_blake2s.new(size: size)!
	hasher.write(data)!
	return hasher.checksum()
}

// blake2s_256 computes the BLAKE2s-256 hash of data (32 bytes output).
//
// Example:
// ```v
// hash := hash.blake2s_256('Hello'.bytes())!
// ```
pub fn blake2s_256(data []u8) ![]u8 {
	return blake2s(data, 32)
}

// blake3 computes the BLAKE3 hash of data.
//
// Example:
// ```v
// hash := hash.blake3('Hello'.bytes())
// ```
pub fn blake3(data []u8) []u8 {
	mut hasher := crypto_blake3.new()
	hasher.write(data) or { panic(err) }
	return hasher.sum([])
}

// BLAKE2bHasher provides incremental BLAKE2b hashing
pub struct BLAKE2bHasher {
mut:
	hasher      crypto_blake2b.Digest
	output_size int
}

// new_blake2b creates a new BLAKE2b hasher for incremental hashing.
//
// Example:
// ```v
// mut hasher := hash.new_blake2b(32)! // 256-bit output
// hasher.write('Part 1'.bytes())
// hasher.write('Part 2'.bytes())
// result := hasher.sum()
// ```
pub fn new_blake2b(size int) !BLAKE2bHasher {
	if size < 1 || size > 64 {
		return error('BLAKE2b size must be between 1 and 64 bytes')
	}
	return BLAKE2bHasher{
		hasher:      crypto_blake2b.new(size: size)!
		output_size: size
	}
}

// write adds data to the hash
pub fn (mut h BLAKE2bHasher) write(data []u8) {
	h.hasher.write(data) or { panic(err) }
}

// sum returns the final hash
pub fn (mut h BLAKE2bHasher) sum() []u8 {
	return h.hasher.checksum()
}

// reset resets the hasher to its initial state
pub fn (mut h BLAKE2bHasher) reset() {
	h.hasher = crypto_blake2b.new(size: h.output_size) or { panic(err) }
}

// size returns the hash size in bytes
pub fn (h BLAKE2bHasher) size() int {
	return h.output_size
}

// BLAKE3Hasher provides incremental BLAKE3 hashing
pub struct BLAKE3Hasher {
mut:
	hasher crypto_blake3.Hasher
}

// new_blake3 creates a new BLAKE3 hasher for incremental hashing.
//
// Example:
// ```v
// mut hasher := hash.new_blake3()
// hasher.write('Part 1'.bytes())
// hasher.write('Part 2'.bytes())
// result := hasher.sum()
// ```
pub fn new_blake3() BLAKE3Hasher {
	return BLAKE3Hasher{
		hasher: crypto_blake3.new()
	}
}

// write adds data to the hash
pub fn (mut h BLAKE3Hasher) write(data []u8) {
	h.hasher.write(data) or { panic(err) }
}

// sum returns the final hash
pub fn (mut h BLAKE3Hasher) sum() []u8 {
	return h.hasher.sum([])
}

// reset resets the hasher to its initial state
pub fn (mut h BLAKE3Hasher) reset() {
	h.hasher = crypto_blake3.new()
}

// size returns the hash size in bytes (32 for BLAKE3)
pub fn (h BLAKE3Hasher) size() int {
	return 32
}
