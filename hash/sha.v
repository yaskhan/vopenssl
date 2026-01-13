module hash

import crypto.sha1 as crypto_sha1
import crypto.sha256 as crypto_sha256
import crypto.sha512 as crypto_sha512

// sha1 computes the SHA-1 hash of data.
// Note: SHA-1 is deprecated for security-critical applications.
//
// Example:
// ```v
// hash := hash.sha1('Hello'.bytes())
// ```
pub fn sha1(data []u8) []u8 {
	return crypto_sha1.sum(data)
}

// sha256 computes the SHA-256 hash of data.
//
// Example:
// ```v
// hash := hash.sha256('Hello'.bytes())
// println('SHA-256: ${hash.hex()}')
// ```
pub fn sha256(data []u8) []u8 {
	return crypto_sha256.sum256(data)
}

// sha224 computes the SHA-224 hash of data.
//
// Example:
// ```v
// hash := hash.sha224('Hello'.bytes())
// ```
pub fn sha224(data []u8) []u8 {
	return crypto_sha256.sum224(data)
}

// sha512 computes the SHA-512 hash of data.
//
// Example:
// ```v
// hash := hash.sha512('Hello'.bytes())
// ```
pub fn sha512(data []u8) []u8 {
	return crypto_sha512.sum512(data)
}

// sha384 computes the SHA-384 hash of data.
//
// Example:
// ```v
// hash := hash.sha384('Hello'.bytes())
// ```
pub fn sha384(data []u8) []u8 {
	return crypto_sha512.sum384(data)
}

// SHA256Hasher provides incremental SHA-256 hashing
pub struct SHA256Hasher {
mut:
	digest crypto_sha256.Digest
}

// new_sha256 creates a new SHA-256 hasher for incremental hashing.
//
// Example:
// ```v
// mut hasher := hash.new_sha256()
// hasher.write('Part 1'.bytes())
// hasher.write('Part 2'.bytes())
// result := hasher.sum()
// ```
pub fn new_sha256() SHA256Hasher {
	return SHA256Hasher{
		digest: crypto_sha256.new()
	}
}

// write adds data to the hash
pub fn (mut h SHA256Hasher) write(data []u8) {
	h.digest.write(data) or { panic(err) }
}

// sum returns the final hash
pub fn (mut h SHA256Hasher) sum() []u8 {
	return h.digest.sum([])
}

// reset resets the hasher to its initial state
pub fn (mut h SHA256Hasher) reset() {
	h.digest = crypto_sha256.new()
}

// size returns the hash size in bytes (32 for SHA-256)
pub fn (h SHA256Hasher) size() int {
	return 32
}

// SHA512Hasher provides incremental SHA-512 hashing
pub struct SHA512Hasher {
mut:
	digest crypto_sha512.Digest
}

// new_sha512 creates a new SHA-512 hasher for incremental hashing.
//
// Example:
// ```v
// mut hasher := hash.new_sha512()
// hasher.write('Part 1'.bytes())
// hasher.write('Part 2'.bytes())
// result := hasher.sum()
// ```
pub fn new_sha512() SHA512Hasher {
	return SHA512Hasher{
		digest: crypto_sha512.new()
	}
}

// write adds data to the hash
pub fn (mut h SHA512Hasher) write(data []u8) {
	h.digest.write(data) or { panic(err) }
}

// sum returns the final hash
pub fn (mut h SHA512Hasher) sum() []u8 {
	return h.digest.sum([])
}

// reset resets the hasher to its initial state
pub fn (mut h SHA512Hasher) reset() {
	h.digest = crypto_sha512.new()
}

// size returns the hash size in bytes (64 for SHA-512)
pub fn (h SHA512Hasher) size() int {
	return 64
}

// sha256_file computes the SHA-256 hash of a file.
//
// Example:
// ```v
// hash := hash.sha256_file('document.pdf')!
// ```
pub fn sha256_file(path string) ![]u8 {
	return hash_file(path, .sha256)
}

// sha512_file computes the SHA-512 hash of a file.
//
// Example:
// ```v
// hash := hash.sha512_file('document.pdf')!
// ```
pub fn sha512_file(path string) ![]u8 {
	return hash_file(path, .sha512)
}
