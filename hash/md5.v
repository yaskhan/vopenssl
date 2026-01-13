module hash

import crypto.md5 as crypto_md5

// md5 computes the MD5 hash of data.
//
// WARNING: MD5 is cryptographically broken and should not be used for
// security-critical applications. It is provided only for compatibility
// with legacy systems.
//
// Example:
// ```v
// hash := hash.md5('Hello'.bytes())
// ```
pub fn md5(data []u8) []u8 {
	return crypto_md5.sum(data)
}

// MD5Hasher provides incremental MD5 hashing
//
// WARNING: MD5 is cryptographically broken. Use SHA-256 or BLAKE3 instead.
pub struct MD5Hasher {
mut:
	digest crypto_md5.Digest
}

// new_md5 creates a new MD5 hasher for incremental hashing.
//
// WARNING: MD5 is cryptographically broken. Use new_sha256() or new_blake3() instead.
//
// Example:
// ```v
// mut hasher := hash.new_md5()
// hasher.write('Part 1'.bytes())
// hasher.write('Part 2'.bytes())
// result := hasher.sum()
// ```
pub fn new_md5() MD5Hasher {
	return MD5Hasher{
		digest: crypto_md5.new()
	}
}

// write adds data to the hash
pub fn (mut h MD5Hasher) write(data []u8) {
	h.digest.write(data) or { panic(err) }
}

// sum returns the final hash
pub fn (mut h MD5Hasher) sum() []u8 {
	return h.digest.sum([])
}

// reset resets the hasher to its initial state
pub fn (mut h MD5Hasher) reset() {
	h.digest = crypto_md5.new()
}

// size returns the hash size in bytes (16 for MD5)
pub fn (h MD5Hasher) size() int {
	return 16
}
