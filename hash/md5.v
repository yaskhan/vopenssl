module hash

import crypto.md5 as crypto_md5

// md5 computes the MD5 hash of data.
// WARNING: MD5 is cryptographically broken.
pub fn md5(data []u8) []u8 {
	return crypto_md5.sum(data)
}
