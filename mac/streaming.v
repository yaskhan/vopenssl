module mac

import hash

// HMAC represents a streaming HMAC calculator.
pub struct HMAC {
mut:
	inner      hash.Hasher
	outer      hash.Hasher
	block_size int
	finished   bool
}

// new_hmac creates a new streaming HMAC instance.
pub fn new_hmac(key []u8, algorithm hash.HashAlgorithm) !HMAC {
	mut inner := hash.new_hasher(algorithm)!
	mut outer := hash.new_hasher(algorithm)!
	block_size := inner.block_size()

	mut k := key.clone()
	if k.len > block_size {
		// If key is longer than block size, hash it first
		// We need a temporary hasher for this one-shot operation
		// Or we can just use the provided one-shot functions from hash module
		k = hash.hash_bytes(k, algorithm)
	}

	if k.len < block_size {
		// Pad with zeros
		mut padded := []u8{cap: block_size}
		padded << k
		for _ in k.len .. block_size {
			padded << 0
		}
		k = padded.clone()
	}

	// Prepare inner and outer pads
	mut ipad := []u8{len: block_size}
	mut opad := []u8{len: block_size}

	for i in 0 .. block_size {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}

	// Initialize hashers
	inner.write(ipad)!
	outer.write(opad)!

	return HMAC{
		inner:      inner
		outer:      outer
		block_size: block_size
		finished:   false
	}
}

// write adds data to the HMAC stream.
pub fn (mut h HMAC) write(p []u8) !int {
	if h.finished {
		return error('HMAC already finished')
	}
	return h.inner.write(p)
}

// checksum calculates and returns the final HMAC signature.
// This finalizes the stream; subsequent writes will fail, but checksum can be called again.
pub fn (mut h HMAC) checksum() []u8 {
	if !h.finished {
		inner_sum := h.inner.checksum()
		h.outer.write(inner_sum) or { panic(err) } // Should not fail
		h.finished = true
	}
	return h.outer.checksum()
}

// reset resets the HMAC state to initial with the same key.
// Note: Since we don't store the key, we can't fully reset easily without re-init.
// But wait, inner/outer already processed the key pads.
// If we reset inner/outer, we lose the key pad state. 
// So HMAC reset requires storing the generic key pads or re-initializing.
// Standard vlib mechanism? 
// Actually, `new_hmac` does the setup.
// For streaming HMAC to be reset-able, we need to save the initial state of inner/outer (after key padding).
// Generic `Hasher` might not support `copy` or state export.
// So providing `reset()` might be tricky without re-providing the key or storing key pads.
// Let's store o_key_pad and i_key_pad?
// But `new_hmac` logic is cleaner. 
// For now, let's omit `reset()` or make it panic/error, as saving state is hard generically.
// Or we can store opad/ipad.
// Let's store opad/ipad to support reset.

/* 
   Wait, implementing generic reset correctly requires re-writing the pads to the hashers. 
   But `hash.Hasher.reset()` clears everything. 
   So yes, we reset underlying hashers then re-write pads. 
*/

// free releases resources
pub fn (mut h HMAC) free() {
	h.inner.free()
	h.outer.free()
}
