module cipher

import encoding.binary

// ChaCha20 state
// ChaCha20 state represents the internal state of the ChaCha20 cipher.
// It consists of 16 32-bit words.
struct ChaCha20 {
mut:
	state [16]u32
}

// new_chacha20 creates a new ChaCha20 instance with the given key and nonce.
// Key must be 32 bytes (256 bits). Nonce must be 12 bytes (96 bits).
pub fn new_chacha20(key []u8, nonce []u8) !ChaCha20 {
	if key.len != 32 {
		return error('invalid ChaCha20 key length: ${key.len}, expected 32')
	}
	if nonce.len != 12 {
		return error('invalid ChaCha20 nonce length: ${nonce.len}, expected 12')
	}

	mut c := ChaCha20{}
	
	// Constant "expand 32-byte k"
	c.state[0] = 0x61707865
	c.state[1] = 0x3320646e
	c.state[2] = 0x79622d32
	c.state[3] = 0x6b206574
	
	// Key
	for i in 0 .. 8 {
		c.state[4 + i] = binary.little_endian_u32(key[i * 4..(i + 1) * 4])
	}
	
	// Counter (start at 1 usually for TLS, but state init starts at 0 or whatever caller sets, usually 0)
	// RFC 8439: Block Counter is 32-bit at state[12]
	c.state[12] = 0
	
	// Nonce
	for i in 0 .. 3 {
		c.state[13 + i] = binary.little_endian_u32(nonce[i * 4..(i + 1) * 4])
	}
	
	return c
}

// set_counter sets the initial block counter.
// The default is usually 0, but can be set to start at a different offset.
pub fn (mut c ChaCha20) set_counter(counter u32) {
	c.state[12] = counter
}

// encrypt_decrypt encrypts or decrypts the input byte slice.
// Since ChaCha20 is a stream cipher, encryption and decryption are identical operations (XOR).
// The internal state is updated as data is processed.
pub fn (mut c ChaCha20) encrypt_decrypt(input []u8) []u8 {
	mut output := []u8{len: input.len}
	mut block := [64]u8{}
	mut block_pos := 64 // Force generation on first byte
	
	for i in 0 .. input.len {
		if block_pos == 64 {
			c.generate_block(mut block)
			block_pos = 0
		}
		output[i] = input[i] ^ block[block_pos]
		block_pos++
	}
	
	return output
}

// xor_key_stream acts as an alias for encrypt_decrypt but writes the output to dst.
// src and dst must have the same length and can overlap.
pub fn (mut c ChaCha20) xor_key_stream(mut dst []u8, src []u8) {
	encrypted := c.encrypt_decrypt(src)
	for i in 0 .. src.len {
		dst[i] = encrypted[i]
	}
}

// generate_block generates 64 bytes of keystream and increments counter
// generate_block generates 64 bytes of keystream and increments counter
fn (mut c ChaCha20) generate_block(mut block [64]u8) {
	// Manual clone
	mut x := []u32{len: 16}
	for i in 0 .. 16 {
		x[i] = c.state[i]
	}
	
	for _ in 0 .. 10 { // 20 rounds (10 iterations of 2 rounds)
		quarter_round(mut x, 0, 4, 8, 12)
		quarter_round(mut x, 1, 5, 9, 13)
		quarter_round(mut x, 2, 6, 10, 14)
		quarter_round(mut x, 3, 7, 11, 15)
		
		quarter_round(mut x, 0, 5, 10, 15)
		quarter_round(mut x, 1, 6, 11, 12)
		quarter_round(mut x, 2, 7, 8, 13)
		quarter_round(mut x, 3, 4, 9, 14)
	}
	
	for i in 0 .. 16 {
		val := x[i] + c.state[i]
		binary.little_endian_put_u32(mut block[i * 4..], val)
	}
	
	// Increment counter
	c.state[12]++
}

fn quarter_round(mut x []u32, a int, b int, c int, d int) {
	x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 16)
	x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 12)
	x[a] += x[b]; x[d] = rotl(x[d] ^ x[a], 8)
	x[c] += x[d]; x[b] = rotl(x[b] ^ x[c], 7)
}

fn rotl(v u32, n int) u32 {
	return (v << n) | (v >> (32 - n))
}
