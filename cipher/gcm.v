module cipher

import crypto.aes as crypto_aes // still needed for types if shared, but we will use our AES

// gcm_encrypt_decrypt performs AES-GCM encryption or decryption.
// key: AES key (16, 24, or 32 bytes)
// nonce: GCM nonce (recommended 12 bytes)
// data: Plaintext (for encryption) or Ciphertext (for decryption)
// aad: Additional Authenticated Data (optional, verified but not encrypted)
// encrypt: true for encryption, false for decryption
// Returns (ciphertext, tag) for encryption, or (plaintext, tag) for decryption.
// Note: When decrypting, the caller must verify the returned tag against the expected tag.
pub fn gcm_encrypt_decrypt(key []u8, nonce []u8, data []u8, aad []u8, encrypt bool) !([]u8, []u8) {
	if nonce.len != 12 {
		return error('GCM nonce must be 12 bytes')
	}

	aes_cipher := crypto_aes.new_cipher(key)
	
	// 1. Hash Subkey
	mut h := []u8{len: 16}
	aes_cipher.encrypt(mut h, []u8{len: 16})
	
	// 2. Pre-counter block J_0
	mut j0 := []u8{len: 16}
	copy(mut j0, nonce)
	j0[15] = 1
	
	// 4. CTR encryption
	mut cb := inc32(j0)
	mut ciphertext := []u8{len: data.len}
	
	for i := 0; i < data.len; i += 16 {
		mut keystream := []u8{len: 16}
		aes_cipher.encrypt(mut keystream, cb)
		cb = inc32(cb)
		
		limit := if i + 16 > data.len { data.len } else { i + 16 }
		for j in i .. limit {
			ciphertext[j] = data[j] ^ keystream[j - i]
		}
	}
	
	// 5. Authentication tag
	mut ghash_input := []u8{}
	
	// Pad AAD
	ghash_input << aad
	if aad.len % 16 != 0 {
		ghash_input << []u8{len: 16 - (aad.len % 16)}
	}
	
	// Pad ciphertext
	c_to_hash := if encrypt { ciphertext } else { data }
	ghash_input << c_to_hash
	if c_to_hash.len % 16 != 0 {
		ghash_input << []u8{len: 16 - (c_to_hash.len % 16)}
	}
	
	// Add lengths (in bits)
	mut len_block := []u8{len: 16}
	aad_bits := u64(aad.len) * 8
	data_bits := u64(c_to_hash.len) * 8
	
	for i in 0 .. 8 {
		len_block[7 - i] = u8(aad_bits >> (i * 8))
		len_block[15 - i] = u8(data_bits >> (i * 8))
	}
	ghash_input << len_block
	
	s := ghash(h, ghash_input)
	
	// Mask tag with J_0 encryption
	mut tag_mask := []u8{len: 16}
	aes_cipher.encrypt(mut tag_mask, j0)
	mut tag := []u8{len: 16}
	for i in 0 .. 16 {
		tag[i] = s[i] ^ tag_mask[i]
	}
	
	return ciphertext, tag
}

fn inc32(counter []u8) []u8 {
	mut c := counter.clone()
	mut ctr := c[c.len-4..].clone()
	// Increment last 4 bytes as big endian integer
	// We can interpret as u32, add 1, write back.
	// Or simple byte loop logic.
	for i := 3; i >= 0; i-- {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
	}
	for i in 0 .. 4 {
		c[c.len-4+i] = ctr[i]
	}
	return c
}
