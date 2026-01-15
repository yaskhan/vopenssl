module cipher

fn test_aes_gcm_nist() {
	// Test Case 4 from NIST SP 800-38D (AES-256)
	// Key: 0000000000000000000000000000000000000000000000000000000000000000
	// Nonce: 000000000000000000000000
	// PT: 00000000000000000000000000000000
	// CT: cea7403d4d606b6e074ec5d3baf39d18
	// Tag: d0d1c8a799996bf0265b98b5d48ab919
	
	key := []u8{len: 32}
	nonce := []u8{len: 12}
	plaintext := []u8{len: 16}
	aad := []u8{}
	
	expected_ct_hex := 'cea7403d4d606b6e074ec5d3baf39d18'
	expected_tag_hex := 'd0d1c8a799996bf0265b98b5d48ab919'
	
	ct, tag := gcm_encrypt_decrypt(key, nonce, plaintext, aad, true) or {
		assert false
		return
	}
	
	assert ct.hex() == expected_ct_hex
	assert tag.hex() == expected_tag_hex
	
	// Test Decryption
	dt, dtag := gcm_encrypt_decrypt(key, nonce, ct, aad, false) or {
		assert false
		return
	}
	
	assert dt.hex() == plaintext.hex()
	assert dtag.hex() == tag.hex()
}

fn test_aes_gcm_aad() {
	// Test with AAD
	key := []u8{len: 16}
	nonce := []u8{len: 12}
	plaintext := 'Hello GCM'.bytes()
	aad := 'Additional Data'.bytes()
	
	ct, tag := gcm_encrypt_decrypt(key, nonce, plaintext, aad, true)!
	
	dt, dtag := gcm_encrypt_decrypt(key, nonce, ct, aad, false)!
	
	assert dt.bytestr() == 'Hello GCM'
	assert dtag.hex() == tag.hex()
}
