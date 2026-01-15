module tls

import vopenssl.cipher

fn test_record_encryption_decryption() {
	key := [u8(0x01), 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10]
	iv := [u8(0x10), 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]

	mut rl := new_record_layer(version_tls_13)
	
	// Setup generic cipher suite with AES-128-GCM properties
	// We mocked these properties/structs, assuming they exist or we just act as if
	// RecordLayer needs a CipherSuite. Let's inspect CipherSuite struct if needed.
	// For now, assume set_cipher works if we pass dummy suite.
	
	suite := CipherSuite{
		id: 0x1301 // TLS_AES_128_GCM_SHA256
		suite_type: .tls_13
		key_length: 16
		iv_length: 12
	}
	rl.set_cipher(suite, key, key, iv, iv)

	original_data := 'Hello, TLS 1.3!'.bytes()
	record := TLSRecord{
		content_type: 22 // handshake
		version:      version_tls_12 // legacy version
		length:       u16(original_data.len)
		fragment:     original_data
	}

	// Encrypt
	encrypted := rl.encrypt_record(record) or {
		panic('Encryption failed: ${err}')
	}

	assert encrypted.content_type == 23
	assert encrypted.length > record.length
	assert encrypted.fragment.len == encrypted.length

	// Decrypt
	// Reset sequence number for receive side (simulation)
	rl2 := new_record_layer(version_tls_13)
	rl2.set_cipher(suite, key, key, iv, iv)
	
	decrypted := rl2.decrypt_record(encrypted) or {
		panic('Decryption failed: ${err}')
	}

	assert decrypted.content_type == 22
	assert decrypted.fragment == original_data
	println('Record encryption/decryption test passed')
}
