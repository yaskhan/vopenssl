module tls

import encoding.binary
import vopenssl.cipher

pub struct TLSRecord {
pub:
	content_type u8
	version      u16
	length       u16
	fragment     []u8
}

pub struct RecordLayer {
mut:
	sequence_number u64
	cipher_suite    ?CipherSuite
	read_key        []u8
	write_key       []u8
	read_iv         []u8
	write_iv        []u8
	version         u16
}

pub fn new_record_layer(version u16) RecordLayer {
	return RecordLayer{
		sequence_number: 0
		version:         version
	}
}

// read_record reads a single TLS record from the given data
pub fn read_record(data []u8) !TLSRecord {
	if data.len < 5 {
		return error('TLS record too short: expected at least 5 bytes, got ${data.len}')
	}

	content_type := data[0]
	version := binary.big_endian_u16(data[1..3])
	length := binary.big_endian_u16(data[3..5])

	if data.len < 5 + int(length) {
		return error('TLS record fragment truncated: expected ${length} bytes, got ${data.len - 5}')
	}

	if length > max_ciphertext_length {
		return error('TLS record too large: ${length} bytes (max ${max_ciphertext_length})')
	}

	fragment := data[5..5 + int(length)].clone()

	return TLSRecord{
		content_type: content_type
		version:      version
		length:       length
		fragment:     fragment
	}
}

// write_record serializes a TLS record to bytes
pub fn write_record(record TLSRecord) []u8 {
	mut result := []u8{len: 5 + record.fragment.len}

	result[0] = record.content_type
	binary.big_endian_put_u16(mut result[1..3], record.version)
	binary.big_endian_put_u16(mut result[3..5], record.length)

	for i, b in record.fragment {
		result[5 + i] = b
	}

	return result
}

// create_record creates a new TLS record
pub fn create_record(content_type u8, version u16, fragment []u8) !TLSRecord {
	if fragment.len > max_plaintext_length {
		return error('fragment too large: ${fragment.len} bytes (max ${max_plaintext_length})')
	}

	return TLSRecord{
		content_type: content_type
		version:      version
		length:       u16(fragment.len)
		fragment:     fragment.clone()
	}
}

// split_into_records splits data into multiple TLS records if necessary
pub fn split_into_records(content_type u8, version u16, data []u8) []TLSRecord {
	mut records := []TLSRecord{}
	mut offset := 0

	for offset < data.len {
		remaining := data.len - offset
		fragment_len := if remaining > max_plaintext_length {
			max_plaintext_length
		} else {
			remaining
		}

		fragment := data[offset..offset + fragment_len].clone()
		records << TLSRecord{
			content_type: content_type
			version:      version
			length:       u16(fragment_len)
			fragment:     fragment
		}

		offset += fragment_len
	}

	return records
}

// encrypt_record encrypts a TLS record using the active cipher suite
pub fn (mut rl RecordLayer) encrypt_record(record TLSRecord) !TLSRecord {
	if rl.cipher_suite == none {
		return TLSRecord{
			...record
		}
	}

	// Calculate nonce: IV XOR Sequence Number (padded)
	mut nonce := rl.write_iv.clone()
	for i := 0; i < 8; i++ {
		nonce[nonce.len - 1 - i] ^= u8(rl.sequence_number >> (i * 8))
	}

	// Construct AAD
	// TLS 1.3: opaque_type + legacy_record_version + length
	// We assume TLS 1.3 for now as per context
	mut aad := []u8{len: 5}
	aad[0] = 23 // opaque_type (application_data)
	binary.big_endian_put_u16(mut aad[1..3], record.version)
	
	// Payload includes content type byte for TLS 1.3 inner plaintext
	// And tag expansion
	plaintext_len := record.fragment.len + 1 // + inner content type
	tag_len := 16 // GCM tag length
	encrypted_len := plaintext_len + tag_len
	binary.big_endian_put_u16(mut aad[3..5], u16(encrypted_len))

	// Construct plaintext (TLS 1.3 InnerPlaintext)
	mut plaintext := record.fragment.clone()
	plaintext << record.content_type // Inner content type
	
	// Encrypt
	ciphertext, tag := match rl.cipher_suite?.bulk_cipher {
		.chacha20_poly1305 {
			// ChaCha20-Poly1305 returns Ciphertext || Tag directly
			result := cipher.aead_chacha20_poly1305_encrypt(rl.write_key, nonce, aad, plaintext)!
			// Split for consistency with GCM logic below (or just adapt logic)
			result[..result.len - 16], result[result.len - 16..]
		}
		else {
			// Default to GCM (AES-128-GCM or AES-256-GCM)
			cipher.gcm_encrypt_decrypt(rl.write_key, nonce, plaintext, aad, true)!
		}
	}
	
	mut full_ciphertext := ciphertext.clone()
	full_ciphertext << tag

	rl.sequence_number++

	// TLS 1.3 records look like Application Data (23) externally
	return TLSRecord{
		content_type: 23 // application_data
		version:      record.version // wrapper version (usually 0x0303)
		length:       u16(full_ciphertext.len)
		fragment:     full_ciphertext
	}
}

// decrypt_record decrypts a TLS record using the active cipher suite
pub fn (mut rl RecordLayer) decrypt_record(record TLSRecord) !TLSRecord {
	if rl.cipher_suite == none {
		return TLSRecord{
			...record
		}
	}

	// Calculate nonce
	mut nonce := rl.read_iv.clone()
	for i := 0; i < 8; i++ {
		nonce[nonce.len - 1 - i] ^= u8(rl.sequence_number >> (i * 8))
	}

	// Construct AAD
	mut aad := []u8{len: 5}
	aad[0] = record.content_type
	binary.big_endian_put_u16(mut aad[1..3], record.version)
	binary.big_endian_put_u16(mut aad[3..5], record.length)

	if record.fragment.len < 16 {
		return error('record too short for authentication tag')
	}

	// Split tag
	tag := record.fragment[record.fragment.len - 16..]
	ciphertext := record.fragment[..record.fragment.len - 16]

	// Decrypt
	plaintext, calculated_tag := match rl.cipher_suite?.bulk_cipher {
		.chacha20_poly1305 {
			// ChaCha20-Poly1305 decrypt returns plaintext and verifies tag internally
			combined := record.fragment.clone() // already has tag at end
			pt := cipher.aead_chacha20_poly1305_decrypt(rl.read_key, nonce, aad, combined)!
			// Return plaintext and the tag extracted from input (for consistency with GCM flow)
			pt, tag
		}
		else {
			// Default to GCM
			cipher.gcm_encrypt_decrypt(rl.read_key, nonce, ciphertext, aad, false)!
		}
	}

	// Verify tag (GCM does it here manually, ChaCha already did it but we simulate match for flow consistency or refactor)
	if rl.cipher_suite?.bulk_cipher != .chacha20_poly1305 {
		mut match_found := true
		for i in 0 .. 16 {
			if tag[i] != calculated_tag[i] {
				match_found = false
				break
			}
		}
		if !match_found {
			return error('bad_record_mac')
		}
	}

	// Remove padding and extract inner content type (TLS 1.3)
	// Scan from end for non-zero byte
	mut i := plaintext.len - 1
	for i >= 0 && plaintext[i] == 0 {
		i--
	}
	if i < 0 {
		return error('unexpected_message: zero-length fragment')
	}
	content_type := plaintext[i]
	fragment := plaintext[..i]

	rl.sequence_number++

	return TLSRecord{
		content_type: content_type
		version:      record.version
		length:       u16(fragment.len)
		fragment:     fragment
	}
}

// set_cipher sets the cipher suite and keys for the record layer
pub fn (mut rl RecordLayer) set_cipher(cipher_suite CipherSuite, read_key []u8, write_key []u8, read_iv []u8, write_iv []u8) {
	rl.cipher_suite = cipher_suite
	rl.read_key = read_key.clone()
	rl.write_key = write_key.clone()
	rl.read_iv = read_iv.clone()
	rl.write_iv = write_iv.clone()
	rl.sequence_number = 0
}

// reset_sequence_number resets the sequence number (used for key updates)
pub fn (mut rl RecordLayer) reset_sequence_number() {
	rl.sequence_number = 0
}
