module tls

import encoding.binary

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
	cipher_suite := rl.cipher_suite or { return TLSRecord{
		...record
	} }

	// For now, return unencrypted (encryption would use cipher module)
	// In a full implementation, this would:
	// 1. Apply MAC (for non-AEAD ciphers)
	// 2. Encrypt the fragment
	// 3. Update sequence number

	rl.sequence_number++
	return TLSRecord{
		...record
	}
}

// decrypt_record decrypts a TLS record using the active cipher suite
pub fn (mut rl RecordLayer) decrypt_record(record TLSRecord) !TLSRecord {
	cipher_suite := rl.cipher_suite or { return TLSRecord{
		...record
	} }

	// For now, return unencrypted (decryption would use cipher module)
	// In a full implementation, this would:
	// 1. Decrypt the fragment
	// 2. Verify MAC (for non-AEAD ciphers)
	// 3. Update sequence number

	rl.sequence_number++
	return TLSRecord{
		...record
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
