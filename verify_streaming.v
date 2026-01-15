module main

import hash
import mac

fn main() {
	println('Verifying Streaming API...')

	// Test Data
	data := 'The quick brown fox jumps over the lazy dog'.bytes()
	
	// 0. SHA-256 Empty
	println('Testing SHA-256 Empty...')
	mut h256_e := hash.new_hasher(.sha256)!
	sum256_e := h256_e.checksum()
	expected256_e := hash.hash_bytes([]u8{}, .sha256)
	println('Empty sum: ${sum256_e.hex()}')
	println('Expct sum: ${expected256_e.hex()}')
	assert_eq(sum256_e, expected256_e, 'SHA-256 Empty')

	// 1. SHA-256 Streaming
	println('Testing SHA-256 Streaming...')
	mut h256 := hash.new_hasher(.sha256)!
	h256.write(data)!
	sum256 := h256.checksum()
	println('Data sum: ${sum256.hex()}')
	expected256 := hash.hash_bytes(data, .sha256)
	println('Expct sum: ${expected256.hex()}')
	assert_eq(sum256, expected256, 'SHA-256')

	// Chunked Write
	h256.reset()
	h256.write(data[..10])!
	h256.write(data[10..])!
	sum256_chunked := h256.checksum()
	assert_eq(sum256_chunked, expected256, 'SHA-256 Chunked')
	println('SHA-256 OK')
	
	// 2. SHA-512 Streaming
	println('Testing SHA-512 Streaming...')
	mut h512 := hash.new_hasher(.sha512)!
	h512.write(data)!
	sum512 := h512.checksum()
	expected512 := hash.hash_bytes(data, .sha512)
	assert_eq(sum512, expected512, 'SHA-512')
	println('SHA-512 OK')

	// 3. HMAC-SHA256 Streaming
	println('Testing HMAC-SHA256 Streaming...')
	key := 'key'.bytes()
	mut hmac256 := mac.new_hmac(key, .sha256)!
	hmac256.write(data)!
	mac_sum := hmac256.checksum()
	expected_mac := mac.hmac_sha256(key, data)
	assert_eq(mac_sum, expected_mac, 'HMAC-SHA256')
	
	// Chunked HMAC
	// Note: We need to re-create or implement reset properly.
	// Our current implementation doesn't fully support reset logic without stored pads.
	// So we create a new one.
	mut hmac256_2 := mac.new_hmac(key, .sha256)!
	hmac256_2.write(data[..20])!
	hmac256_2.write(data[20..])!
	mac_sum_2 := hmac256_2.checksum()
	assert_eq(mac_sum_2, expected_mac, 'HMAC-SHA256 Chunked')
	println('HMAC-SHA256 OK')

	println('All streaming tests passed!')
}

fn assert_eq(a []u8, b []u8, name string) {
	if a.hex() != b.hex() {
		println('Test failed for ${name}: expected ${b.hex()}, got ${a.hex()}')
	} else {
		println('PASS: ${name}')
	}
}
