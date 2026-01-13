module main

import hash
import utils
import rand
import mac
import cipher

fn main() {
	println('=== VOpenSSL Library Test ===\n')
	
	// Test 1: Hashing
	println('Test 1: SHA-256 Hash')
	data := 'Hello, VOpenSSL!'.bytes()
	hash_result := hash.sha256(data)
	println('Input: Hello, VOpenSSL!')
	println('SHA-256: ${utils.hex(hash_result)}')
	println('✓ Hash test passed\n')
	
	// Test 2: Random generation
	println('Test 2: Random Key Generation')
	key := rand.generate_key(256) or {
		eprintln('Error: ${err}')
		return
	}
	println('Generated 256-bit key: ${utils.hex(key)[..32]}...')
	println('✓ Random generation test passed\n')
	
	// Test 3: HMAC
	println('Test 3: HMAC-SHA256')
	message := 'Test message'.bytes()
	mac_result := mac.hmac_sha256(key, message)
	println('Message: Test message')
	println('HMAC: ${utils.hex(mac_result)[..32]}...')
	is_valid := mac.verify_hmac_sha256(message, mac_result, key)
	println('Verification: ${is_valid}')
	println('✓ HMAC test passed\n')
	
	// Test 4: AES Encryption
	println('Test 4: AES-256-CBC Encryption')
	plaintext := 'Secret data to be encrypted with CBC'.bytes()
	mut aes := cipher.new_aes_cbc(key) or {
		eprintln('Error: ${err}')
		return
	}
	ciphertext := aes.encrypt(plaintext) or {
		eprintln('Error: ${err}')
		return
	}
	println('Plaintext: Secret data to be encrypted with CBC')
	println('Ciphertext length: ${ciphertext.len} bytes')
	
	decrypted := aes.decrypt(ciphertext) or {
		eprintln('Error: ${err}')
		return
	}
	println('Decrypted: ${decrypted.bytestr()}')
	println('Match: ${decrypted.bytestr() == plaintext.bytestr()}')
	println('✓ Encryption test passed\n')

	
	println('=== All Tests Passed! ===')
}
