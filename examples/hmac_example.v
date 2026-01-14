module main

import vopenssl.mac
import vopenssl.rand
import vopenssl.utils

fn main() {
	println('=== VOpenSSL HMAC Example ===\n')

	// Generate a secret key
	key := rand.bytes(32) or {
		eprintln('Error generating key: ${err}')
		return
	}
	println('Generated secret key (32 bytes): ${utils.hex(key)[..32]}...\n')

	// Message to authenticate
	message := 'This is an important message that needs authentication.'.bytes()
	println('Message: ${message.bytestr()}\n')

	// Generate HMAC using different algorithms
	println('--- HMAC Generation ---')

	hmac_sha256 := mac.hmac_sha256(key, message)
	println('HMAC-SHA256: ${utils.hex(hmac_sha256)}')

	hmac_sha512 := mac.hmac_sha512(key, message)
	println('HMAC-SHA512: ${utils.hex(hmac_sha512)}')

	// Verify HMAC
	println('\n--- HMAC Verification ---')

	is_valid := mac.verify_hmac_sha256(message, hmac_sha256, key)
	if is_valid {
		println('✓ HMAC-SHA256 verification successful')
	} else {
		println('✗ HMAC-SHA256 verification failed')
	}

	// Test with tampered message
	tampered_message := 'This is a tampered message!'.bytes()
	is_tampered_valid := mac.verify_hmac_sha256(tampered_message, hmac_sha256, key)
	if !is_tampered_valid {
		println('✓ Tampered message correctly rejected')
	} else {
		println('✗ Tampered message incorrectly accepted!')
	}

	// Practical use case: API request signing
	println('\n--- Practical Use Case: API Request Signing ---')
	api_key := 'my-secret-api-key'.bytes()
	request_data := 'POST /api/users {"name":"John","email":"john@example.com"}'.bytes()

	signature := mac.hmac_sha256(api_key, request_data)
	println('Request: ${request_data.bytestr()}')
	println('Signature: ${utils.hex(signature)}')

	// Server-side verification
	is_request_valid := mac.verify_hmac_sha256(request_data, signature, api_key)
	if is_request_valid {
		println('✓ API request signature valid - request accepted')
	} else {
		println('✗ API request signature invalid - request rejected')
	}

	println('\n=== Example Complete ===')
}
