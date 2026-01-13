module main

import vopenssl.cipher
import vopenssl.rand
import vopenssl.utils
import os

fn main() {
	println('=== VOpenSSL File Encryption Example ===\n')

	// Create a test file
	input_file := 'plaintext.txt'
	encrypted_file := 'encrypted.bin'
	decrypted_file := 'decrypted.txt'

	test_content := 'This is a secret message that will be encrypted using AES-256-GCM!
It can contain multiple lines and special characters: @#$%^&*()
The encryption is authenticated, providing both confidentiality and integrity.'

	os.write_file(input_file, test_content) or {
		eprintln('Error creating test file: ${err}')
		return
	}

	println('Original file: ${input_file}')
	println('Content length: ${test_content.len} bytes\n')

	// Generate a random encryption key
	key := rand.generate_key(256) or {
		eprintln('Error generating key: ${err}')
		return
	}
	println('Generated 256-bit AES key: ${utils.hex(key)[..32]}...\n')

	// Encrypt the file using AES-256-GCM
	println('--- Encrypting File ---')
	cipher.encrypt_file_aes_gcm(key, input_file, encrypted_file) or {
		eprintln('Error encrypting file: ${err}')
		return
	}

	encrypted_size := os.file_size(encrypted_file)
	println('✓ File encrypted successfully')
	println('Encrypted file: ${encrypted_file}')
	println('Encrypted size: ${encrypted_size} bytes\n')

	// Decrypt the file
	println('--- Decrypting File ---')
	cipher.decrypt_file_aes_gcm(key, encrypted_file, decrypted_file) or {
		eprintln('Error decrypting file: ${err}')
		return
	}

	println('✓ File decrypted successfully')
	println('Decrypted file: ${decrypted_file}\n')

	// Verify the decrypted content matches the original
	decrypted_content := os.read_file(decrypted_file) or {
		eprintln('Error reading decrypted file: ${err}')
		return
	}

	println('--- Verification ---')
	if decrypted_content == test_content {
		println('✓ Decrypted content matches original!')
		println('Content length: ${decrypted_content.len} bytes')
	} else {
		println('✗ Decrypted content does not match!')
	}

	// Demonstrate in-memory encryption
	println('\n--- In-Memory Encryption ---')
	plaintext := 'Quick in-memory encryption test'.bytes()

	mut aes := cipher.new_aes_gcm(key) or {
		eprintln('Error creating cipher: ${err}')
		return
	}

	ciphertext := aes.encrypt(plaintext) or {
		eprintln('Error encrypting: ${err}')
		return
	}
	println('Plaintext: ${plaintext.bytestr()}')
	println('Ciphertext (hex): ${utils.hex(ciphertext)[..64]}...')
	println('Ciphertext length: ${ciphertext.len} bytes')

	decrypted := aes.decrypt(ciphertext) or {
		eprintln('Error decrypting: ${err}')
		return
	}
	println('Decrypted: ${decrypted.bytestr()}')

	if decrypted.bytestr() == plaintext.bytestr() {
		println('✓ In-memory encryption/decryption successful')
	}

	// Cleanup
	println('\n--- Cleanup ---')
	os.rm(input_file) or {}
	os.rm(encrypted_file) or {}
	os.rm(decrypted_file) or {}
	println('✓ Temporary files removed')

	println('\n=== Example Complete ===')
}
