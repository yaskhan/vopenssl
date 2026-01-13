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
	
	test_content := 'This is a secret message that will be encrypted using AES-256-CBC!
It can contain multiple lines and special characters: @#$%^&*()'
	
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
	
	// Encrypt the file using AES-256-CBC
	println('--- Encrypting File ---')
	mut aes := cipher.new_aes_cbc(key) or {
		eprintln('Error creating cipher: ${err}')
		return
	}
	
	aes.encrypt_file(input_file, encrypted_file) or {
		eprintln('Error encrypting file: ${err}')
		return
	}
	
	encrypted_size := os.file_size(encrypted_file)
	println('✓ File encrypted successfully')
	println('Encrypted file: ${encrypted_file}')
	println('Encrypted size: ${encrypted_size} bytes\n')
	
	// Decrypt the file
	println('--- Decrypting File ---')
	// Need to recreate cipher or reset? new_aes_cbc generates new IV.
	// We need to read the IV from the file for decryption?
	// Our encrypt_file implementation PREPENDS the IV.
	// And decrypt_file implementation EXTRACTS the IV.
	// So we can just create a new cipher instance with the same key.
	// Note: new_aes_cbc generates a random IV, but decrypt() reads IV from ciphertext, so initial IV doesn't matter for decryption.
	
	mut dec_aes := cipher.new_aes_cbc(key) or {
		eprintln('Error creating decrypt cipher: ${err}')
		return
	}
	
	dec_aes.decrypt_file(encrypted_file, decrypted_file) or {
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
	
	// Cleanup
	println('\n--- Cleanup ---')
	os.rm(input_file) or {}
	os.rm(encrypted_file) or {}
	os.rm(decrypted_file) or {}
	println('✓ Temporary files removed')
	
	println('\n=== Example Complete ===')
}
