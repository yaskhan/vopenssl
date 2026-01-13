module main

import vopenssl.hash
import vopenssl.utils
import os

fn main() {
	println('=== VOpenSSL Hash File Example ===\n')

	// Create a test file
	test_file := 'test_data.txt'
	test_content := 'Hello, VOpenSSL! This is a test file for hashing.'
	os.write_file(test_file, test_content) or {
		eprintln('Error creating test file: ${err}')
		return
	}
	defer {
		os.rm(test_file) or {}
	}

	println('File: ${test_file}')
	println('Content: ${test_content}\n')

	// Hash with different algorithms
	println('--- SHA Family ---')
	sha256_hash := hash.sha256_file(test_file) or {
		eprintln('Error hashing file with SHA-256: ${err}')
		return
	}
	println('SHA-256: ${utils.hex(sha256_hash)}')

	sha512_hash := hash.sha512_file(test_file) or {
		eprintln('Error hashing file with SHA-512: ${err}')
		return
	}
	println('SHA-512: ${utils.hex(sha512_hash)}')

	println('\n--- BLAKE Family ---')
	blake2b_hash := hash.hash_file(test_file, .blake2b_256) or {
		eprintln('Error hashing file with BLAKE2b: ${err}')
		return
	}
	println('BLAKE2b-256: ${utils.hex(blake2b_hash)}')

	blake3_hash := hash.hash_file(test_file, .blake3) or {
		eprintln('Error hashing file with BLAKE3: ${err}')
		return
	}
	println('BLAKE3: ${utils.hex(blake3_hash)}')

	// Demonstrate incremental hashing
	println('\n--- Incremental Hashing ---')
	mut hasher := hash.new_sha256()
	hasher.write('Hello, '.bytes())
	hasher.write('VOpenSSL! '.bytes())
	hasher.write('This is a test file for hashing.'.bytes())
	incremental_hash := hasher.sum()
	println('SHA-256 (incremental): ${utils.hex(incremental_hash)}')

	// Verify they match
	direct_hash := hash.sha256(test_content.bytes())
	if utils.hex(incremental_hash) == utils.hex(direct_hash) {
		println('✓ Incremental hash matches direct hash')
	} else {
		println('✗ Hash mismatch!')
	}

	// Hash verification
	println('\n--- Hash Verification ---')
	is_valid := hash.verify_hash(test_content.bytes(), sha256_hash, .sha256)
	if is_valid {
		println('✓ Hash verification successful')
	} else {
		println('✗ Hash verification failed')
	}

	println('\n=== Example Complete ===')
}
