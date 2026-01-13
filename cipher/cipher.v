module cipher

// CipherMode represents the mode of operation for block ciphers
pub enum CipherMode {
	cbc // Cipher Block Chaining
	ctr // Counter Mode
	gcm // Galois/Counter Mode (authenticated encryption)
	cfb // Cipher Feedback
	ofb // Output Feedback
}

// CipherType represents the type of cipher and key size
pub enum CipherType {
	aes_128 // AES with 128-bit key
	aes_192 // AES with 192-bit key
	aes_256 // AES with 256-bit key
}

// Cipher is the interface for symmetric encryption/decryption
pub interface Cipher {
	// encrypt encrypts plaintext and returns ciphertext
	encrypt(plaintext []u8) ![]u8
	// decrypt decrypts ciphertext and returns plaintext
	decrypt(ciphertext []u8) ![]u8
}

// get_key_size returns the key size in bytes for a cipher type
pub fn get_key_size(cipher_type CipherType) int {
	return match cipher_type {
		.aes_128 { 16 }
		.aes_192 { 24 }
		.aes_256 { 32 }
	}
}

// get_block_size returns the block size in bytes for a cipher type
pub fn get_block_size(cipher_type CipherType) int {
	return match cipher_type {
		.aes_128, .aes_192, .aes_256 { 16 }
	}
}

// validate_key validates that a key is the correct size for the cipher type
pub fn validate_key(key []u8, cipher_type CipherType) ! {
	expected_size := get_key_size(cipher_type)
	if key.len != expected_size {
		return error('invalid key size: expected ${expected_size} bytes, got ${key.len} bytes')
	}
}
