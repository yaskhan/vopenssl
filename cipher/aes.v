module cipher

import crypto.aes
import crypto.cipher as crypto_cipher
import os
import rand
import utils


// AESCipher provides AES encryption/decryption with various modes
pub struct AESCipher {
	mode CipherMode
	key  []u8
mut:
	iv []u8
}

// new_aes_cipher creates a new AES cipher with the specified key and mode.
// The key size determines the AES variant (128, 192, or 256 bits).
//
// Example:
// ```v
// key := rand.generate_key(256)! // 32 bytes for AES-256
// mut cipher := cipher.new_aes_cipher(key, .gcm)!
// ```
pub fn new_aes_cipher(key []u8, mode CipherMode) !AESCipher {
	if key.len != 16 && key.len != 24 && key.len != 32 {
		return error('invalid AES key size: must be 16, 24, or 32 bytes')
	}

	// Generate a random IV
	iv_size := match mode {
		.gcm { 12 } // GCM uses 12-byte nonce
		else { 16 } // Other modes use 16-byte IV
	}
	iv := rand.generate_iv(iv_size)!

	return AESCipher{
		mode: mode
		key:  key
		iv:   iv
	}
}

// new_aes_gcm creates a new AES-GCM cipher (authenticated encryption).
//
// Example:
// ```v
// key := rand.generate_key(256)!
// mut cipher := cipher.new_aes_gcm(key)!
// ciphertext := cipher.encrypt(plaintext)!
// ```
pub fn new_aes_gcm(key []u8) !AESCipher {
	return new_aes_cipher(key, .gcm)
}

// new_aes_cbc creates a new AES-CBC cipher.
//
// Example:
// ```v
// key := rand.generate_key(256)!
// mut cipher := cipher.new_aes_cbc(key)!
// ```
pub fn new_aes_cbc(key []u8) !AESCipher {
	return new_aes_cipher(key, .cbc)
}

// new_aes_ctr creates a new AES-CTR cipher.
//
// Example:
// ```v
// key := rand.generate_key(256)!
// mut cipher := cipher.new_aes_ctr(key)!
// ```
pub fn new_aes_ctr(key []u8) !AESCipher {
	return new_aes_cipher(key, .ctr)
}

// encrypt encrypts plaintext using AES.
// For GCM mode, the IV/nonce is prepended to the ciphertext.
//
// Example:
// ```v
// ciphertext := cipher.encrypt('Secret message'.bytes())!
// ```
pub fn (mut c AESCipher) encrypt(plaintext []u8) ![]u8 {
	match c.mode {
		.gcm {
			return c.encrypt_gcm(plaintext)
		}
		.cbc {
			return c.encrypt_cbc(plaintext)
		}
		.ctr {
			return c.encrypt_ctr(plaintext)
		}
		else {
			return error('cipher mode not implemented: ${c.mode}')
		}
	}
}

// decrypt decrypts ciphertext using AES.
// For GCM mode, the IV/nonce is expected to be prepended to the ciphertext.
//
// Example:
// ```v
// plaintext := cipher.decrypt(ciphertext)!
// ```
pub fn (mut c AESCipher) decrypt(ciphertext []u8) ![]u8 {
	match c.mode {
		.gcm {
			return c.decrypt_gcm(ciphertext)
		}
		.cbc {
			return c.decrypt_cbc(ciphertext)
		}
		.ctr {
			return c.decrypt_ctr(ciphertext)
		}
		else {
			return error('cipher mode not implemented: ${c.mode}')
		}
	}
}

// encrypt_gcm encrypts using AES-GCM (authenticated encryption)
fn (mut c AESCipher) encrypt_gcm(plaintext []u8) ![]u8 {
	block := aes.new_cipher(c.key)
	gcm := crypto_cipher.new_gcm(block)!

	// Prepend nonce to ciphertext
	mut result := []u8{len: c.iv.len + plaintext.len + 16} // nonce + ciphertext + tag
	copy(mut result, c.iv)

	sealed := gcm.seal(c.iv, plaintext)
	copy(mut result[c.iv.len..], sealed)

	// Generate new IV for next encryption
	c.iv = rand.generate_iv(12)!

	return result
}

// decrypt_gcm decrypts using AES-GCM (authenticated encryption)
fn (mut c AESCipher) decrypt_gcm(ciphertext []u8) ![]u8 {
	if ciphertext.len < 12 + 16 {
		return error('ciphertext too short for GCM')
	}

	// Extract nonce from ciphertext
	nonce := ciphertext[..12]
	encrypted := ciphertext[12..]

	block := aes.new_cipher(c.key)
	gcm := crypto_cipher.new_gcm(block)!

	plaintext := gcm.open(nonce, encrypted)!
	return plaintext
}

// encrypt_cbc encrypts using AES-CBC
fn (mut c AESCipher) encrypt_cbc(plaintext []u8) ![]u8 {
	// Apply PKCS#7 padding
	padded := utils.pkcs7_pad(plaintext, 16)

	block := aes.new_cipher(c.key)
	mode := crypto_cipher.new_cbc(block, c.iv)

	mut ciphertext := []u8{len: c.iv.len + padded.len}
	copy(mut ciphertext, c.iv)

	mode.encrypt_blocks(mut ciphertext[c.iv.len..], padded)

	// Generate new IV for next encryption
	c.iv = rand.generate_iv(16)!

	return ciphertext
}

// decrypt_cbc decrypts using AES-CBC
fn (mut c AESCipher) decrypt_cbc(ciphertext []u8) ![]u8 {
	if ciphertext.len < 16 + 16 {
		return error('ciphertext too short for CBC')
	}

	// Extract IV from ciphertext
	iv := ciphertext[..16]
	encrypted := ciphertext[16..]

	if encrypted.len % 16 != 0 {
		return error('ciphertext length must be multiple of block size')
	}

	block := aes.new_cipher(c.key)
	mode := crypto_cipher.new_cbc(block, iv)

	mut plaintext := []u8{len: encrypted.len}
	mode.decrypt_blocks(mut plaintext, encrypted)

	// Remove PKCS#7 padding
	return utils.pkcs7_unpad(plaintext)
}

// encrypt_ctr encrypts using AES-CTR
fn (mut c AESCipher) encrypt_ctr(plaintext []u8) ![]u8 {
	block := aes.new_cipher(c.key)
	stream := crypto_cipher.new_ctr(block, c.iv)

	mut ciphertext := []u8{len: c.iv.len + plaintext.len}
	copy(mut ciphertext, c.iv)

	stream.xor_key_stream(mut ciphertext[c.iv.len..], plaintext)

	// Generate new IV for next encryption
	c.iv = rand.generate_iv(16)!

	return ciphertext
}

// decrypt_ctr decrypts using AES-CTR
fn (mut c AESCipher) decrypt_ctr(ciphertext []u8) ![]u8 {
	if ciphertext.len < 16 {
		return error('ciphertext too short for CTR')
	}

	// Extract IV from ciphertext
	iv := ciphertext[..16]
	encrypted := ciphertext[16..]

	block := aes.new_cipher(c.key)
	stream := crypto_cipher.new_ctr(block, iv)

	mut plaintext := []u8{len: encrypted.len}
	stream.xor_key_stream(mut plaintext, encrypted)

	return plaintext
}

// encrypt_file encrypts a file using AES.
//
// Example:
// ```v
// cipher.encrypt_file('input.txt', 'output.enc')!
// ```
pub fn (mut c AESCipher) encrypt_file(input_path string, output_path string) ! {
	if !os.exists(input_path) {
		return error('input file does not exist: ${input_path}')
	}

	plaintext := os.read_bytes(input_path)!
	ciphertext := c.encrypt(plaintext)!
	os.write_file(output_path, ciphertext.bytestr())!
}

// decrypt_file decrypts a file using AES.
//
// Example:
// ```v
// cipher.decrypt_file('output.enc', 'decrypted.txt')!
// ```
pub fn (mut c AESCipher) decrypt_file(input_path string, output_path string) ! {
	if !os.exists(input_path) {
		return error('input file does not exist: ${input_path}')
	}

	ciphertext := os.read_bytes(input_path)!
	plaintext := c.decrypt(ciphertext)!
	os.write_file(output_path, plaintext.bytestr())!
}

// Convenience functions for common use cases

// encrypt_aes_256_gcm encrypts data using AES-256-GCM.
//
// Example:
// ```v
// key := rand.generate_key(256)!
// ciphertext := cipher.encrypt_aes_256_gcm(key, plaintext)!
// ```
pub fn encrypt_aes_256_gcm(key []u8, plaintext []u8) ![]u8 {
	mut c := new_aes_gcm(key)!
	return c.encrypt(plaintext)
}

// decrypt_aes_256_gcm decrypts data using AES-256-GCM.
//
// Example:
// ```v
// plaintext := cipher.decrypt_aes_256_gcm(key, ciphertext)!
// ```
pub fn decrypt_aes_256_gcm(key []u8, ciphertext []u8) ![]u8 {
	mut c := new_aes_gcm(key)!
	return c.decrypt(ciphertext)
}

// encrypt_file_aes_gcm encrypts a file using AES-GCM.
//
// Example:
// ```v
// key := rand.generate_key(256)!
// cipher.encrypt_file_aes_gcm(key, 'input.txt', 'output.enc')!
// ```
pub fn encrypt_file_aes_gcm(key []u8, input_path string, output_path string) ! {
	mut c := new_aes_gcm(key)!
	c.encrypt_file(input_path, output_path)!
}

// decrypt_file_aes_gcm decrypts a file using AES-GCM.
//
// Example:
// ```v
// cipher.decrypt_file_aes_gcm(key, 'output.enc', 'decrypted.txt')!
// ```
pub fn decrypt_file_aes_gcm(key []u8, input_path string, output_path string) ! {
	mut c := new_aes_gcm(key)!
	c.decrypt_file(input_path, output_path)!
}
