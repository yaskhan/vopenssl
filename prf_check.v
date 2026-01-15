module main

import crypto.sha256
import crypto.hmac

fn main() {
    println('Verifying PRF logic...')
    
    secret := [u8(0x01), 0x02, 0x03, 0x04]
    label := "test"
    seed := [u8(0x05), 0x06, 0x07, 0x08]
    
    out := prf_tls12(secret, label, seed, 32)
    
    if out.len != 32 {
        panic('Output length mismatch')
    }
    
    println('PRF logic executed successfully. Output length: ${out.len}')
    println('Output: ${out}')
}

// prf_tls12 implements the TLS 1.2 Pseudo-Random Function (P_SHA256)
fn prf_tls12(secret []u8, label string, seed []u8, length int) []u8 {
	label_bytes := label.bytes()
	mut label_seed := []u8{}
	label_seed << label_bytes
	label_seed << seed

	return p_sha256(secret, label_seed, length)
}

// p_sha256 implements the P_hash function using SHA-256
fn p_sha256(secret []u8, seed []u8, length int) []u8 {
	mut result := []u8{}
	mut a := hmac.new(secret, seed, sha256.sum, sha256.block_size)
	
	for result.len < length {
		a = hmac.new(secret, a, sha256.sum, sha256.block_size)
		
		mut input := []u8{}
		input << a
		input << seed
		
		output := hmac.new(secret, input, sha256.sum, sha256.block_size)
		result << output
	}
	
	return result[..length]
}
