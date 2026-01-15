module rsa

import math.big

fn test_rsa_key_generation() {
	// Generate a small key for faster testing
	// Generate a small key for faster testing
	key_pair := generate_key_pair(unsafe { RSAKeySize(512) }) or {
		assert false, 'failed to generate key pair: ${err}'
		return
	}

	println('Key pair generated successfully')
	
	n := big.integer_from_bytes(key_pair.public.n)
	e := big.integer_from_bytes(key_pair.public.e)
	d := big.integer_from_bytes(key_pair.private.d)
	p := big.integer_from_bytes(key_pair.private.p)
	q := big.integer_from_bytes(key_pair.private.q)

	// Verify n = p * q
	assert n == p * q, 'n != p * q'
	println('Verified n = p * q')

	// Verify d * e = 1 mod phi
	p_minus_1 := p - big.integer_from_int(1)
	q_minus_1 := q - big.integer_from_int(1)
	phi := p_minus_1 * q_minus_1
	
	de := (d * e) % phi
	assert de == big.integer_from_int(1), 'd * e != 1 mod phi'
	println('Verified d * e = 1 mod phi')
	
	// Test basic encryption/decryption (m^e mod n)
	m := big.integer_from_int(12345)
	c := m.big_mod_pow(e, n) or { panic(err) }
	m2 := c.big_mod_pow(d, n) or { panic(err) }
	
	assert m == m2, 'encryption/decryption failed'
	println('Verified basic encryption/decryption')
}
