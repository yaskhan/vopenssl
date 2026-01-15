module formats

import rsa

fn test_encode_rsa_public_key_pem() {
	// Small key for testing
	key_pair := rsa.generate_key_pair(unsafe { rsa.RSAKeySize(512) }) or {
		assert false, 'failed to generate key pair: ${err}'
		return
	}

	pem_str := encode_rsa_public_key_pem(key_pair.public)
	// println(pem_str)

	assert pem_str.starts_with('-----BEGIN PUBLIC KEY-----')
	assert pem_str.trim_space().ends_with('-----END PUBLIC KEY-----')

	// Try to decode it back using existing decode_rsa_public_key_pem
	decoded_key := decode_rsa_public_key_pem(pem_str) or {
		assert false, 'failed to decode PEM: ${err}'
		return
	}

	assert decoded_key.n == key_pair.public.n
	assert decoded_key.e == key_pair.public.e
}
