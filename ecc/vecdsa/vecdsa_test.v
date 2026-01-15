module vecdsa

import crypto.sha256

pub fn test_ecdsa_p256() {
	curve := p256()
	priv := generate_key(curve) or {
		assert false, 'Failed to generate key'
		return
	}
	
	msg := 'test message'.bytes()
	hash := sha256.sum(msg)
	
	r, s := sign(priv, hash) or {
		assert false, 'Failed to sign'
		return
	}
	
	valid := verify(priv.public_key, hash, r, s)
	assert valid == true
}

pub fn test_ecdsa_asn1_p256() {
	curve := p256()
	priv := generate_key(curve) or {
		assert false, 'Failed to generate key'
		return
	}
	
	msg := 'test message asn1'.bytes()
	hash := sha256.sum(msg)
	
	sig := sign_asn1(priv, hash) or {
		assert false, 'Failed to sign ASN.1'
		return
	}
	
	valid := verify_asn1(priv.public_key, hash, sig)
	assert valid == true
}

pub fn test_ecdsa_encoding_p256() {
	curve := p256()
	priv := generate_key(curve) or {
		assert false, 'Failed to generate key'
		return
	}
	
	pub_bytes := priv.public_key.bytes()
	pk2 := parse_uncompressed_public_key(curve, pub_bytes) or {
		assert false, 'Failed to parse public key'
		return
	}
	assert priv.public_key.equals(pk2)
	
	priv_bytes := priv.bytes()
	assert priv_bytes.len == (curve.params().bit_size + 7) / 8
}
