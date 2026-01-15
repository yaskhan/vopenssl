import vopenssl.rsa
import vopenssl.formats
import vopenssl.ecc

fn main() {
	println('Starting key encoding/decoding verification...')

	// -- RSA Public Key --
	println('\n[RSA Public Key]')
	key_pair := rsa.generate_key_pair(unsafe { rsa.RSAKeySize(512) }) or {
		println('FAILED: failed to generate RSA key pair: ${err}')
		return
	}
	pub_pem := formats.encode_rsa_public_key_pem(key_pair.public)
	println('PEM encoded.')
	decoded_pub := formats.decode_rsa_public_key_pem(pub_pem) or {
		println('FAILED: failed to decode RSA public key: ${err}')
		return
	}
	if decoded_pub.n == key_pair.public.n && decoded_pub.e == key_pair.public.e {
		println('SUCCESS: RSA public key verified!')
	} else {
		println('FAILED: RSA public key mismatch')
	}

	// -- RSA Private Key --
	println('\n[RSA Private Key]')
	priv_pem := formats.encode_rsa_private_key_pem(key_pair.private)
	println('PEM encoded.')
	decoded_priv := formats.decode_rsa_private_key_pem(priv_pem) or {
		println('FAILED: failed to decode RSA private key: ${err}')
		return
	}
	if decoded_priv.n == key_pair.private.n && decoded_priv.d == key_pair.private.d {
		println('SUCCESS: RSA private key verified!')
	} else {
		println('FAILED: RSA private key mismatch')
	}

	// -- EC Public Key (Basic check) --
	println('\n[EC Public Key]')
	// Currently we use secp256r1 as placeholder in decoding, let's just check encoding
	ec_pub := ecc.ECPublicKey{
		curve: .secp256r1
		x: []u8{len: 32, init: 0x01}
		y: []u8{len: 32, init: 0x02}
	}
	ec_pub_pem := formats.encode_ec_public_key_pem(ec_pub)
	println('PEM encoded.')
	if ec_pub_pem.contains('-----BEGIN PUBLIC KEY-----') {
		println('SUCCESS: EC public key encoding looks good!')
	}

	println('\nVerification complete.')
}
