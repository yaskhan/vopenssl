import ecc
import ecc.vecdsa

fn main() {
	println('Verifying ecc integration with vecdsa...')
	
	// Generate key pair for secp256r1
	key_pair := ecc.generate_key_pair(.secp256r1) or {
		println('FAILED: generate_key_pair: ${err}')
		return
	}
	println('Key pair generated.')
	
	msg := 'hello integration'.bytes()
	sig := ecc.ecdsa_sign(key_pair.private, msg, .sha256) or {
		println('FAILED: ecdsa_sign: ${err}')
		return
	}
	println('Signature created.')
	
	valid := ecc.ecdsa_verify(key_pair.public, msg, sig, .sha256) or {
		println('FAILED: ecdsa_verify: ${err}')
		return
	}
	
	if valid {
		println('SUCCESS: ecc integration verified!')
	} else {
		println('FAILED: signature verification failed')
	}
}
