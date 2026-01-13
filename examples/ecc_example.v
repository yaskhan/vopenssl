module main

import vopenssl.ecc
import vopenssl.utils

fn main() {
	println('=== Elliptic Curve Cryptography Example ===\n')

	// Демонстрация поддерживаемых кривых
	println('1. Supported Elliptic Curves:')
	curves := [
		ecc.EllipticCurve.secp256r1,
		ecc.EllipticCurve.secp384r1,
		ecc.EllipticCurve.secp521r1,
		ecc.EllipticCurve.x25519,
		ecc.EllipticCurve.ed25519
	]

	for curve in curves {
		params := ecc.get_curve_params(curve) or {
			eprintln('   ${curve}: ${err}')
			continue
		}
		println('   ${params.name}: ${params.key_size} bits')
	}

	// ECDSA API
	println('\n2. ECDSA API:')
	println('   key_pair := ecc.generate_key_pair(.secp256r1)!')
	println('   signature := ecc.ecdsa_sign(priv_key, data, .sha256)!')
	println('   valid := ecc.ecdsa_verify(pub_key, data, signature, .sha256)!')

	// ECDH API
	println('\n3. ECDH API:')
	println('   shared := ecc.ecdh(priv_key, other_pub_key)!')
	println('   // Both parties compute same shared secret')

	// Ed25519 (уже работает)
	println('\n4. Ed25519 (via crypto.ed25519):')
	key_pair := ecc.generate_key_pair(.ed25519) or {
		eprintln('   Error: ${err}')
		return
	}
	println('   Generated Ed25519 keys')
	
	message := 'Test message'.bytes()
	signature := ecc.ed25519_sign(key_pair.private, message) or {
		eprintln('   Sign error: ${err}')
		return
	}
	println('   Signed: ${utils.hex(signature)[..32]}...')
	
	valid := ecc.ed25519_verify(key_pair.public, message, signature) or {
		eprintln('   Verify error: ${err}')
		return
	}
	println('   Verified: ${valid}')

	// X25519 ECDH (структура)
	println('\n5. X25519 ECDH:')
	println('   alice := ecc.generate_key_pair(.x25519)!')
	println('   bob := ecc.generate_key_pair(.x25519)!')
	println('   shared_alice := ecc.ecdh(alice.private, bob.public)!')
	println('   shared_bob := ecc.ecdh(bob.private, alice.public)!')
	println('   // shared_alice == shared_bob')

	println('\n=== Summary ===')
	println('✓ ECC API structure defined')
	println('✓ Curves: secp256r1, secp384r1, secp521r1, x25519, ed25519')
	println('✓ Ed25519 fully functional (via vlib)')
	println('✓ X25519 structure ready (needs C bindings)')
	println('✓ ECDSA structure ready (needs C bindings)')
}
