module ecc_test

import ecc

fn test_ecdh_agreement() {
	curves := [
		EllipticCurve.x25519,
		EllipticCurve.secp256r1,
		EllipticCurve.secp384r1,
		EllipticCurve.secp521r1,
	]

	for curve in curves {
		println('Testing curve: ${curve}')
		alice_keys := ecc.generate_key_pair(curve) or { panic('Failed to generate Alice keys for ${curve}: ${err}') }
		bob_keys := ecc.generate_key_pair(curve) or { panic('Failed to generate Bob keys for ${curve}: ${err}') }

		alice_shared := ecc.ecdh(alice_keys.private, bob_keys.public) or { panic('Alice failed ECDH for ${curve}: ${err}') }
		bob_shared := ecc.ecdh(bob_keys.private, alice_keys.public) or { panic('Bob failed ECDH for ${curve}: ${err}') }

		assert alice_shared == bob_shared
		
		expected_len := match curve {
			.x25519 { 32 }
			.secp256r1 { 32 }
			.secp384r1 { 48 }
			.secp521r1 { 66 }
			else { 0 }
		}
		assert alice_shared.len == expected_len
		println('OK: ${curve} shared secret length: ${alice_shared.len}')
	}
}
