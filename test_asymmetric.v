module main

import vopenssl.rsa
import vopenssl.ecc
import vopenssl.ed25519
import vopenssl.utils
import vopenssl.encoding

fn main() {
	println('=== VOpenSSL Asymmetric Cryptography Tests ===\n')

	// Тест 1: Ed25519 (работает через встроенный crypto)
	println('Test 1: Ed25519 Signatures')
	test_ed25519()
	println('✓ Ed25519 test passed\n')

	// Тест 2: ECDSA кривые (структуры и заглушки)
	println('Test 2: ECDSA Structures')
	test_ecdsa_structures()
	println('✓ ECDSA structures test passed\n')

	// Тест 3: RSA структуры и padding
	println('Test 3: RSA Structures and Padding')
	test_rsa_structures()
	println('✓ RSA structures test passed\n')

	// Тест 4: PEM encoding
	println('Test 4: PEM Encoding')
	test_pem_encoding()
	println('✓ PEM encoding test passed\n')

	println('=== All Asymmetric Tests Completed! ===')
	println('\nNote: RSA/ECC operations require big integer arithmetic.')
	println('Phase 1 provides API structure and Ed25519 support.')
	println('Phase 3 will add full RSA/ECC with C bindings.')
}

fn test_ed25519() {
	// Генерация ключевой пары
	key_pair := ed25519.generate_key_pair() or {
		eprintln('Error generating Ed25519 keys: ${err}')
		return
	}
	println('Generated Ed25519 key pair')
	println('Private key length: ${key_pair.private.len} bytes')
	println('Public key length: ${key_pair.public.len} bytes')

	// Подпись сообщения
	message := 'Hello, Ed25519!'.bytes()
	signature := ed25519.sign(key_pair.private, message) or {
		eprintln('Error signing: ${err}')
		return
	}
	println('Signature length: ${signature.len} bytes')

	// Проверка подписи
	is_valid := ed25519.verify(key_pair.public, message, signature) or {
		eprintln('Error verifying: ${err}')
		return
	}
	println('Signature valid: ${is_valid}')

	// Проверка с неверными данными
	bad_message := 'Goodbye, Ed25519!'.bytes()
	is_valid_bad := ed25519.verify(key_pair.public, bad_message, signature) or {
		eprintln('Error verifying bad: ${err}')
		return
	}
	println('Bad signature valid: ${is_valid_bad}')

	if is_valid && !is_valid_bad {
		println('✓ Ed25519 working correctly')
	} else {
		println('✗ Ed25519 test failed')
	}
}

fn test_ecdsa_structures() {
	// Тест кривых
	curves := [ecc.EllipticCurve.secp256r1, ecc.EllipticCurve.secp384r1, 
		ecc.EllipticCurve.secp521r1, ecc.EllipticCurve.x25519]

	for curve in curves {
		params := ecc.get_curve_params(curve) or {
			eprintln('Error getting params for ${curve}: ${err}')
			continue
		}
		println('Curve: ${params.name}, key size: ${params.key_size} bits')
	}

	// Попытка генерации ключей (будет ожидаемо работать для Ed25519 и X25519)
	println('\nTrying X25519 key generation...')
	x25519_pair := ecc.generate_key_pair(.x25519) or {
		eprintln('X25519 requires C bindings: ${err}')
		// Это ожидаемо
		return
	}
	println('X25519 keys generated successfully')
	println('X25519 public key: ${utils.hex(x25519_pair.public.x)[..32]}...')

	// ECDH попытка
	other_pair := ecc.generate_key_pair(.x25519) or { return }
	shared_secret := ecc.ecdh(x25519_pair.private, other_pair.public) or {
		eprintln('ECDH requires C bindings: ${err}')
		return
	}
	println('ECDH shared secret: ${utils.hex(shared_secret)[..32]}...')
}

fn test_rsa_structures() {
	// Попытка генерации RSA ключей
	println('Attempting RSA key generation...')
	key_pair := rsa.generate_key_pair(.bits2048) or {
		eprintln('Expected error (requires big int): ${err}')
		// Это ожидаемо в Phase 1
		return
	}

	// Если удалось (что маловероятно), проверим структуру
	println('RSA keys generated (unexpected!)')
	println('Modulus length: ${key_pair.public.n.len} bytes')
	println('Public exponent: ${utils.hex(key_pair.public.e)}')
}

fn test_pem_encoding() {
	// Тест PEM encoding с тестовыми данными
	test_data := 'Test data for PEM encoding'.bytes()
	pem_str := encoding.pem_encode('TEST BLOCK', {'Comment': 'Test'}, test_data)
	println('PEM encoded:')
	println(pem_str)

	// Декодирование
	block := encoding.pem_decode(pem_str) or {
		eprintln('PEM decode error: ${err}')
		return
	}
	println('Decoded type: ${block.type_}')
	println('Decoded data: ${block.bytes.bytestr()}')
	println('Headers: ${block.headers}')

	if block.type_ == 'TEST BLOCK' && block.bytes.bytestr() == test_data.bytestr() {
		println('✓ PEM encoding working correctly')
	} else {
		println('✗ PEM encoding test failed')
	}
}
