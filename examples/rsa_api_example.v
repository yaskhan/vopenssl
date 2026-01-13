module main

import vopenssl.rsa
import vopenssl.utils

fn main() {
	println('=== RSA API Example (Structure Only) ===\n')

	println('This example demonstrates the RSA API structure.')
	println('Full implementation requires big integer arithmetic.\n')

	// Демонстрация API
	println('1. RSA Key Generation API:')
	println('   key_pair := rsa.generate_key_pair(.bits2048)!')
	println('   // Returns: RSAKeyPair with public and private keys\n')

	println('2. RSA Encryption API:')
	println('   ciphertext := rsa.encrypt(pub_key, data, .oaep)!')
	println('   // Supports: PKCS#1 v1.5, OAEP\n')

	println('3. RSA Decryption API:')
	println('   plaintext := rsa.decrypt(priv_key, ciphertext, .oaep)!\n')

	println('4. RSA Signing API:')
	println('   signature := rsa.sign(priv_key, data, .sha256, .pss)!')
	println('   // Supports: PKCS#1 v1.5, PSS\n')

	println('5. RSA Verification API:')
	println('   valid := rsa.verify(pub_key, data, signature, .sha256, .pss)!\n')

	// Попытка реального вызова (будет ожидаемо работать с C bindings)
	println('Attempting key generation (requires C bindings)...')
	key_pair := rsa.generate_key_pair(.bits2048) or {
		println('Expected: ${err}')
		println('\nNote: Phase 1 provides API structure.')
		println('Phase 3 will add C bindings to libcrypto or pure V big int.')
		return
	}

	// Если работает (с C bindings):
	println('Keys generated!')
	data := 'Hello RSA!'.bytes()

	// Шифрование
	ciphertext := rsa.encrypt(key_pair.public, data, .oaep) or {
		eprintln('Encryption error: ${err}')
		return
	}
	println('Encrypted: ${utils.hex(ciphertext)[..32]}...')

	// Дешифрование
	plaintext := rsa.decrypt(key_pair.private, ciphertext, .oaep) or {
		eprintln('Decryption error: ${err}')
		return
	}
	println('Decrypted: ${plaintext.bytestr()}')

	// Подпись
	signature := rsa.sign(key_pair.private, data, .sha256, .pss) or {
		eprintln('Signing error: ${err}')
		return
	}
	println('Signature: ${utils.hex(signature)[..32]}...')

	// Проверка
	valid := rsa.verify(key_pair.public, data, signature, .sha256, .pss) or {
		eprintln('Verification error: ${err}')
		return
	}
	println('Signature valid: ${valid}')
}
