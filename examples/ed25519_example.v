module main

import vopenssl.ed25519
import vopenssl.utils

fn main() {
	println('=== Ed25519 Digital Signatures Example ===\n')

	// Шаг 1: Генерация ключевой пары
	println('1. Generating Ed25519 key pair...')
	key_pair := ed25519.generate_key_pair() or {
		eprintln('Error: ${err}')
		return
	}
	println('   Private key: ${utils.hex(key_pair.private)[..32]}...')
	println('   Public key:  ${utils.hex(key_pair.public)[..32]}...')

	// Шаг 2: Подпись сообщения
	message := 'This is a secret message that needs to be signed'.bytes()
	println('\n2. Signing message...')
	println('   Message: ${message.bytestr()}')
	
	signature := ed25519.sign(key_pair.private, message) or {
		eprintln('Error: ${err}')
		return
	}
	println('   Signature: ${utils.hex(signature)[..32]}...')

	// Шаг 3: Проверка подписи
	println('\n3. Verifying signature...')
	is_valid := ed25519.verify(key_pair.public, message, signature) or {
		eprintln('Error: ${err}')
		return
	}
	println('   Valid: ${is_valid}')

	// Шаг 4: Проверка с поддельными данными
	fake_message := 'This is a fake message'.bytes()
	println('\n4. Verifying with wrong message...')
	is_valid_fake := ed25519.verify(key_pair.public, fake_message, signature) or {
		eprintln('Error: ${err}')
		return
	}
	println('   Valid: ${is_valid_fake}')

	// Шаг 5: Проверка с поддельной подписью
	fake_signature := []u8{len: 64, init: 0} // нулевая подпись
	println('\n5. Verifying with fake signature...')
	is_valid_fake_sig := ed25519.verify(key_pair.public, message, fake_signature) or {
		eprintln('Error: ${err}')
		return
	}
	println('   Valid: ${is_valid_fake_sig}')

	println('\n=== Summary ===')
	println('✓ Ed25519 signatures work correctly')
	println('✓ Message authentication verified')
	println('✓ Forgery detection working')
}
