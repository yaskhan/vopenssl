module ed25519

import crypto.ed25519 as crypto_ed25519

// PublicKey представляет открытый ключ Ed25519
pub type PublicKey = []u8

// PrivateKey представляет приватный ключ Ed25519
pub type PrivateKey = []u8

// KeyPair представляет пару ключей Ed25519
pub struct KeyPair {
pub:
	private PrivateKey
	public  PublicKey
}

// generate_key_pair генерирует новую пару ключей Ed25519
//
// Example:
// ```v
// key_pair := ed25519.generate_key_pair()!
// ```
pub fn generate_key_pair() !KeyPair {
	pub_key, priv_key := crypto_ed25519.generate_key()!
	return KeyPair{
		private: PrivateKey(priv_key)
		public:  PublicKey(pub_key)
	}
}

// sign создает подпись данных приватным ключом
//
// Example:
// ```v
// signature := ed25519.sign(private_key, message)!
// ```
pub fn sign(private_key PrivateKey, message []u8) ![]u8 {
	return crypto_ed25519.sign(private_key, message)
}

// verify проверяет подпись открытым ключом
//
// Example:
// ```v
// is_valid := ed25519.verify(public_key, message, signature)!
// ```
pub fn verify(public_key PublicKey, message []u8, signature []u8) !bool {
	return crypto_ed25519.verify(public_key, message, signature)
}

// new_key_pair_from_seed создает ключевую пару из 32-байтного seed
pub fn new_key_pair_from_seed(seed []u8) !KeyPair {
	if seed.len != 32 {
		return error('Seed must be 32 bytes')
	}

	// Ed25519 seed -> private key transformation
	// В vlib/crypto это делается внутри, но мы можем использовать прямой вызов
	priv_key := crypto_ed25519.new_key_from_seed(seed)
	pub_key := priv_key[32..] // публичная часть в конце приватного ключа

	return KeyPair{
		private: PrivateKey(priv_key)
		public:  PublicKey(pub_key)
	}
}

// public_key_from_private извлекает открытый ключ из приватного
pub fn public_key_from_private(private_key PrivateKey) PublicKey {
	if private_key.len == 64 {
		return PublicKey(private_key[32..])
	}
	// For 32-byte seeds, generate the full key pair first
	full_key := crypto_ed25519.new_key_from_seed(private_key)
	return PublicKey(full_key[32..])
}

// verify_strict выполняет строгую проверку подписи (с проверкой формата)
pub fn verify_strict(public_key PublicKey, message []u8, signature []u8) !bool {
	if signature.len != 64 {
		return error('Invalid signature length')
	}
	if public_key.len != 32 {
		return error('Invalid public key length')
	}

	return verify(public_key, message, signature)
}

// dom2 префикс для Ed25519ctx и Ed25519ph (RFC 8032)
fn dom2(x u8, y []u8) []u8 {
	mut res := 'SigEd25519 no Ed25519 collisions'.bytes()
	res << x
	res << u8(y.len)
	res << y
	return res
}

// sign_context создает подпись с контекстом (для предотвращения replay-атак)
pub fn sign_context(private_key PrivateKey, message []u8, context []u8) ![]u8 {
	if context.len > 255 {
		return error('Context too long (max 255 bytes)')
	}
	// Ed25519ctx - требует специальной обработки
	// Мы будем использовать нашу внутреннюю реализацию
	return sign_internal(private_key, message, context, 0)
}

// sign_ph создает подпись для прехешированного сообщения с контекстом
pub fn sign_ph(private_key PrivateKey, message []u8, context []u8) ![]u8 {
	if context.len > 255 {
		return error('Context too long (max 255 bytes)')
	}
	return sign_internal(private_key, message, context, 1)
}

fn sign_internal(private_key PrivateKey, message []u8, context []u8, ph u8) ![]u8 {
	// Используем нашу новую реализацию из ecc/edwards.v
	return ecc.sign_eddsa_ctx(private_key, message, context, ph)!
}
