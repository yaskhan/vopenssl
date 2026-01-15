module rsa

import math.big
import crypto.rand

// RSA module - Pure V implementation

// RSAKeySize определяет размер ключа RSA в битах
pub enum RSAKeySize {
	bits1024  = 1024
	bits2048  = 2048
	bits3072  = 3072
	bits4096  = 4096
}

// HashAlgorithm определяет алгоритм хеширования для подписей
pub enum HashAlgorithm {
	sha1
	sha224
	sha256
	sha384
	sha512
	md5
}

// RSAPublicKey представляет открытый ключ RSA
pub struct RSAPublicKey {
pub:
	n []u8 // modulus (big-endian)
	e []u8 // public exponent (big-endian)
}

// RSAPrivateKey представляет приватный ключ RSA
pub struct RSAPrivateKey {
pub:
	n  []u8 // modulus (big-endian)
	e  []u8 // public exponent (big-endian)
	d  []u8 // private exponent (big-endian)
	p  []u8 // prime factor p
	q  []u8 // prime factor q
	dp []u8 // d mod (p-1)
	dq []u8 // d mod (q-1)
	qi []u8 // q^(-1) mod p
}

// RSAKeyPair представляет пару ключей RSA
pub struct RSAKeyPair {
pub:
	private RSAPrivateKey
	public  RSAPublicKey
}

// PaddingScheme определяет схему дополнения
pub enum PaddingScheme {
	pkcs1_v15 // PKCS#1 v1.5 padding
	oaep     // Optimal Asymmetric Encryption Padding
	pss      // Probabilistic Signature Scheme
}

// generate_key_pair генерирует пару ключей RSA указанного размера
//
// Example:
// ```v
// key_pair := rsa.generate_key_pair(.bits2048)!
// ```
pub fn generate_key_pair(size RSAKeySize) !RSAKeyPair {
	bit_len := int(size)
	half_len := bit_len / 2

	e := big.integer_from_int(65537)

	for {
		p := generate_prime(half_len)!
		q := generate_prime(half_len)!

		if p == q {
			continue
		}

		n := p * q
		
		p_minus_1 := p - big.integer_from_int(1)
		q_minus_1 := q - big.integer_from_int(1)
		phi := p_minus_1 * q_minus_1

		// gcd(e, phi) must be 1
		g := e.gcd(phi)
		if g != big.integer_from_int(1) {
			continue
		}

		d := e.mod_inverse(phi)!

		// CRT parameters
		dp := d.mod_euclid(p_minus_1)
		dq := d.mod_euclid(q_minus_1)
		qi := q.mod_inverse(p)!

		n_bytes, _ := n.bytes()
		e_bytes, _ := e.bytes()
		d_bytes, _ := d.bytes()
		p_bytes, _ := p.bytes()
		q_bytes, _ := q.bytes()
		dp_bytes, _ := dp.bytes()
		dq_bytes, _ := dq.bytes()
		qi_bytes, _ := qi.bytes()

		return RSAKeyPair{
			private: RSAPrivateKey{
				n: n_bytes
				e: e_bytes
				d: d_bytes
				p: p_bytes
				q: q_bytes
				dp: dp_bytes
				dq: dq_bytes
				qi: qi_bytes
			}
			public: RSAPublicKey{
				n: n_bytes
				e: e_bytes
			}
		}
	}
	return error('failed to generate key pair')
}

// generate_prime генерирует случайное простое число заданного размера
fn generate_prime(bits int) !big.Integer {
	byte_len := (bits + 7) / 8
	for {
		mut bytes := rand.bytes(byte_len)!
		// Устанавливаем старший бит, чтобы гарантировать длину, 
		// и младший бит, чтобы число было нечетным
		bytes[0] |= 0x80
		bytes[byte_len - 1] |= 0x01
		
		p := big.integer_from_bytes(bytes)
		if is_prime(p, 40)! {
			return p
		}
	}
	return error('failed to generate prime')
}

// is_prime проверяет число на простоту с помощью теста Миллера-Рабина
fn is_prime(n big.Integer, k int) !bool {
	one := big.integer_from_int(1)
	two := big.integer_from_int(2)
	zero := big.integer_from_int(0)

	if n < two { return false }
	if n == two || n == big.integer_from_int(3) { return true }
	if n % two == zero { return false }

	// n - 1 = 2^s * d
	mut d := n - one
	mut s := 0
	for d % two == zero {
		d /= two
		s++
	}

	for _ in 0 .. k {
		// Выбираем случайное a в диапазоне [2, n - 2]
		// Для простоты используем маленькие простые числа или случайные байты
		mut a_bytes := rand.bytes(n.bit_len() / 8)!
		mut a := big.integer_from_bytes(a_bytes)
		if a < two { a = two }
		if a >= n - one { a = n - two }

		mut x := a.big_mod_pow(d, n) or { return false }
		if x == one || x == n - one {
			continue
		}

		mut composite := true
		for _ in 0 .. s - 1 {
			x = x.big_mod_pow(two, n) or { return false }
			if x == n - one {
				composite = false
				break
			}
		}
		if composite {
			return false
		}
	}
	return true
}

// encrypt шифрует данные с использованием открытого ключа RSA
//
// Example:
// ```v
// ciphertext := rsa.encrypt(pub_key, plaintext, .oaep)!
// ```
pub fn encrypt(pub_key RSAPublicKey, data []u8, padding PaddingScheme) ![]u8 {
	match padding {
		.pkcs1_v15 {
			return encrypt_pkcs1_v15(pub_key, data)
		}
		.oaep {
			return encrypt_oaep(pub_key, data)
		}
		else {
			return error('unsupported padding scheme for encryption: ${padding}')
		}
	}
}

// decrypt дешифрует данные с использованием приватного ключа RSA
//
// Example:
// ```v
// plaintext := rsa.decrypt(priv_key, ciphertext, .oaep)!
// ```
pub fn decrypt(priv_key RSAPrivateKey, data []u8, padding PaddingScheme) ![]u8 {
	match padding {
		.pkcs1_v15 {
			return decrypt_pkcs1_v15(priv_key, data)
		}
		.oaep {
			return decrypt_oaep(priv_key, data)
		}
		else {
			return error('unsupported padding scheme for decryption: ${padding}')
		}
	}
}

// sign создает подпись данных с использованием приватного ключа RSA
//
// Example:
// ```v
// signature := rsa.sign(priv_key, data, .sha256, .pss)!
// ```
pub fn sign(priv_key RSAPrivateKey, data []u8, hash_alg HashAlgorithm, padding PaddingScheme) ![]u8 {
	match padding {
		.pkcs1_v15 {
			return sign_pkcs1_v15(priv_key, data, hash_alg)
		}
		.pss {
			return sign_pss(priv_key, data, hash_alg)
		}
		else {
			return error('unsupported padding scheme for signing: ${padding}')
		}
	}
}

// verify проверяет подпись данных с использованием открытого ключа RSA
//
// Example:
// ```v
// is_valid := rsa.verify(pub_key, data, signature, .sha256, .pss)!
// ```
pub fn verify(pub_key RSAPublicKey, data []u8, signature []u8, hash_alg HashAlgorithm, padding PaddingScheme) !bool {
	match padding {
		.pkcs1_v15 {
			return verify_pkcs1_v15(pub_key, data, signature, hash_alg)
		}
		.pss {
			return verify_pss(pub_key, data, signature, hash_alg)
		}
		else {
			return error('unsupported padding scheme for verification: ${padding}')
		}
	}
}

// to_public_key извлекает открытый ключ из приватного
pub fn (priv RSAPrivateKey) to_public_key() RSAPublicKey {
	return RSAPublicKey{
		n: priv.n
		e: priv.e
	}
}

// has_private проверяет, содержит ли ключ приватную часть
pub fn (pub RSAPublicKey) has_private() bool {
	return false
}

// has_private проверяет, содержит ли ключ приватную часть
pub fn (priv RSAPrivateKey) has_private() bool {
	return true
}

// Размеры ключей и битовые операции
fn get_key_byte_size(key RSAPublicKey) int {
	return key.n.len
}

// Получить размер модуля в битах
pub fn (pub_key RSAPublicKey) bit_length() int {
	return pub_key.n.len * 8
}

// Получить размер модуля в битах
pub fn (priv_key RSAPrivateKey) bit_length() int {
	return priv_key.n.len * 8
}
