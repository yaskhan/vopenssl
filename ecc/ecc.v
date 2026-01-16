module ecc

import crypto.rand
import crypto.ed25519 as crypto_ed25519
import math.big
import ecc.vecdsa

// ECPublicKey represents an Elliptic Curve public key.
pub struct ECPublicKey {
pub:
	curve EllipticCurve
	x     []u8 // X coordinate
	y     []u8 // Y coordinate
}

// ECPrivateKey represents an Elliptic Curve private key.
pub struct ECPrivateKey {
pub:
	curve   EllipticCurve
	private []u8        // Private key scalar
	public  ECPublicKey // Corresponding public key
}

// ECKeyPair represents an Elliptic Curve key pair.
pub struct ECKeyPair {
pub:
	private ECPrivateKey
	public  ECPublicKey
}

// ECDSASignature represents an ECDSA signature.
pub struct ECDSASignature {
pub:
	r []u8
	s []u8
}

// generate_key_pair generates an ECC key pair for the specified curve.
//
// Example:
// ```v
// key_pair := ecc.generate_key_pair(.secp256r1)!
// ```
pub fn generate_key_pair(curve EllipticCurve) !ECKeyPair {
	match curve {
		.secp256r1, .secp384r1, .secp521r1 {
			return generate_ecdsa_key_pair(curve)
		}
		.x25519 {
			return generate_x25519_key_pair()
		}
		.ed25519 {
			// Используем встроенный Ed25519 из vlib/crypto
			pub_key, priv_key := crypto_ed25519.generate_key()!
			return ECKeyPair{
				private: ECPrivateKey{
					curve:   .ed25519
					private: priv_key
					public:  ECPublicKey{
						curve: .ed25519
						x:     pub_key
						y:     []u8{} // Ed25519 использует один байтовый массив
					}
				}
				public:  ECPublicKey{
					curve: .ed25519
					x:     pub_key
					y:     []u8{}
				}
			}
		}
	}
}

// ecdsa_sign creates an ECDSA signature of data using the given private key and hash algorithm.
//
// Example:
// ```v
// signature := ecc.ecdsa_sign(priv_key, data, .sha256)!
// ```
pub fn ecdsa_sign(priv_key ECPrivateKey, data []u8, hash_alg HashAlgorithm) !ECDSASignature {
	if priv_key.curve == .ed25519 {
		// Ed25519 использует другой механизм подписи
		return error('Use ed25519_sign for Ed25519 curve')
	}

	// Вычисляем хеш от данных
	digest := compute_hash(data, hash_alg)

	if priv_key.curve == .secp256r1 {
		// Используем vecdsa для P-256
		c := vecdsa.p256()
		v_priv := vecdsa.PrivateKey{
			d:          big.integer_from_bytes(priv_key.private)
			public_key: vecdsa.PublicKey{
				curve: c
				x:     big.integer_from_bytes(priv_key.public.x)
				y:     big.integer_from_bytes(priv_key.public.y)
			}
		}
		r, s := vecdsa.sign(&v_priv, digest)!
		r_bytes, _ := r.bytes()
		s_bytes, _ := s.bytes()
		return ECDSASignature{
			r: r_bytes
			s: s_bytes
		}
	}

	return error('ECDSA signing for curve ${priv_key.curve} not yet implemented via vecdsa.')
}

// ecdsa_verify verifies an ECDSA signature.
//
// Example:
// ```v
// is_valid := ecc.ecdsa_verify(pub_key, data, signature, .sha256)!
// ```
pub fn ecdsa_verify(pub_key ECPublicKey, data []u8, signature ECDSASignature, hash_alg HashAlgorithm) !bool {
	if pub_key.curve == .ed25519 {
		return error('Use ed25519_verify for Ed25519 curve')
	}

	digest := compute_hash(data, hash_alg)

	if pub_key.curve == .secp256r1 {
		c := vecdsa.p256()
		v_pub := vecdsa.PublicKey{
			curve: c
			x:     big.integer_from_bytes(pub_key.x)
			y:     big.integer_from_bytes(pub_key.y)
		}
		r := big.integer_from_bytes(signature.r)
		s := big.integer_from_bytes(signature.s)
		return vecdsa.verify(&v_pub, digest, r, s)
	}

	return error('ECDSA verification for curve ${pub_key.curve} not yet implemented via vecdsa.')
}

// ecdh performs Elliptic Curve Diffie-Hellman key exchange.
//
// Example:
// ```v
// shared_secret := ecc.ecdh(priv_key, other_pub_key)!
// ```
pub fn ecdh(priv_key ECPrivateKey, other_pub_key ECPublicKey) ![]u8 {
	if priv_key.curve != other_pub_key.curve {
		return error('Curves must match for ECDH')
	}

	match priv_key.curve {
		.x25519 {
			// X25519 специализированная реализация
			return x25519_scalarmult(priv_key.private, other_pub_key.x)
		}
		.secp256r1, .secp384r1, .secp521r1 {
			// ECDH: shared = private * public_point
			// Используем vecdsa для NIST кривых
			c := match priv_key.curve {
				.secp256r1 { vecdsa.p256() }
				.secp384r1 { vecdsa.p384() }
				.secp521r1 { vecdsa.p521() }
				else { return error('Unexpected curve') }
			}

			x_big := big.integer_from_bytes(other_pub_key.x)
			y_big := big.integer_from_bytes(other_pub_key.y)

			// Выполняем скалярное умножение: (shared_x, shared_y) = priv_key * other_pub_key
			sx, sy := c.scalar_mult(x_big, y_big, priv_key.private)
			zero := big.integer_from_int(0)
			if sx == zero && sy == zero {
				return error('ECDH result is point at infinity')
			}

			// Общий секрет в ECDH - это X-координата результирующей точки
			mut shared_secret, _ := sx.bytes()
			
			// Дополняем нулями до нужной длины (key_size / 8)
			expected_len := (c.params().bit_size + 7) / 8
			if shared_secret.len < expected_len {
				mut padded := []u8{len: expected_len, init: 0}
				for i in 0 .. shared_secret.len {
					padded[expected_len - shared_secret.len + i] = shared_secret[i]
				}
				return padded
			}
			return shared_secret
		}
		else {
			return error('ECDH not supported for curve ${priv_key.curve}')
		}
	}
}

// ed25519_sign creates an Ed25519 signature.
pub fn ed25519_sign(priv_key ECPrivateKey, data []u8) ![]u8 {
	if priv_key.curve != .ed25519 {
		return error('Not an Ed25519 key')
	}

	// Используем встроенный Ed25519
	return crypto_ed25519.sign(priv_key.private, data)
}

// ed25519_verify verifies an Ed25519 signature.
pub fn ed25519_verify(pub_key ECPublicKey, data []u8, signature []u8) !bool {
	if pub_key.curve != .ed25519 {
		return error('Not an Ed25519 key')
	}

	// Используем встроенный Ed25519
	return crypto_ed25519.verify(pub_key.x, data, signature)
}

// Вспомогательные функции

// compute_hash вычисляет хеш с указанным алгоритмом
fn compute_hash(data []u8, alg HashAlgorithm) []u8 {
	// Используем функцию из hash.v
	return hash_bytes(data, alg)
}

// generate_ecdsa_key_pair генерирует ключи для NIST кривых
fn generate_ecdsa_key_pair(curve EllipticCurve) !ECKeyPair {
	c := match curve {
		.secp256r1 { vecdsa.p256() }
		.secp384r1 { vecdsa.p384() }
		.secp521r1 { vecdsa.p521() }
		else { return error('Unexpected curve for ECDSA key generation') }
	}
	
	v_priv := vecdsa.generate_key(c)!

	d_bytes, _ := v_priv.d.bytes()
	d_b := []u8(d_bytes)
	x_bytes, _ := v_priv.public_key.x.bytes()
	x_b := []u8(x_bytes)
	y_bytes, _ := v_priv.public_key.y.bytes()
	y_b := []u8(y_bytes)

	pk := ECPublicKey{
		curve: curve
		x:     x_b
		y:     y_b
	}

	return ECKeyPair{
		private: ECPrivateKey{
			curve:   curve
			private: d_b
			public:  pk
		}
		public: pk
	}
}

// generate_x25519_key_pair генерирует ключи для X25519
fn generate_x25519_key_pair() !ECKeyPair {
	// X25519 использует мультипликативную группу поля
	// Приватный ключ: 32 случайных байта (с флагами)
	mut private := rand.bytes(32)!

	// Установка флагов для X25519 (младшие 3 бита = 0, старший бит = 0)
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	// Вычисляем публичный ключ: public = basepoint ^ private
	// basepoint = 9
	mut basepoint := []u8{len: 32, init: 0}
	basepoint[0] = 9
	public := x25519_scalarmult(private, basepoint)!

	public_struct := ECPublicKey{
		curve: .x25519
		x:     public
		y:     []u8{}
	}
	return ECKeyPair{
		private: ECPrivateKey{
			curve:   .x25519
			private: private
			public:  public_struct
		}
		public: public_struct
	}
}

// x25519_scalarmult выполняет скалярное уможение на X25519
// Это упрощенная реализация, полная версия требует монгомери лестницу
fn x25519_scalarmult(scalar []u8, point []u8) ![]u8 {
	if scalar.len != 32 || point.len != 32 {
		return error('X25519 requires 32-byte inputs')
	}

	return x25519_scalarmult_impl(scalar, point)
}

// get_public_key_from_private recovers the public key from a private key.
pub fn get_public_key_from_private(priv_key ECPrivateKey) !ECPublicKey {
	match priv_key.curve {
		.x25519 {
			mut basepoint := []u8{len: 32, init: 0}
			basepoint[0] = 9
			public := x25519_scalarmult(priv_key.private, basepoint)!
			return ECPublicKey{
				curve: .x25519
				x:     public
				y:     []u8{}
			}
		}
		.ed25519 {
			// Ed25519 публичный ключ уже известен
			return ECPublicKey{
				curve: .ed25519
				x:     priv_key.public.x
				y:     []u8{}
			}
		}
		else {
			return error('Public key derivation not implemented for ${priv_key.curve}')
		}
	}
}
