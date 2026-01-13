module rsa

import crypto.rand
import crypto.sha1
import crypto.sha256
import crypto.sha512
import crypto.md5

// PKCS#1 v1.5 padding для шифрования
fn pkcs1_v15_pad(data []u8, key_size int) ![]u8 {
	// PKCS#1 v1.5 padding: 0x00 || 0x02 || PS || 0x00 || D
	// PS - случайные байты, минимум 8 байт
	// D - данные

	if data.len > key_size - 11 {
		return error('data too long for RSA key size')
	}

	ps_len := key_size - 3 - data.len
	if ps_len < 8 {
		return error('padding length too small')
	}

	// Генерируем случайные байты для PS (не 0x00)
	mut ps := []u8{len: ps_len}
	for i in 0 .. ps_len {
		for {
			b := rand.bytes(1) or { return error('random generation failed') }
			if b[0] != 0x00 {
				ps[i] = b[0]
				break
			}
		}
	}

	mut padded := []u8{len: key_size}
	padded[0] = 0x00
	padded[1] = 0x02
	copy(mut padded[2..2 + ps_len], ps)
	padded[2 + ps_len] = 0x00
	copy(mut padded[3 + ps_len..], data)

	return padded
}

// Удаление PKCS#1 v1.5 padding
fn pkcs1_v15_unpad(data []u8) ![]u8 {
	if data.len < 3 {
		return error('data too short')
	}
	if data[0] != 0x00 || data[1] != 0x02 {
		return error('invalid padding')
	}

	// Найти 0x00 байт после заголовка
	mut i := 2
	for i < data.len && data[i] != 0x00 {
		i++
	}

	if i >= data.len {
		return error('padding separator not found')
	}

	// Проверить, что было минимум 8 случайных байт
	if i - 2 < 8 {
		return error('insufficient padding bytes')
	}

	return data[i + 1..]
}

// OAEP padding
fn oaep_pad(data []u8, key_size int, hash_alg HashAlgorithm) ![]u8 {
	// OAEP: M' = 0x00 || 0x00 || ... || 0x00 || 0x01 || M
	// L - label (empty), H - hash function

	if data.len > key_size - 2 * get_hash_len(hash_alg) - 2 {
		return error('data too long for RSA key size with OAEP')
	}

	// Вычисляем хеш от label (пустая строка)
	l_hash := hash_bytes([], hash_alg)

	// PS = zeros
	ps_len := key_size - data.len - 2 * get_hash_len(hash_alg) - 2

	// DB = l_hash || PS || 0x01 || M
	mut db := []u8{len: get_hash_len(hash_alg) + ps_len + 1 + data.len}
	copy(mut db[0..], l_hash)
	// PS уже нули по умолчанию
	db[get_hash_len(hash_alg) + ps_len] = 0x01
	copy(mut db[get_hash_len(hash_alg) + ps_len + 1..], data)

	// seed случайный
	seed := rand.bytes(get_hash_len(hash_alg))!

	// dbMask = MGF(seed, key_size - get_hash_len(hash_alg) - 1)
	db_mask := mgf1(seed, key_size - get_hash_len(hash_alg) - 1, hash_alg)

	// maskedDB = DB XOR dbMask
	mut masked_db := []u8{len: db.len}
	for i in 0 .. db.len {
		masked_db[i] = db[i] ^ db_mask[i]
	}

	// seedMask = MGF(maskedDB, get_hash_len(hash_alg))
	seed_mask := mgf1(masked_db, get_hash_len(hash_alg), hash_alg)

	// maskedSeed = seed XOR seedMask
	mut masked_seed := []u8{len: seed.len}
	for i in 0 .. seed.len {
		masked_seed[i] = seed[i] ^ seed_mask[i]
	}

	// EM = 0x00 || maskedSeed || maskedDB
	mut em := []u8{len: 1 + masked_seed.len + masked_db.len}
	em[0] = 0x00
	copy(mut em[1..], masked_seed)
	copy(mut em[1 + masked_seed.len..], masked_db)

	return em
}

// OAEP unpadding
fn oaep_unpad(data []u8, hash_alg HashAlgorithm) ![]u8 {
	if data.len < 2 * get_hash_len(hash_alg) + 2 {
		return error('data too short')
	}
	if data[0] != 0x00 {
		return error('invalid OAEP prefix')
	}

	l_hash := hash_bytes([], hash_alg)

	// Разделяем maskedSeed и maskedDB
	masked_seed := data[1..1 + get_hash_len(hash_alg)]
	masked_db := data[1 + get_hash_len(hash_alg)..]

	// seedMask = MGF(maskedDB, get_hash_len(hash_alg))
	seed_mask := mgf1(masked_db, get_hash_len(hash_alg), hash_alg)

	// seed = maskedSeed XOR seedMask
	mut seed := []u8{len: masked_seed.len}
	for i in 0 .. masked_seed.len {
		seed[i] = masked_seed[i] ^ seed_mask[i]
	}

	// dbMask = MGF(seed, len(maskedDB))
	db_mask := mgf1(seed, masked_db.len, hash_alg)

	// DB = maskedDB XOR dbMask
	mut db := []u8{len: masked_db.len}
	for i in 0 .. masked_db.len {
		db[i] = masked_db[i] ^ db_mask[i]
	}

	// Проверяем l_hash
	if db[0..l_hash.len] != l_hash {
		return error('label hash mismatch')
	}

	// Найти 0x01
	mut i := l_hash.len
	for i < db.len && db[i] == 0x00 {
		i++
	}

	if i >= db.len || db[i] != 0x01 {
		return error('invalid padding')
	}

	return db[i + 1..]
}

// MGF1 (Mask Generation Function)
fn mgf1(seed []u8, length int, hash_alg HashAlgorithm) []u8 {
	mut result := []u8{len: 0}
	mut counter := 0

	for result.len < length {
		// C = counter (4 bytes, big-endian)
		mut c := []u8{len: 4}
		c[0] = u8((counter >> 24) & 0xFF)
		c[1] = u8((counter >> 16) & 0xFF)
		c[2] = u8((counter >> 8) & 0xFF)
		c[3] = u8(counter & 0xFF)

		// T = H(seed || C)
		mut input := []u8{len: seed.len + 4}
		copy(mut input, seed)
		copy(mut input[seed.len..], c)

		t := hash_bytes(input, hash_alg)
		result << t

		counter++
	}

	return result[..length]
}

// Вспомогательные функции для работы с хешами
fn get_hash_len(alg HashAlgorithm) int {
	return match alg {
		.sha1 { 20 }
		.sha224 { 28 }
		.sha256 { 32 }
		.sha384 { 48 }
		.sha512 { 64 }
		.md5 { 16 }
	}
}

fn hash_bytes(data []u8, alg HashAlgorithm) []u8 {
	match alg {
		.sha1 { return sha1.sum(data) }
		.sha224 { return sha512.sum512_224(data) }
		.sha256 { return sha256.sum256(data) }
		.sha384 { return sha512.sum384(data) }
		.sha512 { return sha512.sum512(data) }
		.md5 { return md5.sum(data) }
	}
}

// PKCS#1 v1.5 padding для подписей
fn pkcs1_v15_sign_pad(hash []u8, hash_alg HashAlgorithm, key_size int) ![]u8 {
	// ASN.1 DER encoding of hash algorithm identifier
	// For now, we'll use a simplified approach

	// Build the DigestInfo structure
	// This is a simplified version - full ASN.1 DER encoding would be more complex
	mut digest_info := []u8{len: hash.len + 20} // approximate size

	// For SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || hash
	// This is a simplified placeholder
	// В реальной реализации нужна полная ASN.1 кодировка

	// Для теста просто добавим хеш с минимальным префиксом
	match hash_alg {
		.sha256 {
			// OID for SHA-256: 2.16.840.1.101.3.4.2.1
			// DER: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
			digest_info = [
				u8(0x30),
				u8(0x31),
				u8(0x30),
				u8(0x0d),
				u8(0x06),
				u8(0x09),
				u8(0x60),
				u8(0x86),
				u8(0x48),
				u8(0x01),
				u8(0x65),
				u8(0x03),
				u8(0x04),
				u8(0x02),
				u8(0x01),
				u8(0x05),
				u8(0x00),
				u8(0x04),
				u8(0x20),
			]
			digest_info << hash
		}
		.sha1 {
			// OID for SHA-1: 1.3.14.3.2.26
			digest_info = [
				u8(0x30),
				u8(0x21),
				u8(0x30),
				u8(0x09),
				u8(0x06),
				u8(0x05),
				u8(0x2b),
				u8(0x0e),
				u8(0x03),
				u8(0x02),
				u8(0x1a),
				u8(0x05),
				u8(0x00),
				u8(0x04),
				u8(0x14),
			]
			digest_info << hash
		}
		.sha512 {
			// OID for SHA-512: 2.16.840.1.101.3.4.2.3
			digest_info = [
				u8(0x30),
				u8(0x51),
				u8(0x30),
				u8(0x0d),
				u8(0x06),
				u8(0x09),
				u8(0x60),
				u8(0x86),
				u8(0x48),
				u8(0x01),
				u8(0x65),
				u8(0x03),
				u8(0x04),
				u8(0x02),
				u8(0x03),
				u8(0x05),
				u8(0x00),
				u8(0x04),
				u8(0x40),
			]
			digest_info << hash
		}
		else {
			// Для остальных алгоритмов просто используем хеш
			digest_info = hash.clone()
		}
	}

	// Теперь применяем PKCS#1 v1.5 padding
	return pkcs1_v15_pad(digest_info, key_size)
}

// PSS padding (заглушка)
fn pss_pad(hash []u8, hash_alg HashAlgorithm, key_size int) ![]u8 {
	// PSS требует сложной реализации с MGF и случайными байтами
	// Это упрощенная версия для совместимости
	return error('PSS padding not fully implemented. Use PKCS#1 v1.5 for now.')
}

fn pss_unpad(data []u8, hash_alg HashAlgorithm) ![]u8 {
	return error('PSS unpadding not fully implemented')
}
