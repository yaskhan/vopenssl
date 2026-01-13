module encoding

import os
import vopenssl.rsa
import vopenssl.ecc
import vopenssl.ed25519

// RSAKeyFormat определяет формат ключа
pub enum RSAKeyFormat {
	pem
	der
}

// encode_rsa_public_key_pem кодирует открытый ключ RSA в PEM формат
pub fn encode_rsa_public_key_pem(pub_key rsa.RSAPublicKey) string {
	// PKIX формат для открытого ключа RSA
	// ASN.1 structure: SubjectPublicKeyInfo
	// Для фазы 1: заглушка, возвращает PEM с маркером
	// Полная реализация требует ASN.1 DER кодировки

	// Временная реализация - кодируем в простом формате
	mut der := []u8{}
	der << pub_key.n
	der << pub_key.e

	return pem_encode('PUBLIC KEY', {}, der)
}

// decode_rsa_public_key_pem декодирует открытый ключ RSA из PEM
pub fn decode_rsa_public_key_pem(pem_str string) !rsa.RSAPublicKey {
	block := pem_decode(pem_str)!

	if block.type_ != 'PUBLIC KEY' && block.type_ != 'RSA PUBLIC KEY' {
		return error('Invalid PEM type for RSA public key: ${block.type_}')
	}

	// Для фазы 1: заглушка
	// Полная реализация требует ASN.1 DER парсинга
	return error('RSA public key decoding requires ASN.1 parsing. Not fully implemented in Phase 1.')
}

// encode_rsa_private_key_pem кодирует приватный ключ RSA в PEM формат (PKCS#1)
pub fn encode_rsa_private_key_pem(priv_key rsa.RSAPrivateKey) string {
	// PKCS#1 format для приватного ключа RSA
	// ASN.1 structure: RSAPrivateKey

	// Временная реализация
	mut der := []u8{}
	der << priv_key.n
	der << priv_key.e
	der << priv_key.d
	der << priv_key.p
	der << priv_key.q
	der << priv_key.dp
	der << priv_key.dq
	der << priv_key.qi

	return pem_encode('RSA PRIVATE KEY', {}, der)
}

// decode_rsa_private_key_pem декодирует приватный ключ RSA из PEM
pub fn decode_rsa_private_key_pem(pem_str string) !rsa.RSAPrivateKey {
	block := pem_decode(pem_str)!

	if block.type_ != 'PRIVATE KEY' && block.type_ != 'RSA PRIVATE KEY' {
		return error('Invalid PEM type for RSA private key: ${block.type_}')
	}

	return error('RSA private key decoding requires ASN.1 parsing. Not fully implemented in Phase 1.')
}

// encode_ec_public_key_pem кодирует открытый ключ ECC в PEM формат
pub fn encode_ec_public_key_pem(pub_key ecc.ECPublicKey) string {
	// EC public key в формате SubjectPublicKeyInfo
	mut der := []u8{}
	der << pub_key.x
	if pub_key.y.len > 0 {
		der << pub_key.y
	}

	return pem_encode('PUBLIC KEY', {}, der)
}

// decode_ec_public_key_pem декодирует открытый ключ ECC из PEM
pub fn decode_ec_public_key_pem(pem_str string) !ecc.ECPublicKey {
	block := pem_decode(pem_str)!

	if block.type_ != 'PUBLIC KEY' && block.type_ != 'EC PUBLIC KEY' {
		return error('Invalid PEM type for EC public key: ${block.type_}')
	}

	return error('EC public key decoding requires ASN.1 parsing. Not fully implemented in Phase 1.')
}

// encode_ec_private_key_pem кодирует приватный ключ ECC в PEM формат
pub fn encode_ec_private_key_pem(priv_key ecc.ECPrivateKey) string {
	// EC private key в формате PKCS#8 или SEC1
	mut der := []u8{}
	der << priv_key.private
	der << priv_key.public.x
	if priv_key.public.y.len > 0 {
		der << priv_key.public.y
	}

	return pem_encode('EC PRIVATE KEY', {}, der)
}

// decode_ec_private_key_pem декодирует приватный ключ ECC из PEM
pub fn decode_ec_private_key_pem(pem_str string) !ecc.ECPrivateKey {
	block := pem_decode(pem_str)!

	if block.type_ != 'PRIVATE KEY' && block.type_ != 'EC PRIVATE KEY' {
		return error('Invalid PEM type for EC private key: ${block.type_}')
	}

	return error('EC private key decoding requires ASN.1 parsing. Not fully implemented in Phase 1.')
}

// encode_ed25519_key_pair_pem кодирует пару ключей Ed25519 в PEM
pub fn encode_ed25519_key_pair_pem(key_pair ed25519.KeyPair) string {
	// Ed25519 в формате OpenSSH или PKCS#8
	mut der := []u8{}
	der << key_pair.private
	der << key_pair.public

	return pem_encode('OPENSSH PRIVATE KEY', {}, der)
}

// generate_key_pair_pem генерирует ключевую пару и возвращает в PEM формате
pub fn generate_key_pair_pem(key_size rsa.RSAKeySize) !(string, string) {
	key_pair := rsa.generate_key_pair(key_size)!

	priv_pem := encode_rsa_private_key_pem(key_pair.private)
	pub_pem := encode_rsa_public_key_pem(key_pair.public)

	return priv_pem, pub_pem
}

// save_key_to_file сохраняет ключ в файл в PEM формате
pub fn save_key_to_file(key_type string, data []u8, filename string) ! {
	pem_str := match key_type {
		'rsa_public' { pem_encode('PUBLIC KEY', {}, data) }
		'rsa_private' { pem_encode('RSA PRIVATE KEY', {}, data) }
		'ec_public' { pem_encode('PUBLIC KEY', {}, data) }
		'ec_private' { pem_encode('EC PRIVATE KEY', {}, data) }
		'ed25519' { pem_encode('OPENSSH PRIVATE KEY', {}, data) }
		else { return error('Unknown key type') }
	}

	os.write_file(filename, pem_str)!
}

// load_key_from_file загружает ключ из PEM файла
pub fn load_key_from_file(filename string) !(string, []u8) {
	pem_str := os.read_file(filename)!
	block := pem_decode(pem_str)!
	return block.type_, block.bytes
}
