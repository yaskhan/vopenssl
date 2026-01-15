module formats

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
	// SubjectPublicKeyInfo ::= SEQUENCE {
	//    algorithm            AlgorithmIdentifier,
	//    subjectPublicKey     BIT STRING
	// }
	// AlgorithmIdentifier ::= SEQUENCE {
	//    algorithm            OBJECT IDENTIFIER,
	//    parameters           ANY DEFINED BY algorithm OPTIONAL
	// }
	// RSAPublicKey ::= SEQUENCE {
	//    modulus              INTEGER, -- n
	//    publicExponent       INTEGER  -- e
	// }

	// 1. Encode RSAPublicKey (PKCS#1)
	mut rsa_pub_inner := []u8{}
	rsa_pub_inner << encode_integer(pub_key.n)
	rsa_pub_inner << encode_integer(pub_key.e)
	rsa_pub_der := encode_sequence([rsa_pub_inner])

	// 2. Encode AlgorithmIdentifier (rsaEncryption: 1.2.840.113549.1.1.1)
	mut alg_id_inner := []u8{}
	alg_id_inner << encode_oid([1, 2, 840, 113549, 1, 1, 1])
	alg_id_inner << encode_null()
	alg_id_der := encode_sequence([alg_id_inner])

	// 3. Encode SubjectPublicKeyInfo
	mut spki_inner := []u8{}
	spki_inner << alg_id_der
	spki_inner << encode_bit_string(rsa_pub_der)
	spki_der := encode_sequence([spki_inner])

	return pem_encode('PUBLIC KEY', {}, spki_der)
}

// decode_rsa_public_key_pem декодирует открытый ключ RSA из PEM
pub fn decode_rsa_public_key_pem(pem_str string) !rsa.RSAPublicKey {
	block := pem_decode(pem_str)!

	if block.type_ != 'PUBLIC KEY' && block.type_ != 'RSA PUBLIC KEY' {
		return error('Invalid PEM type for RSA public key: ${block.type_}')
	}

	if block.type_ == 'RSA PUBLIC KEY' {
		// PKCS#1 format: RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
		val := asn1_unmarshal(block.bytes)!
		if val is []ASN1Value {
			if val.len >= 2 {
				n_val := val[0]
				e_val := val[1]
				if n_val is []u8 && e_val is []u8 {
					return rsa.RSAPublicKey{
						n: n_val
						e: e_val
					}
				}
			}
		}
		return error('invalid PKCS#1 RSA public key')
	}

	// PKIX format: SubjectPublicKeyInfo
	val := asn1_unmarshal(block.bytes)!
	if val is []ASN1Value {
		// val[0] is AlgorithmIdentifier, val[1] is subjectPublicKey (BIT STRING)
		if val.len >= 2 {
			spki_val := val[1]
			if spki_val is []u8 {
				// spki_val is the DER-encoded RSAPublicKey (PKCS#1)
				inner_val := asn1_unmarshal(spki_val)!
				if inner_val is []ASN1Value {
					if inner_val.len >= 2 {
						n_val := inner_val[0]
						e_val := inner_val[1]
						if n_val is []u8 && e_val is []u8 {
							return rsa.RSAPublicKey{
								n: n_val
								e: e_val
							}
						}
					}
				}
			}
		}
	}

	return error('failed to parse RSA public key')
}

// encode_rsa_private_key_pem кодирует приватный ключ RSA в PEM формат (PKCS#1)
pub fn encode_rsa_private_key_pem(priv_key rsa.RSAPrivateKey) string {
	// PKCS#1 format: RSAPrivateKey ::= SEQUENCE {
	//    version           Version,
	//    modulus           INTEGER,  -- n
	//    publicExponent    INTEGER,  -- e
	//    privateExponent   INTEGER,  -- d
	//    prime1            INTEGER,  -- p
	//    prime2            INTEGER,  -- q
	//    exponent1         INTEGER,  -- d mod (p-1)
	//    exponent2         INTEGER,  -- d mod (q-1)
	//    coefficient       INTEGER,  -- q^-1 mod p
	//    otherPrimeInfos   OtherPrimeInfos OPTIONAL
	// }
	// Version ::= INTEGER { two-prime(0), multi(1) }

	mut items := [][]u8{}
	items << encode_integer([u8(0)]) // version 0
	items << encode_integer(priv_key.n)
	items << encode_integer(priv_key.e)
	items << encode_integer(priv_key.d)
	items << encode_integer(priv_key.p)
	items << encode_integer(priv_key.q)
	items << encode_integer(priv_key.dp)
	items << encode_integer(priv_key.dq)
	items << encode_integer(priv_key.qi)

	der := encode_sequence(items)
	return pem_encode('RSA PRIVATE KEY', {}, der)
}

// decode_rsa_private_key_pem декодирует приватный ключ RSA из PEM
pub fn decode_rsa_private_key_pem(pem_str string) !rsa.RSAPrivateKey {
	block := pem_decode(pem_str)!

	if block.type_ != 'PRIVATE KEY' && block.type_ != 'RSA PRIVATE KEY' {
		return error('Invalid PEM type for RSA private key: ${block.type_}')
	}

	// Assuming PKCS#1 for now
	val := asn1_unmarshal(block.bytes)!
	if val is []ASN1Value {
		// Expected items: version, n, e, d, p, q, dp, dq, qi
		if val.len >= 9 {
			n := val[1] as []u8
			e := val[2] as []u8
			d := val[3] as []u8
			p := val[4] as []u8
			q := val[5] as []u8
			dp := val[6] as []u8
			dq := val[7] as []u8
			qi := val[8] as []u8
			
			return rsa.RSAPrivateKey{
				n: n
				e: e
				d: d
				p: p
				q: q
				dp: dp
				dq: dq
				qi: qi
			}
		}
	}

	return error('failed to parse RSA private key')
}

// encode_ec_public_key_pem кодирует открытый ключ ECC в PEM формат
pub fn encode_ec_public_key_pem(pub_key ecc.ECPublicKey) string {
	// EC public key в формате SubjectPublicKeyInfo
	// AlgorithmIdentifier: id-ecPublicKey (1.2.840.10045.2.1)
	// Parameters: namedCurve OID

	curve_oid := match pub_key.curve {
		.secp256r1 { [1, 2, 840, 10045, 3, 1, 7] }
		.secp384r1 { [1, 3, 132, 0, 34] }
		.secp521r1 { [1, 3, 132, 0, 35] }
		.x25519 { [1, 3, 101, 110] }
		.ed25519 { [1, 3, 101, 112] }
	}

	mut alg_id_inner := []u8{}
	alg_id_inner << encode_oid([1, 2, 840, 10045, 2, 1]) // id-ecPublicKey
	alg_id_inner << encode_oid(curve_oid)
	alg_id_der := encode_sequence([alg_id_inner])

	mut pub_bytes := []u8{}
	if pub_key.curve in [.ed25519, .x25519] {
		pub_bytes = pub_key.x.clone()
	} else {
		pub_bytes << 0x04 // uncompressed
		pub_bytes << pub_key.x
		pub_bytes << pub_key.y
	}

	mut spki_inner := []u8{}
	spki_inner << alg_id_der
	spki_inner << encode_bit_string(pub_bytes)
	spki_der := encode_sequence([spki_inner])

	return pem_encode('PUBLIC KEY', {}, spki_der)
}

// decode_ec_public_key_pem декодирует открытый ключ ECC из PEM
pub fn decode_ec_public_key_pem(pem_str string) !ecc.ECPublicKey {
	block := pem_decode(pem_str)!

	if block.type_ != 'PUBLIC KEY' && block.type_ != 'EC PUBLIC KEY' {
		return error('Invalid PEM type for EC public key: ${block.type_}')
	}

	val := asn1_unmarshal(block.bytes)!
	if val is []ASN1Value {
		if val.len >= 2 {
			alg_id := val[0]
			pub_data := val[1]
			if alg_id is []ASN1Value && pub_data is []u8 {
				// Extraction logic for curve and coordinates
				// This is simplified, real implementation should check OIDs
				return ecc.ECPublicKey{
					curve: .secp256r1 // Placeholder for now, should parse OID
					x: pub_data
					y: []u8{}
				}
			}
		}
	}

	return error('failed to parse EC public key')
}

// encode_ec_private_key_pem кодирует приватный ключ ECC в PEM формат
pub fn encode_ec_private_key_pem(priv_key ecc.ECPrivateKey) string {
	// ECPrivateKey ::= SEQUENCE {
	//   version        INTEGER { ecPrivkeyVer1(1) } (1),
	//   privateKey     OCTET STRING,
	//   parameters [0] EXPLICIT ECDomainParameters OPTIONAL,
	//   publicKey  [1] EXPLICIT BIT STRING OPTIONAL
	// }

	curve_oid := match priv_key.curve {
		.secp256r1 { [1, 2, 840, 10045, 3, 1, 7] }
		.secp384r1 { [1, 3, 132, 0, 34] }
		.secp521r1 { [1, 3, 132, 0, 35] }
		.x25519 { [1, 3, 101, 110] }
		.ed25519 { [1, 3, 101, 112] }
	}

	mut items := [][]u8{}
	items << encode_integer([u8(1)]) // version 1
	
	mut octet_priv := []u8{}
	octet_priv << tag_octet_string
	octet_priv << encode_length(priv_key.private.len)
	octet_priv << priv_key.private
	items << octet_priv
	
	// parameters [0]
	mut params := []u8{}
	params << 0xa0 // context-specific tag 0
	oid_der := encode_oid(curve_oid)
	params << encode_length(oid_der.len)
	params << oid_der
	items << params

	// publicKey [1]
	mut pub_bytes := []u8{}
	if priv_key.curve in [.ed25519, .x25519] {
		pub_bytes = priv_key.public.x.clone()
	} else {
		pub_bytes << 0x04
		pub_bytes << priv_key.public.x
		pub_bytes << priv_key.public.y
	}
	mut pub_tag := []u8{}
	pub_tag << 0xa1 // context-specific tag 1
	bit_str := encode_bit_string(pub_bytes)
	pub_tag << encode_length(bit_str.len)
	pub_tag << bit_str
	items << pub_tag

	der := encode_sequence(items)
	return pem_encode('EC PRIVATE KEY', {}, der)
}

// decode_ec_private_key_pem декодирует приватный ключ ECC из PEM
pub fn decode_ec_private_key_pem(pem_str string) !ecc.ECPrivateKey {
	block := pem_decode(pem_str)!

	if block.type_ != 'PRIVATE KEY' && block.type_ != 'EC PRIVATE KEY' {
		return error('Invalid PEM type for EC private key: ${block.type_}')
	}

	val := asn1_unmarshal(block.bytes)!
	if val is []ASN1Value {
		if val.len >= 2 {
			priv_data := val[1]
			if priv_data is []u8 {
				return ecc.ECPrivateKey{
					curve: .secp256r1 // Placeholder
					private: priv_data
					public: ecc.ECPublicKey{
						curve: .secp256r1
						x: []u8{}
						y: []u8{}
					}
				}
			}
		}
	}

	return error('failed to parse EC private key')
}

// encode_ed25519_key_pair_pem кодирует пару ключей Ed25519 в PEM (PKCS#8)
pub fn encode_ed25519_key_pair_pem(key_pair ed25519.KeyPair) string {
	// PKCS#8 format for Ed25519
	// OneAsymmetricKey ::= SEQUENCE {
	//   version                   Version,
	//   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
	//   privateKey                CurvePrivateKey,
	//   ...
	// }
	// CurvePrivateKey ::= OCTET STRING

	mut alg_id_inner := []u8{}
	alg_id_inner << encode_oid([1, 3, 101, 112]) // ed25519
	alg_id_der := encode_sequence([alg_id_inner])

	// The private key itself is wrapped in an OCTET STRING inside the PKCS#8 OCTET STRING
	mut inner_priv := []u8{}
	inner_priv << tag_octet_string
	inner_priv << encode_length(key_pair.private.len)
	inner_priv << key_pair.private

	mut items := [][]u8{}
	items << encode_integer([u8(0)]) // version 0
	items << alg_id_der
	
	mut octet_priv := []u8{}
	octet_priv << tag_octet_string
	octet_priv << encode_length(inner_priv.len)
	octet_priv << inner_priv
	items << octet_priv

	der := encode_sequence(items)
	return pem_encode('PRIVATE KEY', {}, der)
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
