module ecc

// EllipticCurve определяет поддерживаемые эллиптические кривые
pub enum EllipticCurve {
	secp256r1  // NIST P-256
	secp384r1  // NIST P-384
	secp521r1  // NIST P-521
	x25519     // Curve25519 для ECDH
	ed25519    // Ed25519 для подписей (уже в vlib/crypto)
}

// CurveParams содержит параметры эллиптической кривой
pub struct CurveParams {
pub:
	name      string
	key_size  int      // размер ключа в битах
	field_p   []u8     // поле P
	a         []u8     // коэффициент a
	b         []u8     // коэффициент b
	gx        []u8     // точка G (x)
	gy        []u8     // точка G (y)
	n         []u8     // порядок подгруппы
	h         int      // cofactor
}

// get_curve_params возвращает параметры для указанной кривой
pub fn get_curve_params(curve EllipticCurve) !CurveParams {
	match curve {
		.secp256r1 {
			return CurveParams{
				name: 'secp256r1'
				key_size: 256
				// Параметры в big-endian формате
				// P = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
				field_p: hex_to_bytes('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
				a: hex_to_bytes('FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC')
				b: hex_to_bytes('5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B')
				gx: hex_to_bytes('6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296')
				gy: hex_to_bytes('4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5')
				n: hex_to_bytes('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551')
				h: 1
			}
		}
		.secp384r1 {
			return CurveParams{
				name: 'secp384r1'
				key_size: 384
				field_p: hex_to_bytes('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF00000000FFFFFFFFFFFFFFFF')
				a: hex_to_bytes('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF00000000FFFFFFFFFFFFFFFC')
				b: hex_to_bytes('B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF')
				gx: hex_to_bytes('AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7')
				gy: hex_to_bytes('3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F')
				n: hex_to_bytes('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973')
				h: 1
			}
		}
		.secp521r1 {
			return CurveParams{
				name: 'secp521r1'
				key_size: 521
				field_p: hex_to_bytes('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
				a: hex_to_bytes('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC')
				b: hex_to_bytes('0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00')
				gx: hex_to_bytes('00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66')
				gy: hex_to_bytes('011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650')
				n: hex_to_bytes('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47FBBF67F7C302ED07B1C70B0B5B6C30B1EC2B8A6D7C3B6E9E0B6D2C1B7C3B6E9E0B6D2C1B7')
				h: 1
			}
		}
		.x25519 {
			return CurveParams{
				name: 'x25519'
				key_size: 256
				field_p: hex_to_bytes('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED')
				a: hex_to_bytes('486662') // 486662
				b: hex_to_bytes('1') // 1
				gx: hex_to_bytes('9') // 9
				gy: hex_to_bytes('20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9')
				n: hex_to_bytes('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8B8D')
				h: 8
			}
		}
		else {
			return error('Curve ${curve} not supported')
		}
	}
}

// Вспомогательная функция для конвертации hex в bytes
fn hex_to_bytes(hex_str string) []u8 {
	mut result := []u8{}
	mut hex := hex_str
	if hex.starts_with('0x') || hex.starts_with('0X') {
		hex = hex[2..]
	}
	
	for i := 0; i < hex.len; i += 2 {
		if i + 1 < hex.len {
			byte_str := hex[i..i+2]
			result << u8(strconv_parse_int(byte_str, 16, 8) or { 0 })
		}
	}
	return result
}

// Простая реализация парсинга hex для V (без стандартной библиотеки)
fn strconv_parse_int(s string, base int, bit_size int) !int {
	mut result := 0
	for c in s {
		mut digit := 0
		if c >= `0` && c <= `9` {
			digit = int(c - `0`)
		} else if c >= `a` && c <= `f` {
			digit = int(c - `a` + 10)
		} else if c >= `A` && c <= `F` {
			digit = int(c - `A` + 10)
		} else {
			return error('invalid hex digit')
		}
		result = result * base + digit
	}
	return result
}
