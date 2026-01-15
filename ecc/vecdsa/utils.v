module vecdsa

import math.big
import rand
import formats

// hash_to_int converts a hash value to an integer.
// Per FIPS 186-4, Section 6.4, we use the left-most bits of the hash to match 
// the bit-length of the order of the curve.
pub fn hash_to_int(hash []u8, c Curve) big.Integer {
	order_bits := c.params().n.bit_len()
	order_bytes := (order_bits + 7) / 8
	
	mut refined_hash := hash.clone()
	if refined_hash.len > order_bytes {
		refined_hash = refined_hash[..order_bytes]
	}

	mut ret := big.integer_from_bytes(refined_hash)
	excess := refined_hash.len * 8 - order_bits
	if excess > 0 {
		ret = ret.right_shift(u32(excess))
	}
	return ret
}

// mod returns a % n and ensuring the result is in [0, n).
pub fn mod(a big.Integer, n big.Integer) big.Integer {
	res := a % n
	zero := big.integer_from_int(0)
	if res < zero {
		return res + n
	}
	return res
}

// rand_field_element returns a random element of the order of the given
// curve using the procedure given in FIPS 186-4, Appendix B.5.2.
pub fn rand_field_element(c Curve) !big.Integer {
	params := c.params()
	n := params.n
	byte_len := (n.bit_len() + 7) / 8
	zero := big.integer_from_int(0)
	for {
		b := rand.bytes(byte_len) or { return err }
		mut k := big.integer_from_bytes(b)
		excess := byte_len * 8 - n.bit_len()
		if excess > 0 {
			k = k.right_shift(u32(excess))
		}
		if k != zero && k < n {
			return k
		}
	}
	return error('failed to generate random field element')
}

// encode_asn1_signature encodes r and s into a DER-encoded ASN.1 SEQUENCE.
pub fn encode_asn1_signature(r big.Integer, s big.Integer) []u8 {
	r_bytes := to_asn1_int(r)
	s_bytes := to_asn1_int(s)
	
	mut body := []u8{}
	body << 0x02 // Tag: INTEGER
	body << u8(r_bytes.len)
	body << r_bytes
	
	body << 0x02 // Tag: INTEGER
	body << u8(s_bytes.len)
	body << s_bytes
	
	mut res := []u8{}
	res << 0x30 // Tag: SEQUENCE
	res << u8(body.len)
	res << body
	
	return res
}

fn to_asn1_int(n big.Integer) []u8 {
	mut b, _ := n.bytes()
	// ASN.1 integers are signed. If the high bit is set, prepend 0x00 to keep it positive.
	if b.len > 0 && (b[0] & 0x80) != 0 {
		mut res := []u8{len: b.len + 1}
		res[0] = 0x00
		for i in 0 .. b.len {
			res[i+1] = b[i]
		}
		return res
	}
	// If it's zero or empty
	if b.len == 0 {
		return [u8(0)]
	}
	return b
}

// decode_asn1_signature decodes a DER-encoded ASN.1 SEQUENCE into r and s.
pub fn decode_asn1_signature(sig []u8) !(big.Integer, big.Integer) {
	val := formats.asn1_unmarshal(sig)!
	if val is []formats.ASN1Value {
		if val.len != 2 {
			return error('invalid ASN.1 signature: expected 2 elements in sequence')
		}
		r := asn1_to_big(val[0])!
		s := asn1_to_big(val[1])!
		return r, s
	}
	return error('invalid ASN.1 signature: expected sequence')
}

fn asn1_to_big(val formats.ASN1Value) !big.Integer {
	if val is []u8 {
		return big.integer_from_bytes(val)
	} else if val is i64 {
		return big.integer_from_int(int(val))
	}
	return error('invalid ASN.1 element: expected integer')
}
