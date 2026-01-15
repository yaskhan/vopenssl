module ecc

import math.big
import crypto.sha512

// Point represents a point on the Edwards curve Ed25519
// -x^2 + y^2 = 1 - (121665/121666)x^2y^2 mod p
// Ref: RFC 8032
pub struct Point {
pub mut:
	x big.Integer
	y big.Integer
	z big.Integer
	t big.Integer
}

const (
	p_hex = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"
	d_hex = "52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3" // d = -121665/121666 mod p
	l_hex = "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED" // order of base point
)

fn get_p() big.Integer {
	return big.integer_from_radix(p_hex, 16) or { panic(err) }
}

fn get_d() big.Integer {
	return big.integer_from_radix(d_hex, 16) or { panic(err) }
}

fn get_l() big.Integer {
	return big.integer_from_radix(l_hex, 16) or { panic(err) }
}

// identity returns the identity point (0, 1)
pub fn identity() Point {
	return Point{
		x: big.integer_from_int(0)
		y: big.integer_from_int(1)
		z: big.integer_from_int(1)
		t: big.integer_from_int(0)
	}
}

// base_point returns the Ed25519 base point G
pub fn base_point() Point {
	p := get_p()
	y_hex := "6666666666666666666666666666666666666666666666666666666666666658"
	y := big.integer_from_radix(y_hex, 16) or { panic(err) }
	// x = sqrt((y^2 - 1) / (d*y^2 + 1)) mod p
	// For G, x is 15112221349535400772501151409588531511454012693041857206046113283949847762202
	x_hex := "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
	x := big.integer_from_radix(x_hex, 16) or { panic(err) }
	return Point{
		x: x
		y: y
		z: big.integer_from_int(1)
		t: (x * y) % p
	}
}

// edwards_add adds two points on the Edwards curve
pub fn (p1 Point) add(p2 Point) Point {
	p := get_p()
	d := get_d()
	
	a := ((p1.y - p1.x) * (p2.y - p2.x)) % p
	b := ((p1.y + p1.x) * (p2.y + p2.x)) % p
	c := (p1.t * big.integer_from_int(2) * d * p2.t) % p
	d_val := (p1.z * big.integer_from_int(2) * p2.z) % p
	
	e := (b - a) % p
	f := (d_val - c) % p
	g := (d_val + c) % p
	h := (b + a) % p
	
	return Point{
		x: (e * f) % p
		y: (g * h) % p
		z: (f * g) % p
		t: (e * h) % p
	}
}

// edwards_double doubles a point on the Edwards curve
pub fn (p1 Point) double() Point {
	p := get_p()
	
	a := (p1.x * p1.x) % p
	b := (p1.y * p1.y) % p
	c := (big.integer_from_int(2) * p1.z * p1.z) % p
	d_val := (p - a) % p
	e := ((p1.x + p1.y) * (p1.x + p1.y) - a - b) % p
	g := (d_val + b) % p
	f := (g - c) % p
	h := (d_val - b) % p
	
	return Point{
		x: (e * f) % p
		y: (g * h) % p
		z: (f * g) % p
		t: (e * h) % p
	}
}

// scalar_mult performs scalar multiplication (k * P)
pub fn (p1 Point) scalar_mult(k big.Integer) Point {
	mut res := identity()
	mut base := p1
	mut scalar := k
	zero := big.integer_from_int(0)
	two := big.integer_from_int(2)
	
	for scalar > zero {
		if (scalar % two) != zero {
			res = res.add(base)
		}
		base = base.double()
		scalar = scalar / two
	}
	return res
}

// encode converts a point to a 32-byte array
pub fn (p1 Point) encode() []u8 {
	p := get_p()
	z_inv := p1.z.mod_inverse(p) or { big.integer_from_int(0) }
	x := (p1.x * z_inv) % p
	y := (p1.y * z_inv) % p
	
	mut bytes, _ := y.bytes()
	if bytes.len < 32 {
		mut padded := []u8{len: 32, init: 0}
		for i in 0 .. bytes.len {
			padded[32 - bytes.len + i] = bytes[i]
		}
		bytes = padded.clone()
	} else if bytes.len > 32 {
		bytes = bytes[bytes.len-32..]
	}
	
	bytes.reverse_in_place()
	
	if (x % big.integer_from_int(2)) != big.integer_from_int(0) {
		bytes[31] |= 0x80
	}
	
	return bytes
}

// sign_eddsa_ctx implements EdDSA with context (RFC 8032)
pub fn sign_eddsa_ctx(private_key []u8, message []u8, context []u8, ph u8) ![]u8 {
	if private_key.len != 32 {
		return error("Invalid private key length")
	}
	
	// 1. Hash the private key
	h := sha512.sum512(private_key)
	mut s_bytes := h[..32].clone()
	s_bytes[0] &= 248
	s_bytes[31] &= 127
	s_bytes[31] |= 64
	
	// Little endian integer s
	mut s_le := s_bytes.clone()
	s_le.reverse_in_place()
	s := big.integer_from_bytes(s_le)
	
	prefix := h[32..]
	
	// 2. Compute public key A = s * G
	a_point := base_point().scalar_mult(s)
	a_bytes := a_point.encode()
	
	// 3. Compute r = H(dom2(ph, context) || prefix || M)
	mut dom := []u8{}
	if context.len > 0 || ph > 0 {
		dom = dom2(ph, context)
	}
	
	mut r_data := dom.clone()
	r_data << prefix
	r_data << message
	
	r_hash := sha512.sum512(r_data)
	mut r_le := r_hash.clone()
	r_le.reverse_in_place()
	r := big.integer_from_bytes(r_le)
	
	// 4. Compute R = r * G
	r_point := base_point().scalar_mult(r)
	r_bytes := r_point.encode()
	
	// 5. Compute k = H(dom2(ph, context) || R || A || M)
	mut k_data := dom.clone()
	k_data << r_bytes
	k_data << a_bytes
	k_data << message
	
	k_hash := sha512.sum512(k_data)
	mut k_le := k_hash.clone()
	k_le.reverse_in_place()
	k := big.integer_from_bytes(k_le)
	
	// 6. Compute S = (r + k * s) mod L
	l := get_l()
	s_val := (r + (k * s)) % l
	
	// 7. Signature is R || S
	mut sig := r_bytes.clone()
	mut s_final_bytes, _ := s_val.bytes()
	if s_final_bytes.len < 32 {
		mut padded := []u8{len: 32, init: 0}
		for i in 0 .. s_final_bytes.len {
			padded[32 - s_final_bytes.len + i] = s_final_bytes[i]
		}
		s_final_bytes = padded.clone()
	} else if s_final_bytes.len > 32 {
		s_final_bytes = s_final_bytes[s_final_bytes.len-32..]
	}
	s_final_bytes.reverse_in_place()
	sig << s_final_bytes
	
	return sig
}

fn dom2(x u8, y []u8) []u8 {
	mut res := "SigEd25519 no Ed25519 collisions".bytes()
	res << x
	res << u8(y.len)
	res << y
	return res
}
