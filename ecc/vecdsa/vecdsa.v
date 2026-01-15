module vecdsa

import math.big
import crypto.sha256 as _ // Generic hash, will use for hash_to_int if needed

// CurveImpl contains the parameters of an elliptic curve.
@[heap]
pub struct CurveImpl {
pub:
	p       big.Integer // the order of the underlying field
	n       big.Integer // the order of the base point
	a       big.Integer // the constant a of the curve equation
	b       big.Integer // the constant b of the curve equation
	gx      big.Integer // x-coordinate of the base point
	gy      big.Integer // y-coordinate of the base point
	bit_size int        // the size of the underlying field, in bits
	name    string      // the canonical name of the curve
}

// Curve represents an elliptic curve.
pub interface Curve {
	params() &CurveImpl
	scalar_base_mult(k []u8) (big.Integer, big.Integer)
	scalar_mult(x big.Integer, y big.Integer, k []u8) (big.Integer, big.Integer)
	add(x1 big.Integer, y1 big.Integer, x2 big.Integer, y2 big.Integer) (big.Integer, big.Integer)
	is_on_curve(x big.Integer, y big.Integer) bool
}

// PublicKey represents an ECDSA public key.
pub struct PublicKey {
pub:
	curve Curve
	x     big.Integer
	y     big.Integer
}

// PrivateKey represents an ECDSA private key.
pub struct PrivateKey {
pub:
	public_key PublicKey
	d          big.Integer
}

// bytes encodes the public key as an uncompressed point according to SEC 1.
pub fn (pk PublicKey) bytes() []u8 {
	byte_len := (pk.curve.params().bit_size + 7) / 8
	mut res := []u8{len: 1 + 2 * byte_len}
	res[0] = 0x04 // uncompressed
	
	x_bytes, _ := pk.x.bytes()
	y_bytes, _ := pk.y.bytes()
	
	// Pad with leading zeros
	for i in 0 .. x_bytes.len {
		res[1 + byte_len - x_bytes.len + i] = x_bytes[i]
	}
	for i in 0 .. y_bytes.len {
		res[1 + 2 * byte_len - y_bytes.len + i] = y_bytes[i]
	}
	
	return res
}

// parse_uncompressed_public_key parses a public key encoded as an uncompressed point.
pub fn parse_uncompressed_public_key(curve Curve, data []u8) !PublicKey {
	byte_len := (curve.params().bit_size + 7) / 8
	if data.len != 1 + 2 * byte_len || data[0] != 0x04 {
		return error('invalid uncompressed public key')
	}
	
	x := big.integer_from_bytes(data[1 .. 1 + byte_len])
	y := big.integer_from_bytes(data[1 + byte_len .. 1 + 2 * byte_len])
	
	if !curve.is_on_curve(x, y) {
		return error('public key point is not on the curve')
	}
	
	return PublicKey{
		curve: curve
		x: x
		y: y
	}
}

// bytes encodes the private key as a fixed-length big-endian integer.
pub fn (priv PrivateKey) bytes() []u8 {
	byte_len := (priv.public_key.curve.params().bit_size + 7) / 8
	mut res := []u8{len: byte_len}
	d_bytes, _ := priv.d.bytes()
	
	// Pad with leading zeros
	if d_bytes.len <= byte_len {
		for i in 0 .. d_bytes.len {
			res[byte_len - d_bytes.len + i] = d_bytes[i]
		}
	} else {
		// This should not happen if the key is valid, but for safety:
		return d_bytes[d_bytes.len - byte_len ..]
	}
	return res
}

// Equals reports whether pk and x have the same value.
pub fn (pk PublicKey) equals(other PublicKey) bool {
	return pk.x == other.x && pk.y == other.y && pk.curve.params().name == other.curve.params().name
}

// Equals reports whether sk and x have the same value.
pub fn (sk PrivateKey) equals(other PrivateKey) bool {
	return sk.public_key.equals(other.public_key) && sk.d == other.d
}
