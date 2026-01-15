module vecdsa

import math.big
import crypto.rand as _

// generate_key generates a new ECDSA private key for the specified curve.
pub fn generate_key(c Curve) !PrivateKey {
    k := rand_field_element(c)!
    k_bytes, _ := k.bytes()
    x, y := c.scalar_base_mult(k_bytes)
    
    return PrivateKey{
        d: k
        public_key: PublicKey{
            curve: c
            x: x
            y: y
        }
    }
}

// sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. It returns the signature as a pair of integers.
pub fn sign(priv &PrivateKey, hash []u8) !(big.Integer, big.Integer) {
    c := priv.public_key.curve
    n := c.params().n
    zero := big.integer_from_int(0)
    if n == zero {
        return error('zero parameter')
    }
    
    mut r := big.integer_from_int(0)
    mut s := big.integer_from_int(0)
    // zero is already defined above
    
    for {
        mut k := big.integer_from_int(0)
        for {
            k = rand_field_element(c)!
            k_inv := k.mod_inverse(n) or { continue }
            
            k_bytes, _ := k.bytes()
            rx, _ := c.scalar_base_mult(k_bytes)
            r = mod(rx, n)
            if r != zero {
                // We found a good k
                e := hash_to_int(hash, c)
                // s = k^-1 * (e + r*d) mod n
                rd := mod(r * priv.d, n)
                erd := mod(e + rd, n)
                s = mod(k_inv * erd, n)
                if s != zero {
                    return r, s
                }
            }
        }
    }
    return error('unreachable')
}

// verify verifies the signature in r, s of hash using the public key, pk.
pub fn verify(pk &PublicKey, hash []u8, r big.Integer, s big.Integer) bool {
    zero := big.integer_from_int(0)
    if r <= zero || s <= zero {
        return false
    }
    
    c := pk.curve
    n := c.params().n
    
    if r >= n || s >= n {
        return false
    }
    
    // e = hash_to_int(hash)
    e := hash_to_int(hash, c)
    // w = s^-1 mod n
    w := s.mod_inverse(n) or { return false }
    
    // u1 = e * w mod n
    u1 := mod(e * w, n)
    // u2 = r * w mod n
    u2 := mod(r * w, n)
    
    // x, y = u1*G + u2*pk
    u1_bytes, _ := u1.bytes()
    u2_bytes, _ := u2.bytes()
    x1, y1 := c.scalar_base_mult(u1_bytes)
    x2, y2 := c.scalar_mult(pk.x, pk.y, u2_bytes)
    x, _ := c.add(x1, y1, x2, y2)
    
    if x == zero {
        return false
    }
    
    v := mod(x, n)
    return v == r
}

// sign_asn1 signs a hash using the private key and returns the ASN.1 encoded signature.
pub fn sign_asn1(priv &PrivateKey, hash []u8) ![]u8 {
	r, s := sign(priv, hash)!
	return encode_asn1_signature(r, s)
}

// verify_asn1 verifies the ASN.1 encoded signature of hash using the public key pk.
pub fn verify_asn1(pk &PublicKey, hash []u8, sig []u8) bool {
	r, s := decode_asn1_signature(sig) or { return false }
	return verify(pk, hash, r, s)
}
