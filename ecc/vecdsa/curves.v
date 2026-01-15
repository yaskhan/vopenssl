module vecdsa

import math.big

// P256 returns a Curve which implements P-256.
// P256 returns a Curve which implements P-256.
pub fn p256() Curve {
	return &CurveImpl{
		name: 'P-256'
		bit_size: 256
		p: big.integer_from_string('115792089210356248762697446949407573530086143415290314195533631308867097853951') or { panic(err) }
		n: big.integer_from_string('115792089210356248762697446949407573529996955224135760342422259061068512044369') or { panic(err) }
		a: big.integer_from_int(-3)
		b: big.integer_from_radix('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16) or { panic(err) }
		gx: big.integer_from_radix('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16) or { panic(err) }
		gy: big.integer_from_radix('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16) or { panic(err) }
	}
}

// P384 returns a Curve which implements P-384.
// P384 returns a Curve which implements P-384.
pub fn p384() Curve {
	return &CurveImpl{
		name: 'P-384'
		bit_size: 384
		p: big.integer_from_string('394020061963944792122790401001436138050797392704644919173168391083556927116357454392708111928391095494633346408501103') or { panic(err) }
		n: big.integer_from_string('394020061963944792122790401001436138050797392704644919173168391083556927116357454392708111928391147814330598517006851') or { panic(err) }
		a: big.integer_from_int(-3)
		b: big.integer_from_radix('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef', 16) or { panic(err) }
		gx: big.integer_from_radix('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7', 16) or { panic(err) }
		gy: big.integer_from_radix('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f', 16) or { panic(err) }
	}
}

// P521 returns a Curve which implements P-521.
// P521 returns a Curve which implements P-521.
pub fn p521() Curve {
	return &CurveImpl{
		name: 'P-521'
		bit_size: 521
		p: big.integer_from_string('6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151') or { panic(err) }
		n: big.integer_from_string('6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532931722754926024968023246473449343714154435503254181461') or { panic(err) }
		a: big.integer_from_int(-3)
		b: big.integer_from_radix('051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00', 16) or { panic(err) }
		gx: big.integer_from_radix('c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66', 16) or { panic(err) }
		gy: big.integer_from_radix('11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650', 16) or { panic(err) }
	}
}

pub fn (p &CurveImpl) params() &CurveImpl {
	return p
}

// is_on_curve reports whether the given (x,y) lies on the curve.
pub fn (p &CurveImpl) is_on_curve(x big.Integer, y big.Integer) bool {
    // y^2 = x^3 + ax + b
    y2 := mod(y * y, p.p)
    x3 := mod(x * x * x, p.p)
    ax := mod(p.a * x, p.p)
    rhs := mod(x3 + ax + p.b, p.p)
    return y2 == rhs
}

// add returns the sum of (x1,y1) and (x2,y2)
pub fn (p &CurveImpl) add(x1 big.Integer, y1 big.Integer, x2 big.Integer, y2 big.Integer) (big.Integer, big.Integer) {
    zero := big.integer_from_int(0)
    if x1 == zero && y1 == zero { return x2, y2 }
    if x2 == zero && y2 == zero { return x1, y1 }
    
    if x1 == x2 {
        if y1 == y2 {
            return p.double(x1, y1)
        }
        return big.integer_from_int(0), big.integer_from_int(0)
    }
    
    // slope m = (y2 - y1) / (x2 - x1)
    num := mod(y2 - y1, p.p)
    den := mod(x2 - x1, p.p)
    inv_den := den.mod_inverse(p.p) or { return big.integer_from_int(0), big.integer_from_int(0) }
    m := mod(num * inv_den, p.p)
    
    // x3 = m^2 - x1 - x2
    x3 := mod(m * m - x1 - x2, p.p)
    // y3 = m(x1 - x3) - y1
    y3 := mod(m * (x1 - x3) - y1, p.p)
    
    return x3, y3
}

fn (p &CurveImpl) double(x1 big.Integer, y1 big.Integer) (big.Integer, big.Integer) {
    zero := big.integer_from_int(0)
    if y1 == zero { return zero, zero }
    
    // slope m = (3x1^2 + a) / 2y1
    num := mod(big.integer_from_int(3) * x1 * x1 + p.a, p.p)
    den := mod(big.integer_from_int(2) * y1, p.p)
    inv_den := den.mod_inverse(p.p) or { return big.integer_from_int(0), big.integer_from_int(0) }
    m := mod(num * inv_den, p.p)
    
    // x3 = m^2 - 2x1
    x3 := mod(m * m - big.integer_from_int(2) * x1, p.p)
    // y3 = m(x1 - x3) - y1
    y3 := mod(m * (x1 - x3) - y1, p.p)
    
    return x3, y3
}

// scalar_mult returns k*(bx,by)
pub fn (p &CurveImpl) scalar_mult(bx big.Integer, by big.Integer, k []u8) (big.Integer, big.Integer) {
    mut rx := big.integer_from_int(0)
    mut ry := big.integer_from_int(0)
    
    mut bx_i := bx
    mut by_i := by
    
    // Iterate from LSB to MSB for the base doubling part or stay with this
    // This is right-to-left: k = sum(bi * 2^i)
    // I will iterate from the end of the byte slice (LSB)
    for i := k.len - 1; i >= 0; i-- {
        b := k[i]
        for j in 0..8 {
            if (b >> j) & 1 == 1 {
                rx, ry = p.add(rx, ry, bx_i, by_i)
            }
            bx_i, by_i = p.double(bx_i, by_i)
        }
    }
    return rx, ry
}

pub fn (p &CurveImpl) scalar_base_mult(k []u8) (big.Integer, big.Integer) {
    return p.scalar_mult(p.gx, p.gy, k)
}
