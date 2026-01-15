module cipher

// ghash_mul performs multiplication in GF(2^128) as defined in SP 800-38D
fn ghash_mul(mut x []u8, y []u8) {
	mut v := []u8{len: 16}
	copy(mut v, y)
	mut z := []u8{len: 16} // initialized to zero

	for i in 0 .. 128 {
		if (x[i / 8] & (u8(1) << (7 - (i % 8)))) != 0 {
			for j in 0 .. 16 {
				z[j] ^= v[j]
			}
		}
		
		mut carry := (v[15] & 1) != 0
		for j := 15; j > 0; j-- {
			v[j] = (v[j] >> 1) | (v[j - 1] << 7)
		}
		v[0] >>= 1
		
		if carry {
			v[0] ^= 0xe1
		}
	}
	copy(mut x, z)
}

// GHASH computes the GHASH of X given hash subkey H
fn ghash(h []u8, x []u8) []u8 {
	mut y := []u8{len: 16} // Y_0
	m := x.len / 16
	
	for i in 0 .. m {
		mut block := x[i * 16 .. (i + 1) * 16].clone()
		for j in 0 .. 16 {
			y[j] ^= block[j]
		}
		ghash_mul(mut y, h)
	}
	
	return y
}
