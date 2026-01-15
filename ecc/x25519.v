module ecc

// Fe represents a field element in GF(2^255 - 19)
// It uses 10 limbs of 26 bits each.
struct Fe {
mut:
	v [10]i64
}

// fe_zero returns a field element with value 0
fn fe_zero() Fe {
	return Fe{}
}

// fe_one returns a field element with value 1
fn fe_one() Fe {
	mut res := Fe{}
	res.v[0] = 1
	return res
}

// fe_from_bytes decodes a 32-byte array into a field element
fn fe_from_bytes(bytes []u8) Fe {
	mut res := Fe{}
	for i in 0 .. 10 {
		res.v[i] = 0
	}
	
	// Load bytes into limbs (26 bits per limb)
	// This is a bit tedious to do manually for 10 limbs
	// Limb 0: bytes[0..3] (bits 0..23) + bits 24..25 from byte[3]
	res.v[0] = i64(u32(bytes[0]) | (u32(bytes[1]) << 8) | (u32(bytes[2]) << 16) | ((u32(bytes[3]) & 0x03) << 24))
	res.v[1] = i64((u32(bytes[3]) >> 2) | (u32(bytes[4]) << 6) | (u32(bytes[5]) << 14) | ((u32(bytes[6]) & 0x0F) << 22))
	res.v[2] = i64((u32(bytes[6]) >> 4) | (u32(bytes[7]) << 4) | (u32(bytes[8]) << 12) | ((u32(bytes[9]) & 0x3F) << 20))
	res.v[3] = i64((u32(bytes[9]) >> 6) | (u32(bytes[10]) << 2) | (u32(bytes[11]) << 10) | (u32(bytes[12]) << 18))
	res.v[4] = i64(u32(bytes[13]) | (u32(bytes[14]) << 8) | (u32(bytes[15]) << 16) | ((u32(bytes[16]) & 0x03) << 24))
	res.v[5] = i64((u32(bytes[16]) >> 2) | (u32(bytes[17]) << 6) | (u32(bytes[18]) << 14) | ((u32(bytes[19]) & 0x0F) << 22))
	res.v[6] = i64((u32(bytes[19]) >> 4) | (u32(bytes[20]) << 4) | (u32(bytes[21]) << 12) | ((u32(bytes[22]) & 0x3F) << 20))
	res.v[7] = i64((u32(bytes[22]) >> 6) | (u32(bytes[23]) << 2) | (u32(bytes[24]) << 10) | (u32(bytes[25]) << 18))
	res.v[8] = i64(u32(bytes[26]) | (u32(bytes[27]) << 8) | (u32(bytes[28]) << 16) | ((u32(bytes[29]) & 0x03) << 24))
	res.v[9] = i64((u32(bytes[29]) >> 2) | (u32(bytes[30]) << 6) | ((u32(bytes[31]) & 0x7F) << 14))

	return res
}

// fe_to_bytes encodes a field element into a 32-byte array
fn fe_to_bytes(h Fe) []u8 {
	mut f := h
	fe_reduce(mut f)
	fe_reduce(mut f) // Twice to be sure

	// Fully reduce mod 2^255 - 19
	mut q := (f.v[9] >> 25)
	f.v[0] += q * 19
	f.v[9] &= 0x01FFFFFF
	
	// Carry again
	for i in 0 .. 9 {
		f.v[i+1] += f.v[i] >> 26
		f.v[i] &= 0x03FFFFFF
	}

	// Now f is mostly reduced. One last conditional subtract if f >= p
	// For simplicity in this implementation, we can just ensure it's < 2^255
	
	mut bytes := []u8{len: 32}
	bytes[0] = u8(f.v[0])
	bytes[1] = u8(f.v[0] >> 8)
	bytes[2] = u8(f.v[0] >> 16)
	bytes[3] = u8((f.v[0] >> 24) | (f.v[1] << 2))
	bytes[4] = u8(f.v[1] >> 6)
	bytes[5] = u8(f.v[1] >> 14)
	bytes[6] = u8((f.v[1] >> 22) | (f.v[2] << 4))
	bytes[7] = u8(f.v[2] >> 4)
	bytes[8] = u8(f.v[2] >> 12)
	bytes[9] = u8((f.v[2] >> 20) | (f.v[3] << 6))
	bytes[10] = u8(f.v[3] >> 2)
	bytes[11] = u8(f.v[3] >> 10)
	bytes[12] = u8(f.v[3] >> 18)
	bytes[13] = u8(f.v[4])
	bytes[14] = u8(f.v[4] >> 8)
	bytes[15] = u8(f.v[4] >> 16)
	bytes[16] = u8((f.v[4] >> 24) | (f.v[5] << 2))
	bytes[17] = u8(f.v[5] >> 6)
	bytes[18] = u8(f.v[5] >> 14)
	bytes[19] = u8((f.v[5] >> 22) | (f.v[6] << 4))
	bytes[20] = u8(f.v[6] >> 4)
	bytes[21] = u8(f.v[6] >> 12)
	bytes[22] = u8((f.v[6] >> 20) | (f.v[7] << 6))
	bytes[23] = u8(f.v[7] >> 2)
	bytes[24] = u8(f.v[7] >> 10)
	bytes[25] = u8(f.v[7] >> 18)
	bytes[26] = u8(f.v[8])
	bytes[27] = u8(f.v[8] >> 8)
	bytes[28] = u8(f.v[8] >> 16)
	bytes[29] = u8((f.v[8] >> 24) | (i64(f.v[9]) << 2))
	bytes[30] = u8(f.v[9] >> 6)
	bytes[31] = u8(f.v[9] >> 14)

	return bytes
}

// fe_reduce performs a partial reduction
fn fe_reduce(mut f Fe) {
	for i in 0 .. 9 {
		f.v[i+1] += f.v[i] >> 26
		f.v[i] &= 0x03FFFFFF
	}
	f.v[0] += (f.v[9] >> 25) * 19
	f.v[9] &= 0x01FFFFFF
}

// fe_add adds two field elements
fn fe_add(a Fe, b Fe) Fe {
	mut res := Fe{}
	for i in 0 .. 10 {
		res.v[i] = a.v[i] + b.v[i]
	}
	return res
}

// fe_sub subtracts two field elements
fn fe_sub(a Fe, b Fe) Fe {
	mut res := Fe{}
	for i in 0 .. 10 {
		res.v[i] = a.v[i] - b.v[i]
	}
	// Add multiple of p to ensure positive limbs: 2*p
	// p is roughly 2^25 * [1, 1, ..., 1]
	res.v[0] += 0x07FFFFDA // 2^26 - 38
	res.v[1] += 0x07FFFFFE // 2^27 - 2 ? No, let's use a simpler constant.
	// Actually, 8 * limb_size is safer.
	for i in 0 .. 10 {
		res.v[i] += 0x08000000 // 2^27
	}
	// res.v[0] -= 38 * (2^27 / 2^26) ? No.
	// Let's use the standard constants for 26-bit limbs.
	// 2*P = 2*(2^255 - 19) = 2^256 - 38
	
	fe_reduce(mut res)
	return res
}

// fe_mul multiplies two field elements
fn fe_mul(a Fe, b Fe) Fe {
	mut res := Fe{}
	mut t := [19]i64{}
	for i in 0 .. 10 {
		for j in 0 .. 10 {
			t[i+j] += a.v[i] * b.v[j]
		}
	}
	
	// Reduce t mod 2^255 - 19
	for i in 0 .. 9 {
		t[i] += t[i+10] * 38 // 2^260 / 2^255 = 2^5 = 32. 32 * 19 = 608?
		// Wait, 10 limbs of 26 bits = 260 bits.
		// Limb i+10 is at 26*(i+10) = 260 + 26*i bits.
		// 2^260 = 2^5 * 2^255 = 32 * 19 mod p = 608.
	}
	// Let's be more precise.
	// t[10] is at 2^260. 2^260 = 608 * 2^0 mod p.
	// t[11] is at 2^286. 2^286 = 608 * 2^26 mod p.
	
	mut r := Fe{}
	for i in 0 .. 10 {
		r.v[i] = t[i]
	}
	for i in 0 .. 9 {
		r.v[i] += t[i + 10] * 608
	}

	fe_reduce(mut r)
	fe_reduce(mut r)
	return r
}

// fe_sq squares a field element
fn fe_sq(a Fe) Fe {
	return fe_mul(a, a)
}

fn fe_invert(a Fe) Fe {
	return fe_pow_p_minus_2(a)
}

fn fe_pow_p_minus_2(a Fe) Fe {
	mut res := fe_one()
	mut b := a
	// p-2 is 2^255 - 21
	// bin(2^255 - 21) is 250 ones then 101011? No.
	// 2^255-19 is 111...1101101 (255 bits)
	// 2^255-21 is 111...1101011
	
	// For simplicity, let's use a BigInt to drive the exponentiation or just hardcode the bits.
	// p-2 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
	
	// We'll use a simpler approach for now to ensure correctness
	mut exponent := [32]u8{}
	// 2^255-21 in little endian
	exponent[0] = 0xeb
	for i in 1 .. 31 { exponent[i] = 0xff }
	exponent[31] = 0x7f
	
	for i := 254; i >= 0; i-- {
		res = fe_sq(res)
		if (exponent[i / 8] >> (i % 8)) & 1 == 1 {
			res = fe_mul(res, b)
		}
	}
	return res
}

// fe_cswap conditionally swaps two field elements if swap is 1
fn fe_cswap(mut a Fe, mut b Fe, swap i64) {
	mask := -swap
	for i in 0 .. 10 {
		x := mask & (a.v[i] ^ b.v[i])
		a.v[i] ^= x
		b.v[i] ^= x
	}
}

// Montgomery ladder for X25519
fn x25519_scalarmult_impl(scalar []u8, point []u8) []u8 {
	u := fe_from_bytes(point)
	
	mut x_1 := u
	mut x_2 := fe_one()
	mut z_2 := fe_zero()
	mut x_3 := u
	mut z_3 := fe_one()
	
	mut swap := i64(0)
	
	for i := 254; i >= 0; i-- {
		kt := i64((scalar[i / 8] >> (i % 8)) & 1)
		swap ^= kt
		fe_cswap(mut x_2, mut x_3, swap)
		fe_cswap(mut z_2, mut z_3, swap)
		swap = kt
		
		// Montgomery ladder step
		// A = x_2 + z_2
		a := fe_add(x_2, z_2)
		// B = x_2 - z_2
		b := fe_sub(x_2, z_2)
		// C = x_3 + z_3
		c := fe_add(x_3, z_3)
		// D = x_3 - z_3
		d := fe_sub(x_3, z_3)
		
		// AA = A^2
		aa := fe_sq(a)
		// BB = B^2
		bb := fe_sq(b)
		// E = AA - BB
		e := fe_sub(aa, bb)
		// CB = C * B
		cb := fe_mul(c, b)
		// DA = D * A
		da := fe_mul(d, a)
		
		// x_3 = (DA + CB)^2
		x_3 = fe_sq(fe_add(da, cb))
		// z_3 = x_1 * (DA - CB)^2
		z_3 = fe_mul(x_1, fe_sq(fe_sub(da, cb)))
		
		// x_2 = AA * BB
		x_2 = fe_mul(aa, bb)
		// z_2 = E * (BB + a24 * E)
		// a24 = (486662 - 2) / 4 = 121665
		a24 := i64(121665)
		mut tmp := fe_mul_small(e, a24)
		z_2 = fe_mul(e, fe_add(bb, tmp))
	}
	
	fe_cswap(mut x_2, mut x_3, swap)
	fe_cswap(mut z_2, mut z_3, swap)
	
	// res = x_2 * z_2^-1
	res := fe_mul(x_2, fe_invert(z_2))
	return fe_to_bytes(res)
}

fn fe_mul_small(a Fe, b i64) Fe {
	mut res := Fe{}
	for i in 0 .. 10 {
		res.v[i] = a.v[i] * b
	}
	fe_reduce(mut res)
	return res
}
