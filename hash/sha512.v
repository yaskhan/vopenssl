module hash

import encoding.binary



struct Sha512Hasher {
mut:
	h      [8]u64
	x      [128]u8
	nx     int
	len    u64
	alg    HashAlgorithm // .sha512 or .sha384
}

fn new_sha512_hasher() Hasher {
	mut s := Sha512Hasher{ alg: .sha512 }
	s.reset()
	return s
}

fn new_sha384_hasher() Hasher {
	mut s := Sha512Hasher{ alg: .sha384 }
	s.reset()
	return s
}

pub fn (mut d Sha512Hasher) reset() {
	if d.alg == .sha384 {
		d.h[0] = 0xcbbb9d5dc1059ed8
		d.h[1] = 0x629a292a367cd507
		d.h[2] = 0x9159015a3070dd17
		d.h[3] = 0x152fecd8f70e5939
		d.h[4] = 0x67332667ffc00b31
		d.h[5] = 0x8eb44a8768581511
		d.h[6] = 0xdb0c2e0d64f98fa7
		d.h[7] = 0x47b5481dbefa4fa4
	} else {
		// SHA-512
		d.h[0] = 0x6a09e667f3bcc908
		d.h[1] = 0xbb67ae8584caa73b
		d.h[2] = 0x3c6ef372fe94f82b
		d.h[3] = 0xa54ff53a5f1d36f1
		d.h[4] = 0x510e527fade682d1
		d.h[5] = 0x9b05688c2b3e6c1f
		d.h[6] = 0x1f83d9abfb41bd6b
		d.h[7] = 0x5be0cd19137e2179
	}
	d.nx = 0
	d.len = 0
}

pub fn (mut d Sha512Hasher) free() {}

pub fn (d Sha512Hasher) block_size() int { return 128 }
pub fn (d Sha512Hasher) size() int { 
	return if d.alg == .sha384 { 48 } else { 64 }
}

pub fn (mut d Sha512Hasher) write(p []u8) !int {
	d.len += u64(p.len)
	mut nn := p.len
	mut p_idx := 0
	
	if d.nx > 0 {
		n := 128 - d.nx
		if nn >= n {
			for i in 0 .. n {
				d.x[d.nx + i] = p[p_idx + i]
			}
			d.block(d.x[..])
			d.nx = 0
			p_idx += n
			nn -= n
		} else {
			for i in 0 .. nn {
				d.x[d.nx + i] = p[p_idx + i]
			}
			d.nx += nn
			return p.len
		}
	}
	
	if nn >= 128 {
		n := nn & 0xFFFFFF80 // n = (nn / 128) * 128
		for i := 0; i < n; i += 128 {
			d.block(p[p_idx + i .. p_idx + i + 128])
		}
		p_idx += n
		nn -= n
	}
	
	if nn > 0 {
		for i in 0 .. nn {
			d.x[d.nx + i] = p[p_idx + i]
		}
		d.nx = nn
	}
	
	return p.len
}

pub fn (mut d Sha512Hasher) checksum() []u8 {
	mut d2 := d 
	
	len := d.len
	mut tmp := [128]u8{}
	tmp[0] = 0x80
	if len % 128 < 112 {
		d2.write(tmp[0..1]) or {}
		// Pad with zeros until 112
		for (d2.len % 128) != 112 {
			d2.write(tmp[1..2]) or {}
		}
	} else {
		d2.write(tmp[0..1]) or {}
		for (d2.len % 128) != 112 {
			d2.write(tmp[1..2]) or {}
		}
	}
	
	// Append length in bits as big-endian u128
	// Only low 64 bits supported for now
	len_bits := len * 8
	// u128 is 16 bytes. last 8 bytes is len_bits
	// first 8 bytes 0 if len < 2^61 bytes
	mut len_blk := [16]u8{}
	binary.big_endian_put_u64(mut len_blk[8..16], len_bits)
	d2.write(len_blk[..]) or {}
	
	sz := d.size()
	mut digest := []u8{len: sz}
	
	for i in 0 .. sz / 8 {
		binary.big_endian_put_u64(mut digest[i * 8..(i + 1) * 8], d2.h[i])
	}
	
	return digest
}

fn (mut d Sha512Hasher) block(p []u8) {
	mut w := [80]u64{}
	
	for i in 0 .. 16 {
		w[i] = binary.big_endian_u64(p[i * 8..(i + 1) * 8])
	}
	
	for i in 16 .. 80 {
		v1 := w[i - 2]
		t1 := (v1 >> 19 | v1 << (64 - 19)) ^ (v1 >> 61 | v1 << (64 - 61)) ^ (v1 >> 6)
		v2 := w[i - 15]
		t2 := (v2 >> 1 | v2 << (64 - 1)) ^ (v2 >> 8 | v2 << (64 - 8)) ^ (v2 >> 7)
		w[i] = t1 + w[i - 7] + t2 + w[i - 16]
	}
	
	mut a := d.h[0]
	mut b := d.h[1]
	mut c := d.h[2]
	mut dd := d.h[3]
	mut e := d.h[4]
	mut f := d.h[5]
	mut g := d.h[6]
	mut h := d.h[7]
	
	k512 := [
		u64(0x428a2f98d728ae22), 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cddfbc843, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
	]

	for i in 0 .. 80 {
		t1 := h + ((e >> 14 | e << (64 - 14)) ^ (e >> 18 | e << (64 - 18)) ^ (e >> 41 | e << (64 - 41))) + ((e & f) ^ (~e & g)) + k512[i] + w[i]
		t2 := ((a >> 28 | a << (64 - 28)) ^ (a >> 34 | a << (64 - 34)) ^ (a >> 39 | a << (64 - 39))) + ((a & b) ^ (a & c) ^ (b & c))
		
		h = g
		g = f
		f = e
		e = dd + t1
		dd = c
		c = b
		b = a
		a = t1 + t2
	}
	
	d.h[0] += a
	d.h[1] += b
	d.h[2] += c
	d.h[3] += dd
	d.h[4] += e
	d.h[5] += f
	d.h[6] += g
	d.h[7] += h
}
