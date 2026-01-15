module hash

import encoding.binary



struct Sha256Hasher {
mut:
	h      [8]u32
	x      [64]u8
	nx     int
	len    u64
}

fn new_sha256_hasher() Hasher {
	mut s := Sha256Hasher{}
	s.reset()
	return s
}

pub fn (mut d Sha256Hasher) reset() {
	d.h[0] = 0x6a09e667
	d.h[1] = 0xbb67ae85
	d.h[2] = 0x3c6ef372
	d.h[3] = 0xa54ff53a
	d.h[4] = 0x510e527f
	d.h[5] = 0x9b05688c
	d.h[6] = 0x1f83d9ab
	d.h[7] = 0x5be0cd19
	d.nx = 0
	d.len = 0
}

pub fn (mut d Sha256Hasher) free() {}

pub fn (d Sha256Hasher) block_size() int { return 64 }
pub fn (d Sha256Hasher) size() int { return 32 }

pub fn (mut d Sha256Hasher) write(p []u8) !int {
	d.len += u64(p.len)
	mut nn := p.len
	mut p_idx := 0
	
	if d.nx > 0 {
		n := 64 - d.nx
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
	
	if nn >= 64 {
		n := nn & 0xFFFFFFC0
		for i := 0; i < n; i += 64 {
			d.block(p[p_idx + i .. p_idx + i + 64])
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

pub fn (mut d Sha256Hasher) checksum() []u8 {
	mut d2 := d 
	
	len := d.len
	mut tmp := [64]u8{}
	tmp[0] = 0x80
	if len % 64 < 56 {
		d2.write(tmp[0..1]) or {}
		for (d2.len % 64) != 56 {
			d2.write(tmp[1..2]) or {}
		}
	} else {
		d2.write(tmp[0..1]) or {}
		for (d2.len % 64) != 56 {
			d2.write(tmp[1..2]) or {}
		}
	}
	
	len_bits := len * 8
	binary.big_endian_put_u64(mut tmp[0..8], len_bits)
	d2.write(tmp[0..8]) or {}
	
	mut digest := []u8{len: 32}
	for i in 0 .. 8 {
		binary.big_endian_put_u32(mut digest[i*4..(i+1)*4], d2.h[i])
	}
	return digest
}

fn sha256_block(mut h_state [8]u32, p []u8) {
    // println('In block p: ${p.hex()}')
	k_local := [
		u32(0x428a2f98), u32(0x71374491), u32(0xb5c0fbcf), u32(0xe9b5dba5), u32(0x3956c25b), u32(0x59f111f1), u32(0x923f82a4), u32(0xab1c5ed5),
		u32(0xd807aa98), u32(0x12835b01), u32(0x243185be), u32(0x550c7dc3), u32(0x72be5d74), u32(0x80deb1fe), u32(0x9bdc06a7), u32(0xc19bf174),
		u32(0xe49b69c1), u32(0xefbe4786), u32(0x0fc19dc6), u32(0x240ca1cc), u32(0x2de92c6f), u32(0x4a7484aa), u32(0x5cb0a9dc), u32(0x76f988da),
		u32(0x983e5152), u32(0xa831c66d), u32(0xb00327c8), u32(0xbf597fc7), u32(0xc6e00bf3), u32(0xd5a79147), u32(0x06ca6351), u32(0x14292967),
		u32(0x27b70a85), u32(0x2e1b2138), u32(0x4d2c6dfc), u32(0x53380d13), u32(0x650a7354), u32(0x766a0abb), u32(0x81c2c92e), u32(0x92722c85),
		u32(0xa2bfe8a1), u32(0xa81a664b), u32(0xc24b8b70), u32(0xc76c51a3), u32(0xd192e819), u32(0xd6990624), u32(0xf40e3585), u32(0x106aa070),
		u32(0x19a4c116), u32(0x1e376c08), u32(0x2748774c), u32(0x34b0bcb5), u32(0x391c0cb3), u32(0x4ed8aa4a), u32(0x5b9cca4f), u32(0x682e6ff3),
		u32(0x748f82ee), u32(0x78a5636f), u32(0x84c87814), u32(0x8cc70208), u32(0x90befffa), u32(0xa4506ceb), u32(0xbef9a3f7), u32(0xc67178f2),
	]

	mut w := [64]u32{}
	
	for i in 0 .. 16 {
		w[i] = binary.big_endian_u32(p[i * 4..(i + 1) * 4])
	}
	
	for i in 16 .. 64 {
		v1 := (w[i - 2] >> 17 | w[i - 2] << 15) ^ (w[i - 2] >> 19 | w[i - 2] << 13) ^ (w[i - 2] >> 10)
		v2 := (w[i - 15] >> 7 | w[i - 15] << 25) ^ (w[i - 15] >> 18 | w[i - 15] << 14) ^ (w[i - 15] >> 3)
		w[i] = w[i - 16] + v1 + w[i - 7] + v2
	}
	
	mut a := h_state[0]
	mut b := h_state[1]
	mut c := h_state[2]
	mut dd := h_state[3]
	mut e := h_state[4]
	mut f := h_state[5]
	mut g := h_state[6]
	mut h := h_state[7]
	
	for i in 0 .. 64 {
		s1 := (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)
		ch := (e & f) ^ ((~e) & g)
		t1 := h + s1 + ch + k_local[i] + w[i]
		s0 := (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)
		maj := (a & b) ^ (a & c) ^ (b & c)
		t2 := s0 + maj
		
		h = g
		g = f
		f = e
		e = dd + t1
		dd = c
		c = b
		b = a
		a = t1 + t2
	}
	
	h_state[0] += a
	h_state[1] += b
	h_state[2] += c
	h_state[3] += dd
	h_state[4] += e
	h_state[5] += f
	h_state[6] += g
	h_state[7] += h
}

fn (mut d Sha256Hasher) block(p []u8) {
	sha256_block(mut d.h, p)
}
