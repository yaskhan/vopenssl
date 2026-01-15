module hash

import encoding.binary

struct Sha1Hasher {
mut:
	h      [5]u32
	x      [64]u8
	nx     int
	len    u64
}

fn new_sha1_hasher() Hasher {
	mut s := Sha1Hasher{}
	s.reset()
	return s
}

pub fn (mut d Sha1Hasher) reset() {
	d.h[0] = 0x67452301
	d.h[1] = 0xEFCDAB89
	d.h[2] = 0x98BADCFE
	d.h[3] = 0x10325476
	d.h[4] = 0xC3D2E1F0
	d.nx = 0
	d.len = 0
}

pub fn (mut d Sha1Hasher) free() {}

pub fn (d Sha1Hasher) block_size() int { return 64 }
pub fn (d Sha1Hasher) size() int { return 20 }

pub fn (mut d Sha1Hasher) write(p []u8) !int {
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

pub fn (mut d Sha1Hasher) checksum() []u8 {
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
	
	mut digest := []u8{len: 20}
	for i in 0 .. 5 {
		binary.big_endian_put_u32(mut digest[i * 4..(i + 1) * 4], d2.h[i])
	}
	return digest
}

fn (mut d Sha1Hasher) block(p []u8) {
	mut w := [80]u32{}
	
	for i in 0 .. 16 {
		w[i] = binary.big_endian_u32(p[i * 4..(i + 1) * 4])
	}
	
	for i in 16 .. 80 {
		t := w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
		w[i] = (t << 1) | (t >> 31)
	}
	
	mut a := d.h[0]
	mut b := d.h[1]
	mut c := d.h[2]
	mut dd := d.h[3]
	mut e := d.h[4]
	
	for i in 0 .. 80 {
		mut f := u32(0)
		mut k := u32(0)
		
		if i < 20 {
			f = (b & c) | ((~b) & dd)
			k = 0x5A827999
		} else if i < 40 {
			f = b ^ c ^ dd
			k = 0x6ED9EBA1
		} else if i < 60 {
			f = (b & c) | (b & dd) | (c & dd)
			k = 0x8F1BBCDC
		} else {
			f = b ^ c ^ dd
			k = 0xCA62C1D6
		}
		
		temp := ((a << 5) | (a >> 27)) + f + e + k + w[i]
		e = dd
		dd = c
		c = (b << 30) | (b >> 2)
		b = a
		a = temp
	}
	
	d.h[0] += a
	d.h[1] += b
	d.h[2] += c
	d.h[3] += dd
	d.h[4] += e
}
