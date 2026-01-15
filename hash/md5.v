module hash

import encoding.binary



struct Md5Hasher {
mut:
	h      [4]u32
	x      [64]u8
	nx     int
	len    u64
}

fn new_md5_hasher() Hasher {
	mut s := Md5Hasher{}
	s.reset()
	return s
}

pub fn (mut d Md5Hasher) reset() {
	d.h[0] = 0x67452301
	d.h[1] = 0xefcdab89
	d.h[2] = 0x98badcfe
	d.h[3] = 0x10325476
	d.nx = 0
	d.len = 0
}

pub fn (mut d Md5Hasher) free() {}

pub fn (d Md5Hasher) block_size() int { return 64 }
pub fn (d Md5Hasher) size() int { return 16 }

pub fn (mut d Md5Hasher) write(p []u8) !int {
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

pub fn (mut d Md5Hasher) checksum() []u8 {
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
	
	// MD5 uses little-endian length
	len_bits := len * 8
	binary.little_endian_put_u64(mut tmp[0..8], len_bits)
	d2.write(tmp[0..8]) or {}
	
	mut digest := []u8{len: 16}
	for i in 0 .. 4 {
		binary.little_endian_put_u32(mut digest[i * 4..(i + 1) * 4], d2.h[i])
	}
	return digest
}

fn (mut d Md5Hasher) block(p []u8) {
	mut a := d.h[0]
	mut b := d.h[1]
	mut c := d.h[2]
	mut dd := d.h[3]
	
	mut x := [16]u32{}
	for i in 0 .. 16 {
		x[i] = binary.little_endian_u32(p[i*4..(i+1)*4])
	}
	
	k_md5 := [
		u32(0xd76aa478), 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
	]
	
	shifts := [
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
	]

	for i in 0 .. 64 {
		mut f := u32(0)
		mut g := 0
		
		if i < 16 {
			f = (b & c) | ((~b) & dd)
			g = i
		} else if i < 32 {
			f = (dd & b) | ((~dd) & c)
			g = (5 * i + 1) % 16
		} else if i < 48 {
			f = b ^ c ^ dd
			g = (3 * i + 5) % 16
		} else {
			f = c ^ (b | (~dd))
			g = (7 * i) % 16
		}
		
		f = f + a + k_md5[i] + x[g]
		a = dd
		dd = c
		c = b
		b = b + ((f << shifts[i]) | (f >> (32 - shifts[i])))
	}
	
	d.h[0] += a
	d.h[1] += b
	d.h[2] += c
	d.h[3] += dd
}
