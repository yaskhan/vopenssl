module utils

const hex_chars = '0123456789abcdef'

// hex_encode encodes bytes to a hexadecimal string.
//
// Example:
// ```v
// hex := utils.hex_encode([u8(0xde), 0xad, 0xbe, 0xef])
// println(hex) // "deadbeef"
// ```
pub fn hex_encode(data []u8) string {
	mut result := []u8{len: data.len * 2}

	for i, b in data {
		result[i * 2] = hex_chars[b >> 4]
		result[i * 2 + 1] = hex_chars[b & 0x0f]
	}

	return result.bytestr()
}

// hex_decode decodes a hexadecimal string to bytes.
//
// Example:
// ```v
// bytes := utils.hex_decode('deadbeef')!
// ```
pub fn hex_decode(hex_str string) ![]u8 {
	if hex_str.len % 2 != 0 {
		return error('hex string must have even length')
	}

	mut result := []u8{len: hex_str.len / 2}

	for i := 0; i < hex_str.len; i += 2 {
		high := hex_char_to_byte(hex_str[i])!
		low := hex_char_to_byte(hex_str[i + 1])!
		result[i / 2] = (high << 4) | low
	}

	return result
}

// hex_char_to_byte converts a hex character to its byte value
fn hex_char_to_byte(c u8) !u8 {
	return match c {
		`0`...`9` { c - `0` }
		`a`...`f` { c - `a` + 10 }
		`A`...`F` { c - `A` + 10 }
		else { error('invalid hex character: ${c}') }
	}
}

// constant_time_compare compares two byte slices in constant time.
// Returns true if they are equal, false otherwise.
// This prevents timing attacks.
//
// Example:
// ```v
// is_equal := utils.constant_time_compare(mac1, mac2)
// ```
pub fn constant_time_compare(a []u8, b []u8) bool {
	if a.len != b.len {
		return false
	}
	mut result := u8(0)
	for i in 0 .. a.len {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// constant_time_select returns x if v == 1, otherwise returns y.
// The selection is done in constant time.
pub fn constant_time_select(v int, x int, y int) int {
	mask := -(v & 1)
	return (x & mask) | (y & ~mask)
}
