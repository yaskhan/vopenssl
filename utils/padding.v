module utils

// pkcs7_pad applies PKCS#7 padding to data for the given block size.
//
// Example:
// ```v
// padded := utils.pkcs7_pad(data, 16) // Pad to 16-byte blocks
// ```
pub fn pkcs7_pad(data []u8, block_size int) []u8 {
	if block_size <= 0 || block_size > 255 {
		panic('invalid block size: ${block_size}')
	}

	padding_len := block_size - (data.len % block_size)
	padding := []u8{len: padding_len, init: u8(padding_len)}

	mut result := []u8{len: data.len + padding_len}
	copy(mut result, data)
	copy(mut result[data.len..], padding)

	return result
}

// pkcs7_unpad removes PKCS#7 padding from data.
//
// Example:
// ```v
// unpadded := utils.pkcs7_unpad(padded_data)!
// ```
pub fn pkcs7_unpad(data []u8) ![]u8 {
	if data.len == 0 {
		return error('cannot unpad empty data')
	}

	padding_len := int(data[data.len - 1])

	if padding_len == 0 || padding_len > data.len {
		return error('invalid padding')
	}

	// Verify padding
	for i in data.len - padding_len .. data.len {
		if data[i] != u8(padding_len) {
			return error('invalid padding')
		}
	}

	return data[..data.len - padding_len]
}

// zero_pad applies zero padding to data for the given block size.
//
// Example:
// ```v
// padded := utils.zero_pad(data, 16)
// ```
pub fn zero_pad(data []u8, block_size int) []u8 {
	if block_size <= 0 {
		panic('invalid block size: ${block_size}')
	}

	padding_len := block_size - (data.len % block_size)
	if padding_len == block_size {
		return data
	}

	mut result := []u8{len: data.len + padding_len}
	copy(mut result, data)

	return result
}
