module formats

import encoding.base64 as std_base64

// base64_encode encodes data using Base64.
//
// Example:
// ```v
// encoded := encoding.base64_encode('Hello'.bytes())
// ```
pub fn base64_encode(data []u8) string {
	return std_base64.encode(data)
}

// base64_decode decodes a Base64 string.
//
// Example:
// ```v
// decoded := encoding.base64_decode('SGVsbG8=')!
// ```
pub fn base64_decode(s string) ![]u8 {
	return std_base64.decode(s)
}
