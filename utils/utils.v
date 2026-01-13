module utils

// Bytes is a type alias for []u8 that provides additional methods
pub type Bytes = []u8

// hex returns the hexadecimal representation of a byte array.
//
// Example:
// ```v
// import vopenssl.utils
//
// hash := hash.sha256('Hello'.bytes())
// println(utils.hex(hash))
// ```
pub fn hex(data []u8) string {
	return hex_encode(data)
}
