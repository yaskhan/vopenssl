module formats

fn test_pem_encode_decode() {
	println('Testing formats PEM...')
	data := []u8{len: 10, init: 65} // 'A'
	encoded := pem_encode('TEST', {}, data)
	println(encoded)
	
	decoded := pem_decode(encoded) or {
		assert false
		return
	}
	assert decoded.type_ == 'TEST'
	assert decoded.bytes == data
}
