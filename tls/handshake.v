module tls

import encoding.binary
import vopenssl.rand

pub struct HandshakeMessage {
pub:
	msg_type u8
	length   u32
	data     []u8
}

pub struct ClientHello {
pub:
	version             u16
	random              []u8 // 32 bytes
	session_id          []u8
	cipher_suites       []u16
	compression_methods []u8
	extensions          []Extension
}

pub struct ServerHello {
pub:
	version            u16
	random             []u8 // 32 bytes
	session_id         []u8
	cipher_suite       u16
	compression_method u8
	extensions         []Extension
}

pub struct Extension {
pub:
	extension_type u16
	data           []u8
}

pub struct Certificate {
pub:
	certificates [][]u8 // DER-encoded certificates
}

pub struct ServerKeyExchange {
pub:
	params    []u8
	signature []u8
}

pub struct CertificateRequest {
pub:
	certificate_types       []u8
	signature_algorithms    []u16
	certificate_authorities [][]u8
}

pub struct ServerHelloDone {
}

pub struct ClientKeyExchange {
pub:
	exchange_keys []u8
}

pub struct CertificateVerify {
pub:
	signature_algorithm u16
	signature           []u8
}

pub struct Finished {
pub:
	verify_data []u8
}

// create_client_hello creates a ClientHello message
pub fn create_client_hello(version u16, cipher_suites []u16, extensions []Extension) !ClientHello {
	// Generate 32 random bytes
	mut random := []u8{len: 32}
	for i in 0 .. 32 {
		random[i] = u8(rand.int_in_range(0, 256) or { 0 })
	}

	return ClientHello{
		version:             version
		random:              random
		session_id:          []u8{}
		cipher_suites:       cipher_suites.clone()
		compression_methods: [u8(0)] // null compression
		extensions:          extensions.clone()
	}
}

// create_server_hello creates a ServerHello message
pub fn create_server_hello(version u16, cipher_suite u16, extensions []Extension) !ServerHello {
	// Generate 32 random bytes
	mut random := []u8{len: 32}
	for i in 0 .. 32 {
		random[i] = u8(rand.int_in_range(0, 256) or { 0 })
	}

	return ServerHello{
		version:            version
		random:             random
		session_id:         []u8{}
		cipher_suite:       cipher_suite
		compression_method: 0 // null compression
		extensions:         extensions.clone()
	}
}

// serialize_client_hello serializes ClientHello to bytes
pub fn serialize_client_hello(hello ClientHello) []u8 {
	mut data := []u8{}

	// Version (2 bytes)
	mut version_bytes := []u8{len: 2}
	binary.big_endian_put_u16(mut version_bytes, hello.version)
	data << version_bytes

	// Random (32 bytes)
	data << hello.random

	// Session ID length + Session ID
	data << u8(hello.session_id.len)
	data << hello.session_id

	// Cipher suites length + Cipher suites
	mut cs_len := []u8{len: 2}
	binary.big_endian_put_u16(mut cs_len, u16(hello.cipher_suites.len * 2))
	data << cs_len
	for cs in hello.cipher_suites {
		mut cs_bytes := []u8{len: 2}
		binary.big_endian_put_u16(mut cs_bytes, cs)
		data << cs_bytes
	}

	// Compression methods length + Compression methods
	data << u8(hello.compression_methods.len)
	data << hello.compression_methods

	// Extensions
	if hello.extensions.len > 0 {
		mut ext_data := serialize_extensions(hello.extensions)
		mut ext_len := []u8{len: 2}
		binary.big_endian_put_u16(mut ext_len, u16(ext_data.len))
		data << ext_len
		data << ext_data
	}

	return data
}

// serialize_server_hello serializes ServerHello to bytes
pub fn serialize_server_hello(hello ServerHello) []u8 {
	mut data := []u8{}

	// Version (2 bytes)
	mut version_bytes := []u8{len: 2}
	binary.big_endian_put_u16(mut version_bytes, hello.version)
	data << version_bytes

	// Random (32 bytes)
	data << hello.random

	// Session ID length + Session ID
	data << u8(hello.session_id.len)
	data << hello.session_id

	// Cipher suite (2 bytes)
	mut cs_bytes := []u8{len: 2}
	binary.big_endian_put_u16(mut cs_bytes, hello.cipher_suite)
	data << cs_bytes

	// Compression method (1 byte)
	data << hello.compression_method

	// Extensions
	if hello.extensions.len > 0 {
		mut ext_data := serialize_extensions(hello.extensions)
		mut ext_len := []u8{len: 2}
		binary.big_endian_put_u16(mut ext_len, u16(ext_data.len))
		data << ext_len
		data << ext_data
	}

	return data
}

// serialize_extensions serializes extensions to bytes
pub fn serialize_extensions(extensions []Extension) []u8 {
	mut data := []u8{}

	for ext in extensions {
		// Extension type (2 bytes)
		mut ext_type := []u8{len: 2}
		binary.big_endian_put_u16(mut ext_type, ext.extension_type)
		data << ext_type

		// Extension length (2 bytes)
		mut ext_len := []u8{len: 2}
		binary.big_endian_put_u16(mut ext_len, u16(ext.data.len))
		data << ext_len

		// Extension data
		data << ext.data
	}

	return data
}

// parse_client_hello parses ClientHello from bytes
pub fn parse_client_hello(data []u8) !ClientHello {
	if data.len < 34 {
		return error('ClientHello too short')
	}

	mut offset := 0

	// Version (2 bytes)
	version := binary.big_endian_u16(data[offset..offset + 2])
	offset += 2

	// Random (32 bytes)
	random := data[offset..offset + 32].clone()
	offset += 32

	// Session ID
	session_id_len := int(data[offset])
	offset++
	session_id := if session_id_len > 0 {
		data[offset..offset + session_id_len].clone()
	} else {
		[]u8{}
	}
	offset += session_id_len

	// Cipher suites
	cipher_suites_len := int(binary.big_endian_u16(data[offset..offset + 2]))
	offset += 2
	mut cipher_suites := []u16{}
	for _ in 0 .. cipher_suites_len / 2 {
		cipher_suites << binary.big_endian_u16(data[offset..offset + 2])
		offset += 2
	}

	// Compression methods
	compression_methods_len := int(data[offset])
	offset++
	compression_methods := data[offset..offset + compression_methods_len].clone()
	offset += compression_methods_len

	// Extensions (optional)
	mut extensions := []Extension{}
	if offset < data.len {
		extensions_len := int(binary.big_endian_u16(data[offset..offset + 2]))
		offset += 2
		extensions = parse_extensions(data[offset..offset + extensions_len])!
	}

	return ClientHello{
		version:             version
		random:              random
		session_id:          session_id
		cipher_suites:       cipher_suites
		compression_methods: compression_methods
		extensions:          extensions
	}
}

// parse_server_hello parses ServerHello from bytes
pub fn parse_server_hello(data []u8) !ServerHello {
	if data.len < 35 {
		return error('ServerHello too short')
	}

	mut offset := 0

	// Version (2 bytes)
	version := binary.big_endian_u16(data[offset..offset + 2])
	offset += 2

	// Random (32 bytes)
	random := data[offset..offset + 32].clone()
	offset += 32

	// Session ID
	session_id_len := int(data[offset])
	offset++
	session_id := if session_id_len > 0 {
		data[offset..offset + session_id_len].clone()
	} else {
		[]u8{}
	}
	offset += session_id_len

	// Cipher suite (2 bytes)
	cipher_suite := binary.big_endian_u16(data[offset..offset + 2])
	offset += 2

	// Compression method (1 byte)
	compression_method := data[offset]
	offset++

	// Extensions (optional)
	mut extensions := []Extension{}
	if offset < data.len {
		extensions_len := int(binary.big_endian_u16(data[offset..offset + 2]))
		offset += 2
		extensions = parse_extensions(data[offset..offset + extensions_len])!
	}

	return ServerHello{
		version:            version
		random:             random
		session_id:         session_id
		cipher_suite:       cipher_suite
		compression_method: compression_method
		extensions:         extensions
	}
}

// parse_extensions parses extensions from bytes
pub fn parse_extensions(data []u8) ![]Extension {
	mut extensions := []Extension{}
	mut offset := 0

	for offset < data.len {
		if offset + 4 > data.len {
			break
		}

		ext_type := binary.big_endian_u16(data[offset..offset + 2])
		offset += 2

		ext_len := int(binary.big_endian_u16(data[offset..offset + 2]))
		offset += 2

		if offset + ext_len > data.len {
			return error('extension data truncated')
		}

		ext_data := data[offset..offset + ext_len].clone()
		offset += ext_len

		extensions << Extension{
			extension_type: ext_type
			data:           ext_data
		}
	}

	return extensions
}

// create_handshake_message wraps data in a handshake message
pub fn create_handshake_message(msg_type u8, data []u8) HandshakeMessage {
	return HandshakeMessage{
		msg_type: msg_type
		length:   u32(data.len)
		data:     data.clone()
	}
}

// serialize_handshake_message serializes a handshake message to bytes
pub fn serialize_handshake_message(msg HandshakeMessage) []u8 {
	mut result := []u8{len: 4 + msg.data.len}

	result[0] = msg.msg_type
	result[1] = u8((msg.length >> 16) & 0xff)
	result[2] = u8((msg.length >> 8) & 0xff)
	result[3] = u8(msg.length & 0xff)

	for i, b in msg.data {
		result[4 + i] = b
	}

	return result
}

// parse_handshake_message parses a handshake message from bytes
pub fn parse_handshake_message(data []u8) !HandshakeMessage {
	if data.len < 4 {
		return error('handshake message too short')
	}

	msg_type := data[0]
	length := u32(data[1]) << 16 | u32(data[2]) << 8 | u32(data[3])

	if data.len < 4 + int(length) {
		return error('handshake message data truncated')
	}

	msg_data := data[4..4 + int(length)].clone()

	return HandshakeMessage{
		msg_type: msg_type
		length:   length
		data:     msg_data
	}
}

// parse_certificate_verify parses CertificateVerify from bytes
pub fn parse_certificate_verify(data []u8) !CertificateVerify {
	if data.len < 4 {
		return error('CertificateVerify too short')
	}

	mut offset := 0

	// Signature Algorithm (2 bytes)
	sig_alg := binary.big_endian_u16(data[offset..offset + 2])
	offset += 2

	// Signature Length (2 bytes)
	sig_len := int(binary.big_endian_u16(data[offset..offset + 2]))
	offset += 2

	if offset + sig_len > data.len {
		return error('signature truncated')
	}

	signature := data[offset..offset + sig_len].clone()

	return CertificateVerify{
		signature_algorithm: sig_alg
		signature:           signature
	}
}
