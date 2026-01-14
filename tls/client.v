module tls

import net

// dial creates a TLS client connection to the given address
pub fn dial(address string, config TLSConfig) !TLSConnection {
	// Parse address
	parts := address.split(':')
	if parts.len != 2 {
		return error('invalid address format: expected host:port')
	}

	host := parts[0]
	port := parts[1].int()

	// Create TCP connection
	conn := net.dial_tcp('${host}:${port}')!

	// Create TLS config with server name if not set
	mut tls_config := config
	if tls_config.server_name == '' {
		tls_config = TLSConfig{
			...config
			server_name: host
		}
	}

	// Create TLS connection
	mut tls_conn := new_client(conn, tls_config)

	// Perform handshake
	tls_conn.handshake()!

	return tls_conn
}

// dial_with_timeout creates a TLS client connection with a timeout
pub fn dial_with_timeout(address string, config TLSConfig) !TLSConnection {
	return dial(address, config)
}

// client_handshake performs the client-side TLS handshake
pub fn (mut tc TLSConnection) client_handshake() ! {
	if !tc.is_client {
		return error('not a client connection')
	}

	// Determine TLS version to use
	if tc.config.max_version == version_tls_13 {
		// Try TLS 1.3 first
		tc.client_handshake_tls13() or {
			// Fall back to TLS 1.2
			if tc.config.min_version <= version_tls_12 {
				tc.version = version_tls_12
				tc.client_handshake_tls12()!
			} else {
				return err
			}
		}
	} else if tc.config.max_version == version_tls_12 {
		tc.version = version_tls_12
		tc.client_handshake_tls12()!
	} else {
		return error('unsupported TLS version')
	}
}

// receive_server_hello receives and parses the ServerHello message
pub fn (mut tc TLSConnection) receive_server_hello() !ServerHello {
	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	mut length := int(record_header[3]) << 8 | int(record_header[4])
	mut fragment := []u8{len: length}
	_ := tc.conn.read(mut fragment)!

	// Parse handshake message
	handshake_msg := parse_handshake_message(fragment)!

	if handshake_msg.msg_type != handshake_type_server_hello {
		return error('expected ServerHello, got message type ${handshake_msg.msg_type}')
	}

	// Update handshake hash
	tc.update_handshake_hash(fragment)

	// Parse ServerHello
	server_hello := parse_server_hello(handshake_msg.data)!

	// Update version
	tc.version = server_hello.version

	return server_hello
}

// receive_certificate receives the Certificate message
pub fn (mut tc TLSConnection) receive_certificate() !Certificate {
	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	mut length := int(record_header[3]) << 8 | int(record_header[4])
	mut fragment := []u8{len: length}
	_ := tc.conn.read(mut fragment)!

	// Parse handshake message
	handshake_msg := parse_handshake_message(fragment)!

	if handshake_msg.msg_type != handshake_type_certificate {
		return error('expected Certificate, got message type ${handshake_msg.msg_type}')
	}

	// Update handshake hash
	tc.update_handshake_hash(fragment)

	// Simplified certificate parsing
	return Certificate{
		certificates: [handshake_msg.data.clone()]
	}
}

// receive_server_key_exchange receives the ServerKeyExchange message
pub fn (mut tc TLSConnection) receive_server_key_exchange() !ServerKeyExchange {
	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	mut length := int(record_header[3]) << 8 | int(record_header[4])
	mut fragment := []u8{len: length}
	_ := tc.conn.read(mut fragment)!

	// Parse handshake message
	handshake_msg := parse_handshake_message(fragment)!

	if handshake_msg.msg_type != handshake_type_server_key_exchange {
		return error('expected ServerKeyExchange, got message type ${handshake_msg.msg_type}')
	}

	// Update handshake hash
	tc.update_handshake_hash(fragment)

	return ServerKeyExchange{
		params:    handshake_msg.data.clone()
		signature: []u8{}
	}
}

// receive_server_hello_done receives the ServerHelloDone message
pub fn (mut tc TLSConnection) receive_server_hello_done() ! {
	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	mut length := int(record_header[3]) << 8 | int(record_header[4])
	mut fragment := []u8{len: length}
	_ := tc.conn.read(mut fragment)!

	// Parse handshake message
	handshake_msg := parse_handshake_message(fragment)!

	if handshake_msg.msg_type != handshake_type_server_hello_done {
		return error('expected ServerHelloDone, got message type ${handshake_msg.msg_type}')
	}

	// Update handshake hash
	tc.update_handshake_hash(fragment)
}

// send_client_key_exchange sends the ClientKeyExchange message
pub fn (mut tc TLSConnection) send_client_key_exchange(server_hello ServerHello, server_key_exchange ?ServerKeyExchange) ! {
	// Generate pre-master secret (simplified)
	pre_master_secret := []u8{len: 48}

	client_key_exchange := ClientKeyExchange{
		exchange_keys: pre_master_secret.clone()
	}

	handshake_msg := create_handshake_message(handshake_type_client_key_exchange, client_key_exchange.exchange_keys)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, tc.version, serialized)!
	tc.conn.write(write_record(record))!

	// Update handshake hash
	tc.update_handshake_hash(serialized)
}

// send_change_cipher_spec sends the ChangeCipherSpec message
pub fn (mut tc TLSConnection) send_change_cipher_spec() ! {
	change_cipher_spec := [u8(1)]
	record := create_record(content_type_change_cipher_spec, tc.version, change_cipher_spec)!
	tc.conn.write(write_record(record))!
}

// receive_change_cipher_spec receives the ChangeCipherSpec message
pub fn (mut tc TLSConnection) receive_change_cipher_spec() ! {
	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	if record_header[0] != content_type_change_cipher_spec {
		return error('expected ChangeCipherSpec')
	}
}

// receive_certificate_verify receives the CertificateVerify message
pub fn (mut tc TLSConnection) receive_certificate_verify() ! {
	// Simplified - in a full implementation, would read and verify signature
}

// receive_client_hello receives the ClientHello message (server-side)
pub fn (mut tc TLSConnection) receive_client_hello() !ClientHello {
	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	mut length := int(record_header[3]) << 8 | int(record_header[4])
	mut fragment := []u8{len: length}
	_ := tc.conn.read(mut fragment)!

	// Parse handshake message
	handshake_msg := parse_handshake_message(fragment)!

	if handshake_msg.msg_type != handshake_type_client_hello {
		return error('expected ClientHello, got message type ${handshake_msg.msg_type}')
	}

	// Update handshake hash
	tc.update_handshake_hash(fragment)

	// Parse ClientHello
	return parse_client_hello(handshake_msg.data)
}
