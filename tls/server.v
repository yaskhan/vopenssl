module tls

import net

// listen creates a TLS server that listens on the given address
pub fn listen(address string, config TLSConfig) !TLSListener {
	// Parse address
	parts := address.split(':')
	if parts.len != 2 {
		return error('invalid address format: expected host:port')
	}

	port := parts[1].int()

	// Create TCP listener
	listener := net.listen_tcp(.ip, ':${port}')!

	return TLSListener{
		listener: listener
		config:   config
	}
}

pub struct TLSListener {
	listener net.TcpListener
	config   TLSConfig
}

// accept waits for and returns the next TLS connection
pub fn (mut tl TLSListener) accept() !TLSConnection {
	// Accept TCP connection
	conn := tl.listener.accept()!

	// Create TLS connection
	mut tls_conn := new_server(conn, tl.config)

	// Perform handshake
	tls_conn.handshake()!

	return tls_conn
}

// close closes the TLS listener
pub fn (mut tl TLSListener) close() ! {
	tl.listener.close()!
}

// addr returns the listener's network address
pub fn (tl TLSListener) addr() !net.Addr {
	return tl.listener.addr()
}

// server_handshake performs the server-side TLS handshake
pub fn (mut tc TLSConnection) server_handshake() ! {
	if tc.is_client {
		return error('not a server connection')
	}

	// Receive ClientHello to determine version
	client_hello := tc.receive_client_hello()!

	// Determine TLS version from ClientHello
	mut use_tls13 := false
	for ext in client_hello.extensions {
		if ext.extension_type == extension_supported_versions {
			// Check if TLS 1.3 is supported
			if ext.data.len >= 3 {
				versions_len := int(ext.data[0])
				for i := 0; i < versions_len / 2; i++ {
					version := u16(ext.data[1 + i * 2]) << 8 | u16(ext.data[2 + i * 2])
					if version == version_tls_13 && tc.config.max_version >= version_tls_13 {
						use_tls13 = true
						break
					}
				}
			}
		}
	}

	// Perform handshake based on version
	if use_tls13 {
		tc.version = version_tls_13
		// We already received ClientHello, continue with TLS 1.3 handshake
		tc.server_handshake_tls13_continue(client_hello)!
	} else {
		tc.version = version_tls_12
		// We already received ClientHello, continue with TLS 1.2 handshake
		tc.server_handshake_tls12_continue(client_hello)!
	}
}

// server_handshake_tls12_continue continues TLS 1.2 handshake after ClientHello
fn (mut tc TLSConnection) server_handshake_tls12_continue(client_hello ClientHello) ! {
	// Select cipher suite
	cipher_suite := tc.select_cipher_suite_tls12(client_hello.cipher_suites)!
	tc.cipher_suite = cipher_suite

	// Send ServerHello
	tc.send_server_hello_tls12(cipher_suite.id)!

	// Send Certificate
	tc.send_certificate()!

	// Send ServerKeyExchange (if ECDHE)
	if cipher_suite.key_exchange == .ecdhe {
		tc.send_server_key_exchange()!
	}

	// Send ServerHelloDone
	tc.send_server_hello_done()!

	// Receive ClientKeyExchange
	tc.receive_client_key_exchange()!

	// Receive ChangeCipherSpec
	tc.receive_change_cipher_spec()!

	// Receive Finished
	tc.receive_finished_tls12()!

	// Send ChangeCipherSpec
	tc.send_change_cipher_spec()!

	// Send Finished
	tc.send_finished_tls12()!
}

// server_handshake_tls13_continue continues TLS 1.3 handshake after ClientHello
fn (mut tc TLSConnection) server_handshake_tls13_continue(client_hello ClientHello) ! {
	// Select cipher suite
	cipher_suite := tc.select_cipher_suite_tls13(client_hello.cipher_suites)!
	tc.cipher_suite = cipher_suite

	// Send ServerHello with key_share
	tc.send_server_hello_tls13(cipher_suite.id)!

	// Derive handshake traffic keys
	tc.derive_handshake_keys_tls13()!

	// Send EncryptedExtensions
	tc.send_encrypted_extensions()!

	// Send Certificate
	tc.send_certificate()!

	// Send CertificateVerify
	tc.send_certificate_verify()!

	// Send Finished
	tc.send_finished_tls13()!

	// Derive application traffic keys
	tc.derive_application_keys_tls13()!

	// Receive Finished
	tc.receive_finished_tls13()!
}

// send_certificate sends the Certificate message
pub fn (mut tc TLSConnection) send_certificate() ! {
	if tc.config.certificates.len == 0 {
		return error('no server certificate configured')
	}

	// Create Certificate message (simplified)
	mut cert_data := []u8{}

	// Total certificates length (3 bytes)
	mut total_len := 0
	for cert in tc.config.certificates {
		total_len += 3 + cert.len // 3 bytes length + certificate
	}
	cert_data << u8((total_len >> 16) & 0xff)
	cert_data << u8((total_len >> 8) & 0xff)
	cert_data << u8(total_len & 0xff)

	// Each certificate
	for cert in tc.config.certificates {
		cert_data << u8((cert.len >> 16) & 0xff)
		cert_data << u8((cert.len >> 8) & 0xff)
		cert_data << u8(cert.len & 0xff)
		cert_data << cert
	}

	handshake_msg := create_handshake_message(handshake_type_certificate, cert_data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, tc.version, serialized)!

	// Encrypt if necessary (for TLS 1.3)
	if tc.version == version_tls_13 {
		encrypted := tc.record_layer.encrypt_record(record)!
		tc.conn.write(write_record(encrypted))!
	} else {
		tc.conn.write(write_record(record))!
	}

	// Update handshake hash
	tc.update_handshake_hash(serialized)
}

// send_server_key_exchange sends the ServerKeyExchange message
pub fn (mut tc TLSConnection) send_server_key_exchange() ! {
	// Simplified - generate ephemeral key parameters
	params := []u8{len: 32} // Placeholder

	server_key_exchange := ServerKeyExchange{
		params:    params
		signature: []u8{} // Would contain signature
	}

	mut data := []u8{}
	data << server_key_exchange.params
	data << server_key_exchange.signature

	handshake_msg := create_handshake_message(handshake_type_server_key_exchange, data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, tc.version, serialized)!
	tc.conn.write(write_record(record))!

	// Update handshake hash
	tc.update_handshake_hash(serialized)
}

// send_server_hello_done sends the ServerHelloDone message
pub fn (mut tc TLSConnection) send_server_hello_done() ! {
	handshake_msg := create_handshake_message(handshake_type_server_hello_done, []u8{})
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, tc.version, serialized)!
	tc.conn.write(write_record(record))!

	// Update handshake hash
	tc.update_handshake_hash(serialized)
}

// receive_client_key_exchange receives the ClientKeyExchange message
pub fn (mut tc TLSConnection) receive_client_key_exchange() ! {
	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	mut length := int(record_header[3]) << 8 | int(record_header[4])
	mut fragment := []u8{len: length}
	_ := tc.conn.read(mut fragment)!

	// Parse handshake message
	handshake_msg := parse_handshake_message(fragment)!

	if handshake_msg.msg_type != handshake_type_client_key_exchange {
		return error('expected ClientKeyExchange, got message type ${handshake_msg.msg_type}')
	}

	// Update handshake hash
	tc.update_handshake_hash(fragment)

	// Extract pre-master secret and derive keys
	// (simplified - would actually decrypt/process the exchange keys)
	// For now, using a placeholder pre-master secret to match the simplified client
	pre_master_secret := []u8{len: 48}

	if tc.version == version_tls_12 {
		tc.master_secret = tc.compute_master_secret_tls12(pre_master_secret, tc.client_random, tc.server_random)
	}
}

// send_certificate_verify sends the CertificateVerify message
pub fn (mut tc TLSConnection) send_certificate_verify() ! {
	// Simplified - would compute and send signature over handshake transcript
	signature := []u8{len: 64} // Placeholder

	mut data := []u8{}
	// Signature algorithm (2 bytes)
	data << u8(0x08)
	data << u8(0x04) // rsa_pss_rsae_sha256
	// Signature length (2 bytes)
	data << u8(0)
	data << u8(u8(signature.len))
	// Signature
	data << signature

	handshake_msg := create_handshake_message(handshake_type_certificate_verify, data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, tc.version, serialized)!
	encrypted := tc.record_layer.encrypt_record(record)!
	tc.conn.write(write_record(encrypted))!

	tc.update_handshake_hash(serialized)
}
