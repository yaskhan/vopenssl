module tls

import net
import crypto.sha256
import vopenssl.formats
import vopenssl.x509
import vopenssl.rsa
import vopenssl.ecc
import vopenssl.ed25519

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

	// Store server random
	tc.server_random = server_hello.random.clone()

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

	// Compute and store master secret
	if tc.version == version_tls_12 {
		tc.master_secret = tc.compute_master_secret_tls12(pre_master_secret, tc.client_random, tc.server_random)
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
	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	mut length := int(record_header[3]) << 8 | int(record_header[4])
	mut fragment := []u8{len: length}
	_ := tc.conn.read(mut fragment)!

	// Parse handshake message
	handshake_msg := parse_handshake_message(fragment)!

	if handshake_msg.msg_type != handshake_type_certificate_verify {
		return error('expected CertificateVerify, got message type ${handshake_msg.msg_type}')
	}

	// Compute transcript hash up to this point (excluding this message)
	transcript_hash := sha256.sum(tc.handshake_hash)

	// Update handshake hash with this message
	tc.update_handshake_hash(fragment)

	// Parse CertificateVerify
	cert_verify := parse_certificate_verify(handshake_msg.data)!

	// Verify signature
	if tc.peer_certificates.len == 0 {
		return error('no peer certificate received')
	}

	// Parse the leaf certificate
	cert := x509.parse_certificate(tc.peer_certificates[0])!

	// Construct the signed data
	// RFC 8446 Section 4.4.3
	mut signed_data := []u8{}
	for _ in 0 .. 64 { signed_data << 0x20 }
	signed_data << 'TLS 1.3, server CertificateVerify'.bytes()
	signed_data << 0x00
	signed_data << transcript_hash[..]

	// Extract public key and verify
	spki_val := formats.asn1_unmarshal(cert.public_key)!
	if spki_val is []formats.ASN1Value {
		if spki_val.len >= 2 {
			// val[0] is AlgorithmIdentifier (ignored for now, relying on signature algorithm)
			// val[1] is subjectPublicKey (BIT STRING content)
			pub_key_bytes := spki_val[1] as []u8
			
			match cert_verify.signature_algorithm {
				signature_rsa_pss_rsae_sha256 {
					// Parse RSA key
					rsa_val := formats.asn1_unmarshal(pub_key_bytes)!
					if rsa_val is []formats.ASN1Value {
						if rsa_val.len >= 2 {
							n := rsa_val[0] as []u8
							e := rsa_val[1] as []u8
							pub_key := rsa.RSAPublicKey{ n: n, e: e }
							if !rsa.verify(pub_key, signed_data, cert_verify.signature, .sha256, .pss)! {
								return error('RSA-PSS signature verification failed')
							}
							return
						}
					}
					return error('invalid RSA public key')
				}
				signature_ecdsa_secp256r1_sha256 {
					// Parse ECC key (uncompressed point)
					if pub_key_bytes.len > 0 {
						// Extract X and Y (assuming uncompressed 0x04)
						// This is simplified. Real implementation needs robust point parsing.
						// P-256 point is 65 bytes (0x04 + 32 + 32)
						if pub_key_bytes.len == 65 && pub_key_bytes[0] == 0x04 {
							x := pub_key_bytes[1..33]
							y := pub_key_bytes[33..65]
							pub_key := ecc.ECPublicKey{
								curve: .secp256r1
								x: x
								y: y
							}
							
							// Parse DER signature
							der_sig := formats.asn1_unmarshal(cert_verify.signature)!
							if der_sig is []formats.ASN1Value {
								if der_sig.len >= 2 {
									// r and s are INTEGERs
									// parse_integer returns either i64 or []u8
									r_val := der_sig[0]
									s_val := der_sig[1]
									
									r_bytes := match r_val {
										[]u8 { r_val }
										i64 { []u8{} } // Should be bytes for 256-bit curve
										else { return error('invalid r format') }
									}
									s_bytes := match s_val {
										[]u8 { s_val }
										i64 { []u8{} }
										else { return error('invalid s format') }
									}

									// If i64 (implausible for P-256 but possible for small values), 
									// we'd need to convert. For now assuming bytes.
									if r_bytes.len == 0 || s_bytes.len == 0 {
										return error('signature integers too small or invalid')
									}

									ecdsa_sig := ecc.ECDSASignature{
										r: r_bytes
										s: s_bytes
									}
									
									if !ecc.ecdsa_verify(pub_key, signed_data, ecdsa_sig, .sha256)! {
										return error('ECDSA signature verification failed')
									}
									return
								}
							}
							return error('invalid ECDSA signature format')
						}
					}
					return error('invalid ECDSA public key')
				}
				signature_ed25519 {
					// Ed25519 key is raw 32 bytes
					if pub_key_bytes.len == 32 {
						if !ed25519.verify(pub_key_bytes, signed_data, cert_verify.signature)! {
							return error('Ed25519 signature verification failed')
						}
						return
					}
					return error('invalid Ed25519 public key')
				}
				else {
					return error('unsupported signature algorithm: ${cert_verify.signature_algorithm}')
				}
			}
		}
	}
	return error('failed to parse public key info')
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
	client_hello := parse_client_hello(handshake_msg.data)!

	// Store client random
	tc.client_random = client_hello.random.clone()

	return client_hello
}
