module tls

import crypto.sha256
import encoding.binary

// client_handshake_tls13 performs the TLS 1.3 client handshake
pub fn (mut tc TLSConnection) client_handshake_tls13() ! {
	// 1. Send ClientHello with key_share
	tc.send_client_hello_tls13()!

	// 2. Receive ServerHello
	server_hello := tc.receive_server_hello()!

	// Derive handshake traffic keys
	tc.derive_handshake_keys_tls13()!

	// 3. Receive EncryptedExtensions
	tc.receive_encrypted_extensions()!

	// 4. Receive Certificate
	server_cert := tc.receive_certificate()!
	tc.peer_certificates = server_cert.certificates.clone()

	// 5. Receive CertificateVerify
	tc.receive_certificate_verify()!

	// 6. Receive Finished
	tc.receive_finished_tls13()!

	// Derive application traffic keys
	tc.derive_application_keys_tls13()!

	// 7. Send Finished
	tc.send_finished_tls13()!
}

// server_handshake_tls13 performs the TLS 1.3 server handshake
pub fn (mut tc TLSConnection) server_handshake_tls13() ! {
	// 1. Receive ClientHello
	client_hello := tc.receive_client_hello()!

	// 2. Select cipher suite
	cipher_suite := tc.select_cipher_suite_tls13(client_hello.cipher_suites)!
	tc.cipher_suite = cipher_suite

	// 3. Send ServerHello with key_share
	tc.send_server_hello_tls13(cipher_suite.id)!

	// Derive handshake traffic keys
	tc.derive_handshake_keys_tls13()!

	// 4. Send EncryptedExtensions
	tc.send_encrypted_extensions()!

	// 5. Send Certificate
	tc.send_certificate()!

	// 6. Send CertificateVerify
	tc.send_certificate_verify()!

	// 7. Send Finished
	tc.send_finished_tls13()!

	// Derive application traffic keys
	tc.derive_application_keys_tls13()!

	// 8. Receive Finished
	tc.receive_finished_tls13()!
}

// send_client_hello_tls13 sends a TLS 1.3 ClientHello
fn (mut tc TLSConnection) send_client_hello_tls13() ! {
	mut extensions := []Extension{}

	// Supported Versions (TLS 1.3)
	mut versions_data := []u8{len: 3}
	versions_data[0] = 2 // length
	binary.big_endian_put_u16(mut versions_data[1..3], version_tls_13)
	extensions << Extension{
		extension_type: extension_supported_versions
		data:           versions_data
	}

	// Server Name Indication (SNI)
	if tc.server_name != '' {
		mut sni_data := []u8{}
		mut name_list_len := []u8{len: 2}
		binary.big_endian_put_u16(mut name_list_len, u16(tc.server_name.len + 3))
		sni_data << name_list_len
		sni_data << u8(0) // host_name type
		mut name_len := []u8{len: 2}
		binary.big_endian_put_u16(mut name_len, u16(tc.server_name.len))
		sni_data << name_len
		sni_data << tc.server_name.bytes()

		extensions << Extension{
			extension_type: extension_server_name
			data:           sni_data
		}
	}

	// Supported Groups
	mut groups_data := []u8{}
	groups := [supported_group_x25519, supported_group_secp256r1, supported_group_secp384r1]
	mut groups_len := []u8{len: 2}
	binary.big_endian_put_u16(mut groups_len, u16(groups.len * 2))
	groups_data << groups_len
	for group in groups {
		mut group_bytes := []u8{len: 2}
		binary.big_endian_put_u16(mut group_bytes, group)
		groups_data << group_bytes
	}
	extensions << Extension{
		extension_type: extension_supported_groups
		data:           groups_data
	}

	// Key Share (simplified - would generate actual key shares)
	mut key_share_data := []u8{}
	mut ks_len := []u8{len: 2}
	binary.big_endian_put_u16(mut ks_len, 36) // group (2) + length (2) + key (32)
	key_share_data << ks_len
	mut group_bytes := []u8{len: 2}
	binary.big_endian_put_u16(mut group_bytes, supported_group_x25519)
	key_share_data << group_bytes
	mut key_len := []u8{len: 2}
	binary.big_endian_put_u16(mut key_len, 32)
	key_share_data << key_len
	key_share_data << []u8{len: 32} // Placeholder key
	extensions << Extension{
		extension_type: extension_key_share
		data:           key_share_data
	}

	// Signature Algorithms
	mut sig_algs_data := []u8{}
	sig_algs := [
		signature_rsa_pss_rsae_sha256,
		signature_ecdsa_secp256r1_sha256,
		signature_ed25519,
	]
	mut sig_algs_len := []u8{len: 2}
	binary.big_endian_put_u16(mut sig_algs_len, u16(sig_algs.len * 2))
	sig_algs_data << sig_algs_len
	for sig_alg in sig_algs {
		mut sig_alg_bytes := []u8{len: 2}
		binary.big_endian_put_u16(mut sig_alg_bytes, sig_alg)
		sig_algs_data << sig_alg_bytes
	}
	extensions << Extension{
		extension_type: extension_signature_algorithms
		data:           sig_algs_data
	}

	// PSK Key Exchange Modes (optional)
	psk_modes := [u8(1)] // psk_dhe_ke
	extensions << Extension{
		extension_type: extension_psk_key_exchange_modes
		data:           psk_modes
	}

	client_hello := create_client_hello(version_tls_12, tc.config.cipher_suites, extensions)!
	hello_data := serialize_client_hello(client_hello)
	handshake_msg := create_handshake_message(handshake_type_client_hello, hello_data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, version_tls_12, serialized)!
	tc.conn.write(write_record(record))!

	// Update handshake transcript
	tc.update_handshake_hash(serialized)
}

// send_server_hello_tls13 sends a TLS 1.3 ServerHello
fn (mut tc TLSConnection) send_server_hello_tls13(cipher_suite u16) ! {
	mut extensions := []Extension{}

	// Supported Versions
	mut versions_data := []u8{len: 2}
	binary.big_endian_put_u16(mut versions_data, version_tls_13)
	extensions << Extension{
		extension_type: extension_supported_versions
		data:           versions_data
	}

	// Key Share (simplified - would include actual server key share)
	mut key_share_data := []u8{}
	mut group_bytes := []u8{len: 2}
	binary.big_endian_put_u16(mut group_bytes, supported_group_x25519)
	key_share_data << group_bytes
	mut key_len := []u8{len: 2}
	binary.big_endian_put_u16(mut key_len, 32)
	key_share_data << key_len
	key_share_data << []u8{len: 32} // Placeholder key
	extensions << Extension{
		extension_type: extension_key_share
		data:           key_share_data
	}

	server_hello := create_server_hello(version_tls_12, cipher_suite, extensions)!
	hello_data := serialize_server_hello(server_hello)
	handshake_msg := create_handshake_message(handshake_type_server_hello, hello_data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, version_tls_12, serialized)!
	tc.conn.write(write_record(record))!

	// Update handshake transcript
	tc.update_handshake_hash(serialized)
}

// send_encrypted_extensions sends the EncryptedExtensions message
fn (mut tc TLSConnection) send_encrypted_extensions() ! {
	extensions := []Extension{}
	ext_data := serialize_extensions(extensions)

	handshake_msg := create_handshake_message(handshake_type_encrypted_extensions, ext_data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, tc.version, serialized)!
	encrypted := tc.record_layer.encrypt_record(record)!
	tc.conn.write(write_record(encrypted))!

	tc.update_handshake_hash(serialized)
}

// receive_encrypted_extensions receives the EncryptedExtensions message
fn (mut tc TLSConnection) receive_encrypted_extensions() ! {
	// Simplified - in a full implementation, would read and parse
}

// derive_handshake_keys_tls13 derives the handshake traffic keys for TLS 1.3
fn (mut tc TLSConnection) derive_handshake_keys_tls13() ! {
	// Simplified key derivation
	// In a full implementation, this would use HKDF-Extract and HKDF-Expand

	cipher_suite := tc.cipher_suite or { return error('no cipher suite selected') }

	// Placeholder keys
	handshake_key := []u8{len: cipher_suite.key_length}
	handshake_iv := []u8{len: cipher_suite.iv_length}

	tc.record_layer.set_cipher(cipher_suite, handshake_key, handshake_key, handshake_iv,
		handshake_iv)
}

// derive_application_keys_tls13 derives the application traffic keys for TLS 1.3
fn (mut tc TLSConnection) derive_application_keys_tls13() ! {
	// Simplified key derivation
	// In a full implementation, this would derive from the master secret

	cipher_suite := tc.cipher_suite or { return error('no cipher suite selected') }

	// Placeholder keys
	app_key := []u8{len: cipher_suite.key_length}
	app_iv := []u8{len: cipher_suite.iv_length}

	tc.record_layer.set_cipher(cipher_suite, app_key, app_key, app_iv, app_iv)
}

// send_finished_tls13 sends the Finished message for TLS 1.3
fn (mut tc TLSConnection) send_finished_tls13() ! {
	verify_data := tc.compute_verify_data_tls13()

	finished := Finished{
		verify_data: verify_data
	}

	handshake_msg := create_handshake_message(handshake_type_finished, finished.verify_data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, tc.version, serialized)!
	encrypted := tc.record_layer.encrypt_record(record)!
	tc.conn.write(write_record(encrypted))!

	tc.update_handshake_hash(serialized)
}

// receive_finished_tls13 receives and verifies the Finished message for TLS 1.3
fn (mut tc TLSConnection) receive_finished_tls13() ! {
	// Simplified - in a full implementation, would read and verify
}

// compute_verify_data_tls13 computes the verify_data for TLS 1.3 Finished message
fn (tc TLSConnection) compute_verify_data_tls13() []u8 {
	// Simplified implementation
	// In TLS 1.3, this is HMAC(finished_key, transcript_hash)
	hash := sha256.sum(tc.handshake_hash)
	return hash[..]
}

// select_cipher_suite_tls13 selects a cipher suite for TLS 1.3
fn (tc TLSConnection) select_cipher_suite_tls13(client_suites []u16) !CipherSuite {
	for suite_id in tc.config.cipher_suites {
		if suite_id in client_suites {
			if cs := get_cipher_suite(suite_id) {
				if cs.suite_type == .tls_13 {
					return cs
				}
			}
		}
	}
	return error('no common TLS 1.3 cipher suite found')
}
