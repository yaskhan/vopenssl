module tls

import crypto.sha256
import crypto.hmac
import encoding.binary

// client_handshake_tls12 performs the TLS 1.2 client handshake
pub fn (mut tc TLSConnection) client_handshake_tls12() ! {
	// 1. Send ClientHello
	tc.send_client_hello_tls12()!

	// 2. Receive ServerHello
	server_hello := tc.receive_server_hello()!

	// 3. Receive Certificate
	server_cert := tc.receive_certificate()!
	tc.peer_certificates = server_cert.certificates.clone()

	// 4. Receive ServerKeyExchange (if ECDHE)
	cipher_suite := get_cipher_suite(server_hello.cipher_suite) or {
		return error('unsupported cipher suite')
	}

	tc.cipher_suite = cipher_suite

	mut server_key_exchange := ?ServerKeyExchange(none)
	if cipher_suite.key_exchange == .ecdhe {
		server_key_exchange = tc.receive_server_key_exchange()!
	}

	// 5. Receive ServerHelloDone
	tc.receive_server_hello_done()!

	// 6. Send ClientKeyExchange
	tc.send_client_key_exchange(server_hello, server_key_exchange)!

	// 7. Send ChangeCipherSpec
	tc.send_change_cipher_spec()!

	// 8. Send Finished
	tc.send_finished_tls12()!

	// 9. Receive ChangeCipherSpec
	tc.receive_change_cipher_spec()!

	// 10. Receive Finished
	tc.receive_finished_tls12()!
}

// server_handshake_tls12 performs the TLS 1.2 server handshake
pub fn (mut tc TLSConnection) server_handshake_tls12() ! {
	// 1. Receive ClientHello
	client_hello := tc.receive_client_hello()!

	// 2. Select cipher suite
	cipher_suite := tc.select_cipher_suite_tls12(client_hello.cipher_suites)!
	tc.cipher_suite = cipher_suite

	// 3. Send ServerHello
	tc.send_server_hello_tls12(cipher_suite.id)!

	// 4. Send Certificate
	tc.send_certificate()!

	// 5. Send ServerKeyExchange (if ECDHE)
	if cipher_suite.key_exchange == .ecdhe {
		tc.send_server_key_exchange()!
	}

	// 6. Send ServerHelloDone
	tc.send_server_hello_done()!

	// 7. Receive ClientKeyExchange
	tc.receive_client_key_exchange()!

	// 8. Receive ChangeCipherSpec
	tc.receive_change_cipher_spec()!

	// 9. Receive Finished
	tc.receive_finished_tls12()!

	// 10. Send ChangeCipherSpec
	tc.send_change_cipher_spec()!

	// 11. Send Finished
	tc.send_finished_tls12()!
}

// send_client_hello_tls12 sends a TLS 1.2 ClientHello
fn (mut tc TLSConnection) send_client_hello_tls12() ! {
	mut extensions := []Extension{}

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

	// Signature Algorithms
	mut sig_algs_data := []u8{}
	sig_algs := [
		signature_rsa_pss_rsae_sha256,
		signature_rsa_pkcs1_sha256,
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

	client_hello := create_client_hello(version_tls_12, tc.config.cipher_suites, extensions)!
	
	// Store client random
	tc.client_random = client_hello.random.clone()

	hello_data := serialize_client_hello(client_hello)
	handshake_msg := create_handshake_message(handshake_type_client_hello, hello_data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, version_tls_12, serialized)!
	tc.conn.write(write_record(record))!

	// Update handshake hash
	tc.update_handshake_hash(serialized)
}

// send_server_hello_tls12 sends a TLS 1.2 ServerHello
fn (mut tc TLSConnection) send_server_hello_tls12(cipher_suite u16) ! {
	extensions := []Extension{}

	server_hello := create_server_hello(version_tls_12, cipher_suite, extensions)!
	
	// Store server random
	tc.server_random = server_hello.random.clone()

	hello_data := serialize_server_hello(server_hello)
	handshake_msg := create_handshake_message(handshake_type_server_hello, hello_data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, version_tls_12, serialized)!
	tc.conn.write(write_record(record))!

	// Update handshake hash
	tc.update_handshake_hash(serialized)
}

// compute_master_secret_tls12 computes the TLS 1.2 master secret
fn (tc TLSConnection) compute_master_secret_tls12(pre_master_secret []u8, client_random []u8, server_random []u8) []u8 {
	mut seed := []u8{}
	seed << client_random
	seed << server_random

	return prf_tls12(pre_master_secret, 'master secret', seed, 48)
}

// prf_tls12 implements the TLS 1.2 Pseudo-Random Function (P_SHA256)
fn prf_tls12(secret []u8, label string, seed []u8, length int) []u8 {
	label_bytes := label.bytes()
	mut label_seed := []u8{}
	label_seed << label_bytes
	label_seed << seed

	return p_sha256(secret, label_seed, length)
}

// p_sha256 implements the P_hash function using SHA-256
fn p_sha256(secret []u8, seed []u8, length int) []u8 {
	mut result := []u8{}
	mut a := hmac.new(secret, seed, sha256.sum, sha256.block_size)
	
	for result.len < length {
		a = hmac.new(secret, a, sha256.sum, sha256.block_size)
		
		mut input := []u8{}
		input << a
		input << seed
		
		output := hmac.new(secret, input, sha256.sum, sha256.block_size)
		result << output
	}
	
	return result[..length]
}

// send_finished_tls12 sends the Finished message for TLS 1.2
fn (mut tc TLSConnection) send_finished_tls12() ! {
	verify_data := tc.compute_verify_data_tls12()

	finished := Finished{
		verify_data: verify_data
	}

	handshake_msg := create_handshake_message(handshake_type_finished, finished.verify_data)
	serialized := serialize_handshake_message(handshake_msg)

	record := create_record(content_type_handshake, tc.version, serialized)!
	encrypted := tc.record_layer.encrypt_record(record)!
	tc.conn.write(write_record(encrypted))!

	// Update handshake hash with the Finished message we just sent
	tc.update_handshake_hash(serialized)
}

// receive_finished_tls12 receives and verifies the Finished message for TLS 1.2
fn (mut tc TLSConnection) receive_finished_tls12() ! {
	// Read verify_data first, before reading the message which updates the transcript
	expected_verify_data := tc.compute_verify_data_tls12()

	// Read record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	mut length := int(record_header[3]) << 8 | int(record_header[4])
	mut fragment := []u8{len: length}
	_ := tc.conn.read(mut fragment)!

	// Create a record from the fragment
	record := TLSRecord{
		content_type: record_header[0]
		version:      u16(record_header[1]) << 8 | u16(record_header[2])
		length:       u16(length)
		fragment:     fragment
	}

	// Decrypt the record
	decrypted := tc.record_layer.decrypt_record(record)!

	if decrypted.content_type != content_type_handshake {
		return error('expected handshake message (Finished), got content type ${decrypted.content_type}')
	}

	// Parse handshake message
	handshake_msg := parse_handshake_message(decrypted.fragment)!

	if handshake_msg.msg_type != handshake_type_finished {
		return error('expected Finished message, got message type ${handshake_msg.msg_type}')
	}

	// Verify the data
	if handshake_msg.data != expected_verify_data {
		return error('Finished message verification failed')
	}

	// Update handshake hash with the received Finished message
	// Note: We use the DECRYPTED handshake message for the hash updates
	tc.update_handshake_hash(decrypted.fragment)
}

// compute_verify_data_tls12 computes the verify_data for TLS 1.2 Finished message
fn (tc TLSConnection) compute_verify_data_tls12() []u8 {
	label := if tc.is_client { 'client finished' } else { 'server finished' }
	seed := sha256.sum(tc.handshake_hash)
	
	return prf_tls12(tc.master_secret, label, seed[..], 12)
}

// select_cipher_suite_tls12 selects a cipher suite for TLS 1.2
fn (tc TLSConnection) select_cipher_suite_tls12(client_suites []u16) !CipherSuite {
	for suite_id in tc.config.cipher_suites {
		if suite_id in client_suites {
			if cs := get_cipher_suite(suite_id) {
				if cs.suite_type == .tls_12 {
					return cs
				}
			}
		}
	}
	return error('no common cipher suite found')
}

// update_handshake_hash updates the running hash of handshake messages
fn (mut tc TLSConnection) update_handshake_hash(data []u8) {
	tc.handshake_hash << data
}
