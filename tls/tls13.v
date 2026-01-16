module tls

import crypto.sha256
import crypto.hmac
import encoding.binary
import vopenssl.kdf
import vopenssl.ecc as vecc
import vopenssl.hash as vhash

// client_handshake_tls13 performs the TLS 1.3 client handshake
pub fn (mut tc TLSConnection) client_handshake_tls13() ! {
	// 1. Send ClientHello with key_share
	tc.send_client_hello_tls13()!

	// 2. Receive ServerHello
	server_hello := tc.receive_server_hello()!

	// Process Key Share to compute shared secret
	tc.process_server_key_share(server_hello)!

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

	// Key Share
	// Generate X25519 key pair
	key_pair := vecc.generate_key_pair(.x25519)!
	tc.client_key_pair = key_pair
	
	mut key_share_data := []u8{}
	mut ks_len := []u8{len: 2}
	// Group (2) + Length (2) + Key (32) = 36 bytes
	binary.big_endian_put_u16(mut ks_len, 36) 
	key_share_data << ks_len
	
	mut group_bytes := []u8{len: 2}
	binary.big_endian_put_u16(mut group_bytes, supported_group_x25519)
	key_share_data << group_bytes
	
	mut key_len := []u8{len: 2}
	binary.big_endian_put_u16(mut key_len, 32)
	key_share_data << key_len
	
	key_share_data << key_pair.public.x // X25519 public key
	
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
	// Read encrypted record (implicitly handles decryption since keys are set)
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
		return error('expected handshake message (EncryptedExtensions), got content type ${decrypted.content_type}')
	}

	// Parse handshake message
	handshake_msg := parse_handshake_message(decrypted.fragment)!

	if handshake_msg.msg_type != handshake_type_encrypted_extensions {
		return error('expected EncryptedExtensions, got message type ${handshake_msg.msg_type}')
	}

	// Update handshake transcript (using decrypted fragment)
	tc.update_handshake_hash(decrypted.fragment)

	// Note: We could parse extensions here if needed
}

// derive_handshake_keys_tls13 derives the handshake traffic keys for TLS 1.3
fn (mut tc TLSConnection) derive_handshake_keys_tls13() ! {
	cipher_suite := tc.cipher_suite or { return error('no cipher suite selected') }
	hash_len := 32 // Assuming SHA-256 for now 

	// 1. Extract Early Secret (Salt = derived from 0, IKM = 0)
	// For now, simpler: Early Secret = HKDF-Extract(0, 0)
	zero := []u8{len: hash_len, init: 0}
	tc.early_secret = kdf.hkdf_extract_only(zero, zero, .sha256)

	// 2. Derive Handshake Secret
	// Handshake Secret = HKDF-Extract(Derive-Secret(Early Secret, "derived", ""), Shared Secret)
	derived_secret := hkdf_expand_label_tls13(tc.early_secret, 'derived', []u8{}, hash_len, .sha256)
	tc.handshake_secret = kdf.hkdf_extract_only(derived_secret, tc.shared_secret, .sha256)

	// 3. Derive Client Handshake Traffic Secret
	tc.client_handshake_traffic_secret = hkdf_expand_label_tls13(tc.handshake_secret, 'c hs traffic', tc.handshake_hash, hash_len, .sha256)

	// 4. Derive Server Handshake Traffic Secret
	tc.server_handshake_traffic_secret = hkdf_expand_label_tls13(tc.handshake_secret, 's hs traffic', tc.handshake_hash, hash_len, .sha256)

	// 5. Derive keys and IVs
	client_write_key := hkdf_expand_label_tls13(tc.client_handshake_traffic_secret, 'key', []u8{}, cipher_suite.key_length, .sha256)
	client_write_iv := hkdf_expand_label_tls13(tc.client_handshake_traffic_secret, 'iv', []u8{}, cipher_suite.iv_length, .sha256)
	server_write_key := hkdf_expand_label_tls13(tc.server_handshake_traffic_secret, 'key', []u8{}, cipher_suite.key_length, .sha256)
	server_write_iv := hkdf_expand_label_tls13(tc.server_handshake_traffic_secret, 'iv', []u8{}, cipher_suite.iv_length, .sha256)

	// Set keys in record layer
	if tc.is_client {
		tc.record_layer.set_cipher(cipher_suite, client_write_key, server_write_key, client_write_iv, server_write_iv)
	} else {
		tc.record_layer.set_cipher(cipher_suite, server_write_key, client_write_key, server_write_iv, client_write_iv)
	}
}

// derive_application_keys_tls13 derives the application traffic keys for TLS 1.3
fn (mut tc TLSConnection) derive_application_keys_tls13() ! {
	cipher_suite := tc.cipher_suite or { return error('no cipher suite selected') }
	hash_len := 32 // Assuming SHA-256

	// 1. Derive Master Secret
	// Master Secret = HKDF-Extract(Derive-Secret(Handshake Secret, "derived", ""), 0)
	derived_secret := hkdf_expand_label_tls13(tc.handshake_secret, 'derived', []u8{}, hash_len, .sha256)
	zero := []u8{len: hash_len, init: 0}
	tc.master_secret = kdf.hkdf_extract_only(derived_secret, zero, .sha256)

	// 2. Derive Client Application Traffic Secret
	tc.client_application_traffic_secret = hkdf_expand_label_tls13(tc.master_secret, 'c ap traffic', tc.handshake_hash, hash_len, .sha256)

	// 3. Derive Server Application Traffic Secret
	tc.server_application_traffic_secret = hkdf_expand_label_tls13(tc.master_secret, 's ap traffic', tc.handshake_hash, hash_len, .sha256)

	// 4. Derive keys and IVs
	client_write_key := hkdf_expand_label_tls13(tc.client_application_traffic_secret, 'key', []u8{}, cipher_suite.key_length, .sha256)
	client_write_iv := hkdf_expand_label_tls13(tc.client_application_traffic_secret, 'iv', []u8{}, cipher_suite.iv_length, .sha256)
	server_write_key := hkdf_expand_label_tls13(tc.server_application_traffic_secret, 'key', []u8{}, cipher_suite.key_length, .sha256)
	server_write_iv := hkdf_expand_label_tls13(tc.server_application_traffic_secret, 'iv', []u8{}, cipher_suite.iv_length, .sha256)

	// Set keys in record layer
	if tc.is_client {
		tc.record_layer.set_cipher(cipher_suite, client_write_key, server_write_key, client_write_iv, server_write_iv)
	} else {
		tc.record_layer.set_cipher(cipher_suite, server_write_key, client_write_key, server_write_iv, client_write_iv)
	}
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
	expected_verify_data := tc.compute_verify_data_tls13()

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
	tc.update_handshake_hash(decrypted.fragment)
}

// compute_verify_data_tls13 computes the verify_data for TLS 1.3 Finished message
fn (tc TLSConnection) compute_verify_data_tls13() []u8 {
	hash_len := 32 // Assuming SHA-256
	
	// Base Key depends on who is sending
	base_key := if tc.is_client {
		tc.client_handshake_traffic_secret
	} else {
		tc.server_handshake_traffic_secret
	}

	// Finished Key = HKDF-Expand-Label(Base Key, "finished", "", Hash.length)
	finished_key := hkdf_expand_label_tls13(base_key, 'finished', []u8{}, hash_len, .sha256)

	// Verify Data = HMAC(Finished Key, Transcript Hash)
	transcript_hash := sha256.sum(tc.handshake_hash)
	
	return hmac.new(finished_key, transcript_hash[..], sha256.sum, sha256.block_size)
}

// hkdf_expand_label_tls13 derives a secret from a secret using a label and a context
fn hkdf_expand_label_tls13(secret []u8, label string, context []u8, length int, hash_alg vhash.HashAlgorithm) []u8 {
	mut hkdf_label := []u8{}
	// Length (2 bytes)
	hkdf_label << u8((length >> 8) & 0xFF)
	hkdf_label << u8(length & 0xFF)

	// Label: "tls13 " + label
	// Length of label (1 byte)
	full_label := 'tls13 ' + label
	hkdf_label << u8(full_label.len)
	hkdf_label << full_label.bytes()

	// Context
	// Length of context (1 byte)
	hkdf_label << u8(context.len)
	hkdf_label << context

	return kdf.hkdf_expand_only(secret, hkdf_label, length, hash_alg)
}

// process_server_key_share processes the server's key share and computes the shared secret
fn (mut tc TLSConnection) process_server_key_share(server_hello ServerHello) ! {
	// Find Key Share extension
	for ext in server_hello.extensions {
		if ext.extension_type == extension_key_share {
			if ext.data.len < 4 {
				return error('invalid key share extension length')
			}
			
			// Parse group (assuming X25519 for now as it's the only one we sent)
			group := binary.big_endian_u16(ext.data[0..2])
			if group != supported_group_x25519 {
				return error('unsupported group selected by server: ${group}')
			}
			
			// Key length
			key_len := binary.big_endian_u16(ext.data[2..4])
			if int(key_len) != 32 {
				return error('invalid X25519 key length from server')
			}
			
			if ext.data.len < 4 + int(key_len) {
				return error('key share data truncated')
			}
			
			server_public_key_bytes := ext.data[4..4 + int(key_len)]
			
			// Retrieve our private key
			client_kp := tc.client_key_pair or {
				return error('client key pair missing')
			}
			
			// Construct server public key object
			server_pub_key := vecc.ECPublicKey{
				curve: .x25519
				x: server_public_key_bytes.clone()
			}
			
			// Perform ECDH
			tc.shared_secret = vecc.ecdh(client_kp.private, server_pub_key)!
			return
		}
	}
	
	return error('server did not send key share extension')
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
