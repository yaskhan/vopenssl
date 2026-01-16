module tls

import net
import time
import vopenssl.ecc

pub enum ConnectionState {
	idle
	handshaking
	connected
	closing
	closed
	error
}

pub struct TLSConfig {
pub:
	// Version configuration
	min_version u16 = version_tls_12
	max_version u16 = version_tls_13

	// Cipher suites
	cipher_suites []u16 = get_default_cipher_suites()

	// Certificates
	certificates [][]u8 // DER-encoded certificates
	private_key  []u8   // DER-encoded private key

	// Certificate verification
	root_cas             [][]u8 // DER-encoded root CAs
	insecure_skip_verify bool

	// Server name (for client connections)
	server_name string

	// Session resumption
	session_cache bool = true

	// ALPN protocols
	next_protos []string

	// Timeouts
	handshake_timeout time.Duration = 30 * time.second
	read_timeout      time.Duration
	write_timeout     time.Duration
}

pub struct TLSConnection {
mut:
	conn           net.TcpConn
	config         TLSConfig
	state          ConnectionState
	version        u16
	cipher_suite   ?CipherSuite
	record_layer   RecordLayer
	handshake_hash []u8
	master_secret  []u8
	client_random  []u8
	server_random  []u8
	
	// TLS 1.3 Secrets
	early_secret                      []u8
	shared_secret                     []u8
	handshake_secret                  []u8
	client_handshake_traffic_secret   []u8
	server_handshake_traffic_secret   []u8
	client_application_traffic_secret []u8
	server_application_traffic_secret []u8
	
	// Ephemeral key (for TLS 1.3 key share)
	client_key_pair ?ecc.ECKeyPair
	
	is_client      bool
	server_name    string
pub mut:
	peer_certificates [][]u8
}

pub struct Alert {
pub:
	level       u8
	description u8
}

// new_client creates a new TLS client connection
pub fn new_client(conn net.TcpConn, config TLSConfig) TLSConnection {
	return TLSConnection{
		conn:         conn
		config:       config
		state:        .idle
		version:      config.max_version
		record_layer: new_record_layer(config.max_version)
		is_client:    true
		server_name:  config.server_name
	}
}

// new_server creates a new TLS server connection
pub fn new_server(conn net.TcpConn, config TLSConfig) TLSConnection {
	return TLSConnection{
		conn:         conn
		config:       config
		state:        .idle
		version:      config.min_version
		record_layer: new_record_layer(config.min_version)
		is_client:    false
	}
}

// handshake performs the TLS handshake
pub fn (mut tc TLSConnection) handshake() ! {
	if tc.state != .idle {
		return error('handshake already in progress or completed')
	}

	tc.state = .handshaking

	if tc.is_client {
		tc.client_handshake()!
	} else {
		tc.server_handshake()!
	}

	tc.state = .connected
}

// read reads decrypted application data from the connection
pub fn (mut tc TLSConnection) read(mut buf []u8) !int {
	if tc.state != .connected {
		return error('connection not established')
	}

	// Read TLS record
	mut record_header := []u8{len: 5}
	_ := tc.conn.read(mut record_header)!

	record := read_record(record_header)!

	// Read the fragment
	mut fragment := []u8{len: int(record.length)}
	_ := tc.conn.read(mut fragment)!

	full_record := TLSRecord{
		...record
		fragment: fragment
	}

	// Decrypt if needed
	decrypted := tc.record_layer.decrypt_record(full_record)!

	// Handle different content types
	match decrypted.content_type {
		content_type_application_data {
			// Copy to buffer
			copy_len := if decrypted.fragment.len < buf.len {
				decrypted.fragment.len
			} else {
				buf.len
			}
			for i in 0 .. copy_len {
				buf[i] = decrypted.fragment[i]
			}
			return copy_len
		}
		content_type_alert {
			// Handle alert
			tc.handle_alert(decrypted.fragment)!
			return 0
		}
		else {
			return error('unexpected content type: ${decrypted.content_type}')
		}
	}
}

// write writes application data to the connection (encrypted)
pub fn (mut tc TLSConnection) write(data []u8) !int {
	if tc.state != .connected {
		return error('connection not established')
	}

	// Split into records if necessary
	records := split_into_records(content_type_application_data, tc.version, data)

	mut total_written := 0

	for record in records {
		// Encrypt record
		encrypted := tc.record_layer.encrypt_record(record)!

		// Serialize and write
		serialized := write_record(encrypted)
		written := tc.conn.write(serialized)!
		total_written += written
	}

	return total_written
}

// close closes the TLS connection gracefully
pub fn (mut tc TLSConnection) close() ! {
	if tc.state == .closed {
		return
	}

	tc.state = .closing

	// Send close_notify alert
	tc.send_alert(.warning, alert_close_notify)!

	tc.conn.close()!
	tc.state = .closed
}

// send_alert sends a TLS alert
pub fn (mut tc TLSConnection) send_alert(level AlertLevel, description u8) ! {
	alert_data := [u8(level), description]

	record := create_record(content_type_alert, tc.version, alert_data)!
	serialized := write_record(record)

	tc.conn.write(serialized)!
}

// handle_alert handles received alerts
fn (mut tc TLSConnection) handle_alert(data []u8) ! {
	if data.len < 2 {
		return error('invalid alert')
	}

	level := data[0]
	description := data[1]

	if level == alert_level_fatal {
		tc.state = .error
		return error('fatal alert received: ${description}')
	}

	if description == alert_close_notify {
		tc.state = .closing
	}
}

pub enum AlertLevel {
	warning = 1
	fatal   = 2
}

// get_version returns the negotiated TLS version
pub fn (tc TLSConnection) get_version() u16 {
	return tc.version
}

// get_cipher_suite returns the negotiated cipher suite
pub fn (tc TLSConnection) get_cipher_suite() ?CipherSuite {
	return tc.cipher_suite
}

// version_string returns a human-readable version string
pub fn version_string(version u16) string {
	return match version {
		version_tls_10 { 'TLS 1.0' }
		version_tls_11 { 'TLS 1.1' }
		version_tls_12 { 'TLS 1.2' }
		version_tls_13 { 'TLS 1.3' }
		else { 'Unknown' }
	}
}
