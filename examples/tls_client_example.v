module main

import vopenssl.tls

fn main() {
	// Configure TLS client
	config := tls.TLSConfig{
		min_version:          tls.version_tls_12
		max_version:          tls.version_tls_13
		server_name:          'example.com'
		insecure_skip_verify: true // For testing only!
	}

	// Connect to TLS server
	println('Connecting to example.com:443...')
	mut conn := tls.dial('example.com:443', config) or {
		eprintln('Failed to connect: ${err}')
		return
	}

	println('Connected!')
	println('TLS Version: ${tls.version_string(conn.get_version())}')

	if cipher_suite := conn.get_cipher_suite() {
		println('Cipher Suite: ${cipher_suite.name}')
	}

	// Send HTTP GET request
	request := 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'
	conn.write(request.bytes()) or {
		eprintln('Failed to write: ${err}')
		return
	}

	println('Request sent, reading response...')

	// Read response
	mut buffer := []u8{len: 4096}
	bytes_read := conn.read(mut buffer) or {
		eprintln('Failed to read: ${err}')
		return
	}

	println('Received ${bytes_read} bytes:')
	println(buffer[..bytes_read].bytestr())

	// Close connection
	conn.close() or { eprintln('Failed to close: ${err}') }

	println('Connection closed.')
}
