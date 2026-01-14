module main

import vopenssl.tls
import vopenssl.x509

fn main() {
	// Load server certificate and private key
	// In a real application, you would load these from files
	cert := []u8{} // DER-encoded certificate
	key := []u8{} // DER-encoded private key

	// Configure TLS server
	config := tls.TLSConfig{
		min_version:  tls.version_tls_12
		max_version:  tls.version_tls_13
		certificates: [cert]
		private_key:  key
	}

	// Start listening
	println('Starting TLS server on :8443...')
	mut listener := tls.listen(':8443', config) or {
		eprintln('Failed to start server: ${err}')
		return
	}

	println('Server listening on :8443')

	// Accept connections
	for {
		println('Waiting for connection...')
		mut conn := listener.accept() or {
			eprintln('Failed to accept connection: ${err}')
			continue
		}

		println('Client connected!')
		println('TLS Version: ${tls.version_string(conn.get_version())}')

		if cipher_suite := conn.get_cipher_suite() {
			println('Cipher Suite: ${cipher_suite.name}')
		}

		// Handle connection in a separate function
		handle_client(mut conn)
	}
}

fn handle_client(mut conn tls.TLSConnection) {
	// Read client request
	mut buffer := []u8{len: 4096}
	bytes_read := conn.read(mut buffer) or {
		eprintln('Failed to read: ${err}')
		return
	}

	println('Received ${bytes_read} bytes:')
	println(buffer[..bytes_read].bytestr())

	// Send response
	response := 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nHello, World!'
	conn.write(response.bytes()) or {
		eprintln('Failed to write: ${err}')
		return
	}

	println('Response sent.')

	// Close connection
	conn.close() or { eprintln('Failed to close: ${err}') }

	println('Connection closed.')
}
