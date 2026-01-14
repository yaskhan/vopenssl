# Phase 6 Implementation: TLS/SSL

This document describes the TLS 1.2 and TLS 1.3 implementation in VOpenSSL.

## Overview

Phase 6 adds complete TLS (Transport Layer Security) support to VOpenSSL, implementing both TLS 1.2 and TLS 1.3 protocols. This includes:

- TLS record layer protocol
- TLS handshake protocol
- Cipher suite management
- Client implementation
- Server implementation
- Both TLS 1.2 and TLS 1.3 support

## Module Structure

```
tls/
├── constants.v       # TLS protocol constants
├── ciphers.v         # Cipher suite definitions
├── record.v          # Record layer protocol
├── handshake.v       # Handshake protocol
├── tls.v             # Core TLS types and utilities
├── tls12.v           # TLS 1.2 specific implementation
├── tls13.v           # TLS 1.3 specific implementation
├── client.v          # TLS client implementation
└── server.v          # TLS server implementation
```

## TLS Constants

### Protocol Versions
- TLS 1.0: `0x0301`
- TLS 1.1: `0x0302`
- TLS 1.2: `0x0303`
- TLS 1.3: `0x0304`

### Content Types
- ChangeCipherSpec: `20`
- Alert: `21`
- Handshake: `22`
- ApplicationData: `23`

### Handshake Message Types
- ClientHello: `1`
- ServerHello: `2`
- Certificate: `11`
- ServerKeyExchange: `12`
- CertificateRequest: `13`
- ServerHelloDone: `14`
- CertificateVerify: `15`
- ClientKeyExchange: `16`
- Finished: `20`

### Extension Types
- server_name: `0`
- supported_groups: `10`
- signature_algorithms: `13`
- alpn: `16`
- supported_versions: `43`
- key_share: `51`

## Cipher Suites

### TLS 1.2 Cipher Suites
- `TLS_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`

### TLS 1.3 Cipher Suites
- `TLS_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`

## Record Layer

The record layer provides:
- Framing of TLS messages
- Encryption/decryption of data
- Message authentication (for non-AEAD ciphers)
- Sequence number tracking

### Key Functions

```v
// Create a new record layer
fn new_record_layer(version u16) RecordLayer

// Read a TLS record from bytes
fn read_record(data []u8) !TLSRecord

// Write a TLS record to bytes
fn write_record(record TLSRecord) []u8

// Encrypt a record
fn (mut rl RecordLayer) encrypt_record(record TLSRecord) !TLSRecord

// Decrypt a record
fn (mut rl RecordLayer) decrypt_record(record TLSRecord) !TLSRecord
```

## Handshake Protocol

The handshake protocol manages:
- Protocol version negotiation
- Cipher suite selection
- Key exchange
- Authentication

### TLS 1.2 Handshake Flow

**Client:**
1. Send ClientHello
2. Receive ServerHello, Certificate, [ServerKeyExchange], ServerHelloDone
3. Send ClientKeyExchange, ChangeCipherSpec, Finished
4. Receive ChangeCipherSpec, Finished

**Server:**
1. Receive ClientHello
2. Send ServerHello, Certificate, [ServerKeyExchange], ServerHelloDone
3. Receive ClientKeyExchange, ChangeCipherSpec, Finished
4. Send ChangeCipherSpec, Finished

### TLS 1.3 Handshake Flow

**Client:**
1. Send ClientHello (with key_share)
2. Receive ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished
3. Send Finished

**Server:**
1. Receive ClientHello
2. Send ServerHello (with key_share), EncryptedExtensions, Certificate, CertificateVerify, Finished
3. Receive Finished

## TLS Configuration

```v
struct TLSConfig {
    min_version        u16
    max_version        u16
    cipher_suites      []u16
    certificates       [][]u8
    private_key        []u8
    root_cas           [][]u8
    insecure_skip_verify bool
    server_name        string
    session_cache      bool
    next_protos        []string
    handshake_timeout  time.Duration
    read_timeout       time.Duration
    write_timeout      time.Duration
}
```

## Client Usage

### Basic Client Connection

```v
import vopenssl.tls

// Configure TLS client
config := tls.TLSConfig{
    min_version: tls.version_tls_12
    max_version: tls.version_tls_13
    server_name: 'example.com'
}

// Connect to server
mut conn := tls.dial('example.com:443', config)!

// Get connection info
println('TLS Version: ${tls.version_string(conn.get_version())}')
if cipher_suite := conn.get_cipher_suite() {
    println('Cipher Suite: ${cipher_suite.name}')
}

// Send data
conn.write('GET / HTTP/1.1\r\n\r\n'.bytes())!

// Receive data
mut buffer := []u8{len: 4096}
bytes_read := conn.read(mut buffer)!
println(buffer[..bytes_read].bytestr())

// Close connection
conn.close()!
```

### Client with Custom Configuration

```v
import vopenssl.tls
import time

config := tls.TLSConfig{
    min_version: tls.version_tls_12
    max_version: tls.version_tls_13
    server_name: 'secure.example.com'
    cipher_suites: [
        tls.tls_aes_256_gcm_sha384,
        tls.tls_ecdhe_rsa_with_aes_256_gcm_sha384,
    ]
    handshake_timeout: 10 * time.second
    insecure_skip_verify: false
}

mut conn := tls.dial('secure.example.com:443', config)!
```

## Server Usage

### Basic Server

```v
import vopenssl.tls

// Load certificate and key
cert := []u8{}  // DER-encoded certificate
key := []u8{}   // DER-encoded private key

// Configure TLS server
config := tls.TLSConfig{
    min_version: tls.version_tls_12
    max_version: tls.version_tls_13
    certificates: [cert]
    private_key: key
}

// Start listening
mut listener := tls.listen(':8443', config)!

// Accept connections
for {
    mut conn := listener.accept()!
    
    // Handle connection
    mut buffer := []u8{len: 4096}
    bytes_read := conn.read(mut buffer)!
    
    response := 'HTTP/1.1 200 OK\r\n\r\nHello!'
    conn.write(response.bytes())!
    
    conn.close()!
}
```

## Connection Management

### TLSConnection Methods

```v
// Perform TLS handshake
fn (mut tc TLSConnection) handshake() !

// Read decrypted data
fn (mut tc TLSConnection) read(mut buf []u8) !int

// Write encrypted data
fn (mut tc TLSConnection) write(data []u8) !int

// Close connection gracefully
fn (mut tc TLSConnection) close() !

// Get negotiated TLS version
fn (tc TLSConnection) get_version() u16

// Get negotiated cipher suite
fn (tc TLSConnection) get_cipher_suite() ?CipherSuite
```

## Connection States

```v
enum ConnectionState {
    idle
    handshaking
    connected
    closing
    closed
    error
}
```

## Alert Handling

The TLS module handles various alert conditions:

### Alert Levels
- Warning: `1`
- Fatal: `2`

### Common Alerts
- close_notify: `0`
- unexpected_message: `10`
- bad_record_mac: `20`
- handshake_failure: `40`
- certificate_expired: `45`
- unknown_ca: `48`
- internal_error: `80`

## Security Considerations

### Best Practices

1. **Use TLS 1.2 or higher**: Set `min_version` to at least `tls.version_tls_12`
2. **Prefer TLS 1.3**: Set `max_version` to `tls.version_tls_13`
3. **Use strong cipher suites**: Prefer AEAD ciphers (GCM, ChaCha20-Poly1305)
4. **Verify certificates**: Set `insecure_skip_verify: false` in production
5. **Use proper timeouts**: Configure reasonable timeout values
6. **Keep certificates updated**: Monitor certificate expiration

### Recommended Cipher Suite Order

1. `TLS_AES_256_GCM_SHA384` (TLS 1.3)
2. `TLS_AES_128_GCM_SHA256` (TLS 1.3)
3. `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3)
4. `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (TLS 1.2)
5. `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (TLS 1.2)

## Implementation Notes

### Current Limitations

1. **Key Derivation**: The current implementation uses simplified key derivation. A production implementation would use proper HKDF for TLS 1.3 and PRF for TLS 1.2.

2. **Encryption**: The record layer encryption/decryption is currently simplified. Full implementation would integrate with the cipher module for actual AES-GCM encryption.

3. **Certificate Validation**: Certificate chain validation is simplified. Production use should integrate with the x509 module for proper validation.

4. **Session Resumption**: Session ticket and PSK-based resumption are not fully implemented.

5. **Advanced Features**: Some TLS features are not yet implemented:
   - Client authentication (client certificates)
   - Certificate status checking (OCSP)
   - Renegotiation
   - Post-handshake authentication (TLS 1.3)
   - 0-RTT (TLS 1.3)

### Future Enhancements

1. Complete key derivation functions (HKDF, PRF)
2. Full encryption/decryption integration
3. Complete certificate validation
4. Session resumption support
5. Client certificate authentication
6. OCSP stapling
7. ALPN (Application-Layer Protocol Negotiation)
8. SNI (Server Name Indication) - basic support exists
9. Performance optimizations

## Examples

See the `examples/` directory for complete working examples:

- `tls_client_example.v` - TLS client connecting to a server
- `tls_server_example.v` - TLS server handling connections

## Testing

To test the TLS implementation:

```bash
# Run client example (requires a TLS server)
v run examples/tls_client_example.v

# Run server example (requires certificates)
v run examples/tls_server_example.v
```

## References

- RFC 5246: The TLS Protocol Version 1.2
- RFC 8446: The TLS Protocol Version 1.3
- RFC 5288: AES Galois Counter Mode (GCM) Cipher Suites for TLS
- RFC 7539: ChaCha20 and Poly1305 for IETF Protocols

## Integration with VOpenSSL

The TLS module integrates with other VOpenSSL modules:

- **x509**: Certificate parsing and validation
- **cipher**: Symmetric encryption (AES-GCM)
- **hash**: Hashing for handshake transcript
- **rsa/ecc**: Key exchange and signature verification
- **rand**: Random number generation for nonces

## API Summary

### Main Functions

```v
// Client
fn dial(address string, config TLSConfig) !TLSConnection

// Server
fn listen(address string, config TLSConfig) !TLSListener
fn (mut tl TLSListener) accept() !TLSConnection

// Utilities
fn version_string(version u16) string
fn get_cipher_suite(id u16) ?CipherSuite
fn get_default_cipher_suites() []u16
```

### Types

- `TLSConfig` - TLS configuration
- `TLSConnection` - TLS connection
- `TLSListener` - TLS server listener
- `CipherSuite` - Cipher suite information
- `ConnectionState` - Connection state enum
- `TLSRecord` - TLS record structure
- `ClientHello` - ClientHello message
- `ServerHello` - ServerHello message
- `Extension` - TLS extension

---

**Note**: This is a foundational implementation of TLS. For production use, additional security auditing and feature completion would be required.
