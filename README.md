# VOpenSSL

High-level cryptographic library for V language - OpenSSL-style API built on V's crypto module.

## Overview

VOpenSSL provides a comprehensive, easy-to-use cryptographic library for V that wraps and extends the built-in `crypto` module. It offers:

- **Unified API**: Consistent interface across all cryptographic operations
- **High-level Functions**: Simplified APIs for common use cases
- **OpenSSL Compatibility**: Familiar API design for developers coming from OpenSSL
- **Pure V**: Built on V's native crypto module with no external dependencies (Phase 1)
- **Type Safety**: Leverages V's type system for safer cryptographic code

## Features

### Current (Phase 1-6)

- ✅ **Random Number Generation**: Cryptographically secure random bytes, keys, and IVs
- ✅ **Hashing**: SHA-1, SHA-256, SHA-512, BLAKE2b, BLAKE2s, MD5 (One-shot wrappers)
- ✅ **HMAC**: Message authentication codes with all hash algorithms
- ✅ **Symmetric Encryption**: AES with CBC and CTR modes
- ✅ **Utilities**: Padding, hex encoding, constant-time operations
- ✅ **Encoding**: Base64, PEM, ASN.1 DER encoding/decoding
- ✅ **X.509 Certificates**: Parsing, validation, CSR creation, PEM/DER utilities
- ✅ **TLS/SSL**: TLS 1.2 and 1.3 client/server implementation

### Planned (Future Phases)

- 🔄 **Authenticated Encryption**: AES-GCM
- 🔄 **Incremental Hashing**: Streaming API for hashes and MACs
- 🔄 **Key Derivation**: PBKDF2, HKDF, Scrypt, Argon2

## Installation

```bash
v install vopenssl
```

Or add to your `v.mod`:

```v
dependencies: ['vopenssl']
```

## Quick Start

### Hashing

```v
import vopenssl.hash
import vopenssl.utils

// Hash a string
data := 'Hello, World!'.bytes()
hash_result := hash.sha256(data)
println('SHA-256: ${utils.hex(hash_result)}')

// Hash a file
file_hash := hash.sha256_file('document.pdf')!
println('File SHA-256: ${utils.hex(file_hash)}')
```

### HMAC

```v
import vopenssl.mac

key := 'secret-key'.bytes()
message := 'Important message'.bytes()

// Generate HMAC
mac_result := mac.hmac_sha256(key, message)

// Verify HMAC
is_valid := mac.verify_hmac(message, mac_result, key, .sha256)
println('HMAC valid: ${is_valid}')
```

### Symmetric Encryption

```v
import vopenssl.cipher
import vopenssl.rand

// Generate a random key
key := rand.generate_key(256)! // 256-bit AES key

// Encrypt data (using AES-CBC)
plaintext := 'Secret message'.bytes()
mut aes := cipher.new_aes_cbc(key)!
ciphertext := aes.encrypt(plaintext)!

// Decrypt data
decrypted := aes.decrypt(ciphertext)!
println('Decrypted: ${decrypted.bytestr()}')

// Encrypt a file
mut file_aes := cipher.new_aes_cbc(key)!
file_aes.encrypt_file('input.txt', 'output.enc')!
file_aes.decrypt_file('output.enc', 'decrypted.txt')!
```

### Encoding

```v
import vopenssl.encoding

// Base64
encoded := encoding.base64_encode('Hello'.bytes())
decoded := encoding.base64_decode(encoded)!

// PEM
pem_str := encoding.pem_encode('PRIVATE KEY', {}, key_bytes)
block := encoding.pem_decode(pem_str)!
println('Type: ${block.type_}')
```

### Random Number Generation

```v
import vopenssl.rand

// Generate random bytes
random_bytes := rand.bytes(32)!

// Generate a cryptographic key
aes_key := rand.generate_key(256)! // 256-bit key

// Generate an IV
iv := rand.generate_iv(16)! // 16-byte IV for AES

// Random integer in range
random_num := rand.int_in_range(1, 100)!
```

### X.509 Certificates

```v
import vopenssl.x509

// Load a certificate from file
cert := x509.load_certificate('cert.pem')!

// Check certificate validity
is_valid := cert.is_valid_now()
is_expired := cert.is_expired()

// Get certificate information
subject := cert.get_subject()
println('Subject: ${subject.common_name}')
println('Issuer: ${cert.get_issuer().common_name}')

// Validate certificate
opts := x509.ValidationOptions{
    current_time: time.now()
    dns_name: 'example.com'
    allow_expired: false
}
result := x509.validate_certificate(cert, [], opts)!
```

### TLS/SSL

```v
import vopenssl.tls

// TLS Client
config := tls.TLSConfig{
    min_version: tls.version_tls_12
    max_version: tls.version_tls_13
    server_name: 'example.com'
}

mut conn := tls.dial('example.com:443', config)!
println('Connected with ${tls.version_string(conn.get_version())}')

conn.write('GET / HTTP/1.1\r\n\r\n'.bytes())!
mut buffer := []u8{len: 4096}
bytes_read := conn.read(mut buffer)!
println(buffer[..bytes_read].bytestr())
conn.close()!

// TLS Server
server_config := tls.TLSConfig{
    certificates: [cert_der]
    private_key: key_der
}

mut listener := tls.listen(':8443', server_config)!
for {
    mut conn := listener.accept()!
    // Handle connection
    conn.close()!
}
```

## Module Structure

```
vopenssl/
├── rand/          # Random number generation
├── hash/          # Hashing algorithms (SHA, BLAKE, MD5)
├── mac/           # HMAC and message authentication
├── cipher/        # Symmetric encryption (AES, modes)
├── encoding/      # Encoding (Base64, PEM, ASN.1)
├── x509/          # X.509 certificates, CSRs, validation
├── tls/           # TLS 1.2 and 1.3 client/server
├── utils/         # Utilities (padding, hex, etc.)
```

## Documentation

Full API documentation is available at: [docs link]

## Examples

See the `examples/` directory for complete working examples:

- `hash_file.v` - File hashing with different algorithms
- `encrypt_file.v` - AES-CBC file encryption/decryption
- `hmac_example.v` - HMAC generation and verification
- `x509_example.v` - X.509 certificate parsing and validation
- `csr_example.v` - Certificate Signing Request creation and management
- `tls_client_example.v` - TLS client connection example
- `tls_server_example.v` - TLS server implementation example

## Development Status

**Current Version**: 0.2.0 (Phase 6)

This library is under active development. Phases 1-6 are complete (core cryptography, encoding, X.509 certificates, and TLS/SSL). Future phases will add key derivation functions and additional features.

## Roadmap

- [x] Phase 1: Project setup and wrapper layer
- [x] Phase 2: Encoding (PEM, DER, ASN.1)
- [x] Phase 3: Asymmetric cryptography (RSA, ECC)
- [x] Phase 4: X.509 certificates
- [x] Phase 5: Certificate parsing, validation, CSR creation
- [x] Phase 6: TLS/SSL client/server (TLS 1.2 and 1.3)
- [ ] Phase 7: Key derivation functions (PBKDF2, HKDF, Argon2)

## Security

⚠️ **Important Security Notes**:

- This library is built on V's `crypto` module
- Always use cryptographically secure random numbers from `vopenssl.rand`
- MD5 and SHA-1 are provided for compatibility but should not be used for security-critical applications
- Keep your dependencies updated

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

Built on top of V's excellent built-in `crypto` module. Inspired by OpenSSL's API design.
