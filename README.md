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

### Current (Phase 1)

- ✅ **Random Number Generation**: Cryptographically secure random bytes, keys, and IVs
- ✅ **Hashing**: SHA-1, SHA-256, SHA-512, BLAKE2b, BLAKE2s, BLAKE3, MD5
- ✅ **HMAC**: Message authentication codes with all hash algorithms
- ✅ **Symmetric Encryption**: AES with multiple modes (CBC, CTR, GCM)
- ✅ **Utilities**: Padding, hex encoding, constant-time operations

### Planned (Future Phases)

- 🔄 **Asymmetric Crypto**: RSA, ECDSA, ECDH, Ed25519
- 🔄 **X.509 Certificates**: Parsing, validation, CSR creation
- 🔄 **TLS/SSL**: TLS 1.2 and 1.3 client/server
- 🔄 **Key Derivation**: PBKDF2, HKDF, Scrypt, Argon2
- 🔄 **Encoding**: PEM, DER, ASN.1

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

// Hash a string
data := 'Hello, World!'.bytes()
hash_result := hash.sha256(data)
println('SHA-256: ${hash_result.hex()}')

// Hash a file
file_hash := hash.sha256_file('document.pdf')!
println('File SHA-256: ${file_hash.hex()}')

// Incremental hashing
mut hasher := hash.new_sha256()
hasher.write('Part 1'.bytes())
hasher.write('Part 2'.bytes())
final_hash := hasher.sum()
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

// Encrypt data
plaintext := 'Secret message'.bytes()
mut aes := cipher.new_aes_gcm(key)!
ciphertext := aes.encrypt(plaintext)!

// Decrypt data
decrypted := aes.decrypt(ciphertext)!
println('Decrypted: ${decrypted.bytestr()}')

// Encrypt a file
cipher.encrypt_file_aes_gcm(key, 'input.txt', 'output.enc')!
cipher.decrypt_file_aes_gcm(key, 'output.enc', 'decrypted.txt')!
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

## Module Structure

```
vopenssl/
├── rand/          # Random number generation
├── hash/          # Hashing algorithms (SHA, BLAKE, MD5)
├── mac/           # HMAC and message authentication
├── cipher/        # Symmetric encryption (AES, modes)
└── utils/         # Utilities (padding, hex, etc.)
```

## Documentation

Full API documentation is available at: [docs link]

## Examples

See the `examples/` directory for complete working examples:

- `hash_file.v` - File hashing with different algorithms
- `encrypt_file.v` - AES-GCM file encryption/decryption
- `hmac_example.v` - HMAC generation and verification

## Development Status

**Current Version**: 0.1.0 (Phase 1)

This library is under active development. Phase 1 (wrapper layer) is complete. Future phases will add RSA, ECC, X.509, and TLS support.

## Roadmap

- [x] Phase 1: Project setup and wrapper layer
- [ ] Phase 2: Encoding (PEM, DER, ASN.1)
- [ ] Phase 3: Asymmetric cryptography (RSA, ECC)
- [ ] Phase 4: X.509 certificates
- [ ] Phase 5: TLS/SSL
- [ ] Phase 6: Key derivation functions

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
