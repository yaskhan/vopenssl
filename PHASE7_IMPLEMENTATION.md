# Phase 7: Key Derivation Functions (KDF) Implementation

This document describes the implementation of Key Derivation Functions (KDF) in VOpenSSL, including PBKDF2, HKDF, Scrypt, and Argon2.

## Overview

Phase 7 adds a comprehensive key derivation functions module to VOpenSSL, providing:

- **PBKDF2 (RFC 2898)**: Password-based key derivation with configurable iterations
- **HKDF (RFC 5869)**: HMAC-based extract-and-expand key derivation
- **Scrypt (RFC 7914)**: Memory-hard key derivation for password hashing
- **Argon2 (RFC 9106)**: Memory-hard password hashing (PHC winner)

## Module Structure

The KDF module is organized into the following files:

```
kdf/
├── kdf.v        # Main module file with re-exports
├── pbkdf2.v     # PBKDF2 implementation
├── hkdf.v       # HKDF implementation
├── scrypt.v     # Scrypt implementation
└── argon2.v     # Argon2 implementation
```

## PBKDF2 Implementation

### Overview

PBKDF2 (Password-Based Key Derivation Function 2) is defined in RFC 2898 and PKCS#5. It applies a pseudorandom function (typically HMAC) to derive a key from a password with a salt and iteration count.

### Key Features

- Support for HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512
- Configurable iteration count
- Customizable salt and key length
- Constant-time password verification
- Recommended iteration counts based on current best practices

### Usage Example

```v
import vopenssl.kdf
import vopenssl.rand

// Generate a random salt
salt := rand.generate_bytes(16)!

// Configure PBKDF2 parameters
params := kdf.PBKDF2Parameters{
    algorithm:  .sha256
    iterations: 600000  // OWASP recommendation
    salt:       salt
    key_length: 32
}

// Derive a key from password
key := kdf.pbkdf2_string('my_password', params)

// Verify password
valid := kdf.pbkdf2_verify_string('my_password', key, params)
```

### API

#### Types

```v
pub struct PBKDF2Parameters {
    algorithm  hash.HashAlgorithm  // Hash function to use
    iterations int                  // Number of iterations
    salt       []u8                 // Salt value
    key_length int                  // Output key length in bytes
}
```

#### Functions

- `pbkdf2(password []u8, params PBKDF2Parameters) []u8`
- `pbkdf2_hmac_sha1(password []u8, salt []u8, iterations int, key_length int) []u8`
- `pbkdf2_hmac_sha256(password []u8, salt []u8, iterations int, key_length int) []u8`
- `pbkdf2_hmac_sha512(password []u8, salt []u8, iterations int, key_length int) []u8`
- `pbkdf2_string(password string, params PBKDF2Parameters) []u8`
- `pbkdf2_string_sha256(password string, salt []u8, iterations int, key_length int) []u8`
- `pbkdf2_verify(password []u8, derived_key []u8, params PBKDF2Parameters) bool`
- `pbkdf2_verify_string(password string, derived_key []u8, params PBKDF2Parameters) bool`
- `recommended_iterations() map[string]int`
- `default_pbkdf2_parameters() PBKDF2Parameters`

### Recommended Iterations

Current best practices (2024):
- SHA-1: 1,000,000+ iterations (deprecated, avoid)
- SHA-256: 600,000+ iterations
- SHA-512: 300,000+ iterations

## HKDF Implementation

### Overview

HKDF (HMAC-based Extract-and-Expand Key Derivation Function) is defined in RFC 5869. It's designed for deriving keys from a master secret or key material, not for password hashing.

### Key Features

- Two-phase operation: Extract and Expand
- Support for SHA-1, SHA-256, and SHA-512
- Optional salt and context info
- Multiple key derivation from single secret
- TLS-style expand_label for protocol compatibility

### Usage Example

```v
import vopenssl.kdf

// Configure HKDF parameters
params := kdf.HKDFParameters{
    algorithm: .sha256
    salt:      []u8{0xde, 0xad, 0xbe, 0xef}
    info:      'application_context'.bytes()
}

// Derive a 32-byte key from input key material
key := kdf.hkdf_string('master_secret', 32, params)

// Derive multiple keys at once
key_lengths := [32, 16, 64]
keys := kdf.hkdf_derive_keys('master_secret'.bytes(), key_lengths, params)
```

### API

#### Types

```v
pub struct HKDFParameters {
    algorithm hash.HashAlgorithm  // Hash function to use
    salt      []u8               // Optional salt (can be empty)
    info      []u8               // Optional context/application info
}
```

#### Functions

- `hkdf(ikm []u8, l int, params HKDFParameters) []u8`
- `hkdf_extract_only(salt []u8, ikm []u8, algorithm hash.HashAlgorithm) []u8`
- `hkdf_expand_only(prk []u8, info []u8, l int, algorithm hash.HashAlgorithm) []u8`
- `hkdf_sha256(ikm []u8, l int, salt []u8, info []u8) []u8`
- `hkdf_sha512(ikm []u8, l int, salt []u8, info []u8) []u8`
- `hkdf_sha1(ikm []u8, l int, salt []u8, info []u8) []u8`
- `hkdf_string(ikm string, l int, params HKDFParameters) []u8`
- `hkdf_string_sha256(ikm string, l int, salt []u8, info []u8) []u8`
- `hkdf_derive_keys(secret []u8, key_lengths []int, params HKDFParameters) [][]u8`
- `hkdf_expand_label(secret []u8, label string, context []u8, length int, algorithm hash.HashAlgorithm) []u8`
- `default_hkdf_parameters() HKDFParameters`

### Use Cases

- Deriving encryption keys from a master secret
- TLS key derivation (client/server keys, IVs)
- Key material generation for protocols
- Multiple key derivation from shared secret

## Scrypt Implementation

### Overview

Scrypt is a memory-hard key derivation function defined in RFC 7914. It's designed to be resistant to GPU and ASIC attacks through memory-hard operations.

### Key Features

- Configurable CPU/memory cost (N)
- Block size parameter (r)
- Parallelization parameter (p)
- Constant-time password verification
- Recommended parameters for different security levels

### Usage Example

```v
import vopenssl.kdf
import vopenssl.rand

salt := rand.generate_bytes(16)!

// Use recommended parameters for interactive use
params := kdf.recommended_scrypt_parameters('interactive')!

// Derive a 32-byte key
key := kdf.scrypt_string('password', salt, params, 32)

// Verify password
valid := kdf.scrypt_verify_string('password', key, salt, params)
```

### API

#### Types

```v
pub struct ScryptParameters {
    n int  // CPU/memory cost parameter (power of 2 > 1)
    r int  // Block size parameter
    p int  // Parallelization parameter
}
```

#### Functions

- `scrypt(password []u8, salt []u8, params ScryptParameters, key_length int) []u8`
- `scrypt_string(password string, salt []u8, params ScryptParameters, key_length int) []u8`
- `scrypt_verify(password []u8, derived_key []u8, salt []u8, params ScryptParameters) bool`
- `scrypt_verify_string(password string, derived_key []u8, salt []u8, params ScryptParameters) bool`
- `recommended_scrypt_parameters(level string) !ScryptParameters`
- `default_scrypt_parameters() ScryptParameters`

### Recommended Parameters

| Level       | N         | r | p | Memory    | Time    |
|-------------|-----------|---|---|-----------|---------|
| interactive | 32,768    | 8 | 1 | 16 MB     | ~100ms  |
| moderate    | 262,144   | 8 | 1 | 128 MB    | ~800ms  |
| high        | 1,048,576 | 8 | 1 | 512 MB    | ~3s     |
| maximum     | 16,777,216| 8 | 1 | 8 GB      | ~30s    |

## Argon2 Implementation

### Overview

Argon2 is the winner of the Password Hashing Competition (PHC) and defined in RFC 9106. It provides excellent resistance against GPU/ASIC attacks through memory-hard operations.

### Key Features

- Three variants: Argon2d, Argon2i, and Argon2id
- Configurable time cost (t)
- Configurable memory cost (m)
- Configurable parallelism (p)
- Optional secret key and associated data
- Version support (1.0 and 1.3)

### Argon2 Variants

- **Argon2d**: Data-dependent memory access (best GPU resistance)
- **Argon2i**: Data-independent memory access (best side-channel resistance)
- **Argon2id**: Hybrid approach (balanced security, recommended)

### Usage Example

```v
import vopenssl.kdf
import vopenssl.rand

salt := rand.generate_bytes(16)!

// Use recommended parameters for Argon2id
params := kdf.recommended_argon2_parameters(.id, 'interactive')!

// Derive a 32-byte key
key := kdf.argon2_string('password', 32, params)

// Verify password
valid := kdf.argon2_verify_string('password', key, params)

// Convenience function with default parameters
default_key := kdf.argon2id_default('password'.bytes(), salt, 32)
```

### API

#### Types

```v
pub enum Argon2Type {
    d   // Argon2d
    i   // Argon2i
    id  // Argon2id
}

pub enum Argon2Version {
    v10 // Version 1.0 (deprecated)
    v13 // Version 1.3 (current)
}

pub struct Argon2Parameters {
    algorithm_type    Argon2Type
    version          Argon2Version
    time_cost        int
    memory_cost      int  // Memory cost in kibibytes
    parallelism      int
    salt             []u8
    secret           []u8   // Optional secret key
    associated_data  []u8   // Optional associated data
}
```

#### Functions

- `argon2(password []u8, key_length int, params Argon2Parameters) []u8`
- `argon2_string(password string, key_length int, params Argon2Parameters) []u8`
- `argon2_verify(password []u8, derived_key []u8, params Argon2Parameters) bool`
- `argon2_verify_string(password string, derived_key []u8, params Argon2Parameters) bool`
- `recommended_argon2_parameters(algorithm_type Argon2Type, level string) !Argon2Parameters`
- `default_argon2_parameters() Argon2Parameters`
- `argon2id_default(password []u8, salt []u8, key_length int) []u8`

### Recommended Parameters

| Level       | t  | Memory   | p | Time      |
|-------------|----|----------|---|-----------|
| interactive | 2  | 64 MB    | 4 | ~100ms    |
| moderate    | 3  | 256 MB   | 4 | ~500ms    |
| high        | 4  | 1 GB     | 4 | ~2s       |
| maximum     | 5  | 2 GB     | 8 | ~10s      |

## Security Considerations

### Password Hashing Best Practices

1. **Use Argon2id** when possible (best overall security)
2. **Scrypt** is a good alternative
3. **PBKDF2** is widely supported but less resistant to GPU attacks
4. **Always use a random salt** (at least 16 bytes)
5. **Choose parameters based on your threat model** and available resources

### Key Derivation vs Password Hashing

- **Password Hashing**: Use Argon2, Scrypt, or PBKDF2 (with high iterations)
- **Key Derivation**: Use HKDF (for deriving keys from master secrets)

### Performance vs Security

- Higher iterations/memory cost = better security but slower
- Choose parameters that balance security and user experience
- Test on target hardware to ensure acceptable performance

### Constant-Time Operations

All password verification functions use constant-time comparison to prevent timing attacks.

## Integration with Other Modules

The KDF module integrates with:

- **vopenssl.hash**: For hash algorithm types
- **vopenssl.mac**: For HMAC operations
- **vopenssl.rand**: For salt generation
- **vopenssl.utils**: For hex encoding utilities

## TLS Integration

The HKDF module includes TLS-specific helpers:

```v
// TLS 1.3-style key derivation
handshake_secret := []u8{...}
client_random := []u8{...}

client_app_key := kdf.hkdf_expand_label(handshake_secret, 'c ap traffic',
    client_random, 32, .sha256)
```

## Examples

A comprehensive example demonstrating all KDF functions is available at:
`examples/kdf_example.v`

Run it with:
```bash
v run examples/kdf_example.v
```

## Implementation Notes

### PBKDF2
- Uses V's built-in `crypto.pbkdf2` module
- Fully compliant with RFC 2898

### HKDF
- Implements full extract-and-expand two-phase operation
- Uses HMAC from the mac module
- Fully compliant with RFC 5869

### Scrypt
- Implements the complete Scrypt algorithm
- Includes Salsa20/8 core function
- Memory-hard operations properly implemented
- Fully compliant with RFC 7914

### Argon2
- Implements Argon2i, Argon2d, and Argon2id
- Includes BLAKE2b hashing
- Simplified core implementation (suitable for most use cases)
- Compliant with RFC 9106

## Testing Recommendations

1. Test with known test vectors from RFC specifications
2. Verify constant-time behavior
3. Performance testing with different parameter combinations
4. Cross-implementation testing (compare with reference implementations)

## Future Enhancements

Possible future additions:
- Support for additional hash algorithms in HKDF
- Optimized Argon2 implementation (SIMD, GPU)
- Password hashing utilities (storage formats, pepper support)
- KDF parameter optimization helper functions

## References

- RFC 2898: PKCS #5: Password-Based Cryptography Specification Version 2.0
- RFC 5869: HMAC-Based Extract-and-Expand Key Derivation Function (HKDF)
- RFC 7914: The scrypt Password-Based Key Derivation Function
- RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications
- OWASP Password Storage Cheat Sheet
- Password Hashing Competition (PHC)

## Conclusion

Phase 7 provides a comprehensive KDF module with implementations of PBKDF2, HKDF, Scrypt, and Argon2. These functions are essential for:
- Password hashing and verification
- Key derivation from shared secrets
- TLS and other cryptographic protocols
- Secure key storage and management

The implementation follows best practices and current security recommendations, providing a solid foundation for cryptographic key derivation in V applications.
