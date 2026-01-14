// Key Derivation Functions Example
// This example demonstrates the use of PBKDF2, HKDF, Scrypt, and Argon2
import vopenssl.kdf
import vopenssl.rand
import vopenssl.utils

fn main() {
	println('=== VOpenSSL KDF Module Examples ===\n')

	// Generate a random salt for KDFs that need it
	salt := rand.generate_bytes(16)!
	println('Generated salt: ${utils.hex_encode(salt)}')

	// PBKDF2 Examples
	println('\n--- PBKDF2 Examples ---')
	example_pbkdf2('my_secure_password', salt)

	// HKDF Examples
	println('\n--- HKDF Examples ---')
	example_hkdf('master_secret_key')

	// Scrypt Examples
	println('\n--- Scrypt Examples ---')
	example_scrypt('my_secure_password', salt)

	// Argon2 Examples
	println('\n--- Argon2 Examples ---')
	example_argon2('my_secure_password', salt)

	// Password Hashing Comparison
	println('\n--- Password Hashing Comparison ---')
	compare_password_hashing()

	// TLS Key Derivation Example
	println('\n--- TLS Key Derivation Example ---')
	tls_key_derivation_example()

	println('\n=== All examples completed successfully ===')
}

fn example_pbkdf2(password string, salt []u8) {
	// Get recommended iterations
	iterations := kdf.recommended_pbkdf2_iterations()
	println('Recommended iterations for PBKDF2:')
	for alg, iter in iterations {
		println('  ${alg}: ${iter}')
	}

	// Derive key using default parameters
	params := kdf.default_pbkdf2_parameters()
	params.salt = salt

	// Generate a 32-byte (256-bit) key
	key := kdf.pbkdf2_string(password, params)
	println('Derived key (SHA-256, ${params.iterations} iterations): ${utils.hex_encode(key)}')

	// Using specific hash algorithm
	params_sha512 := kdf.PBKDF2Parameters{
		algorithm:  .sha512
		iterations: 300000
		salt:       salt
		key_length: 64
	}
	key_sha512 := kdf.pbkdf2_string(password, params_sha512)
	println('Derived key (SHA-512): ${utils.hex_encode(key_sha512)}')

	// Verify password
	valid := kdf.pbkdf2_verify_string(password, key, params)
	println('Password verification: ${valid}')

	// Try wrong password
	invalid := kdf.pbkdf2_verify_string('wrong_password', key, params)
	println('Wrong password verification: ${invalid}')
}

fn example_hkdf(ikm string) {
	// HKDF is useful for deriving keys from a master secret
	println('Input Key Material (IKM): ${ikm}')

	// Default parameters
	params := kdf.default_hkdf_parameters()
	params.salt = rand.generate_bytes(16)!
	params.info = 'application_context'.bytes()

	// Derive a single key
	derived_key := kdf.hkdf_string(ikm, 32, params)
	println('Derived key (32 bytes): ${utils.hex_encode(derived_key)}')

	// Derive multiple keys at once
	key_lengths := [32, 16, 64] // 256-bit, 128-bit, and 512-bit keys
	keys := kdf.hkdf_derive_keys(ikm.bytes(), key_lengths, params)
	println('\nDerived multiple keys:')
	for i, key in keys {
		println('  Key ${i + 1} (${key.len * 8}-bit): ${utils.hex_encode(key)}')
	}

	// Using HKDF with specific hash functions
	key_sha256 := kdf.hkdf_string_sha256(ikm, 32, params.salt, params.info)
	key_sha512 := kdf.hkdf_string_sha512(ikm, 64, params.salt, params.info)
	println('\nHKDF-SHA256 key: ${utils.hex_encode(key_sha256)}')
	println('HKDF-SHA512 key: ${utils.hex_encode(key_sha512)}')

	// TLS-style expand with label
	master_secret := [u8(0)].repeat(48)
	client_random := rand.generate_bytes(32)!
	server_random := rand.generate_bytes(32)!

	client_app_key := kdf.hkdf_expand_label(master_secret, 'c ap traffic', client_random,
		32, .sha256)
	server_app_key := kdf.hkdf_expand_label(master_secret, 's ap traffic', server_random,
		32, .sha512)

	println('\nTLS-style derived keys:')
	println('  Client application key: ${utils.hex_encode(client_app_key)}')
	println('  Server application key: ${utils.hex_encode(server_app_key)}')
}

fn example_scrypt(password string, salt []u8) {
	// Get recommended parameters for different security levels
	levels := ['interactive', 'moderate', 'high']
	println('Recommended Scrypt parameters:')
	for level in levels {
		params := kdf.recommended_scrypt_parameters(level)!
		println('  ${level}: N=${params.n}, r=${params.r}, p=${params.p}')
	}

	// Use interactive parameters (faster)
	params := kdf.recommended_scrypt_parameters('interactive')!
	params.salt = salt

	// Derive a 32-byte key
	key := kdf.scrypt_string(password, salt, params, 32)
	println('\nDerived key (N=${params.n}, r=${params.r}, p=${params.p}): ${utils.hex_encode(key)}')

	// Verify password
	valid := kdf.scrypt_verify_string(password, key, salt, params)
	println('Password verification: ${valid}')

	// Try different security level
	high_params := kdf.recommended_scrypt_parameters('high')!
	high_params.salt = salt

	println('\nDeriving key with high security parameters...')
	high_key := kdf.scrypt_string(password, salt, high_params, 32)
	println('High security key: ${utils.hex_encode(high_key)}')
}

fn example_argon2(password string, salt []u8) {
	// Argon2 has three variants: d, i, and id
	types := [kdf.Argon2Type.d, kdf.Argon2Type.i, kdf.Argon2Type.id]
	println('Argon2 variants:')
	for t in types {
		println('  Argon2${t.str()}: ${get_argon2_description(t)}')
	}

	// Recommended parameters for Argon2id
	params := kdf.recommended_argon2_parameters(.id, 'interactive')!
	params.salt = salt

	// Derive a 32-byte key
	key := kdf.argon2_string(password, 32, params)
	println('\nDerived key with Argon2id:')
	println('  Parameters: t=${params.time_cost}, m=${params.memory_cost}KB, p=${params.parallelism}')
	println('  Key: ${utils.hex_encode(key)}')

	// Verify password
	valid := kdf.argon2_verify_string(password, key, params)
	println('  Password verification: ${valid}')

	// Using default Argon2id function (convenience)
	default_key := kdf.argon2id_default(password.bytes(), salt, 32)
	println('\nDerived key using argon2id_default: ${utils.hex_encode(default_key)}')

	// Compare Argon2 variants
	println('\nComparing Argon2 variants:')
	for t in types {
		variant_params := kdf.recommended_argon2_parameters(t, 'interactive')!
		variant_params.salt = salt
		variant_key := kdf.argon2_string(password, 32, variant_params)
		println('  Argon2${t.str()}: ${utils.hex_encode(variant_key)}')
	}
}

fn compare_password_hashing() {
	password := 'user_password_123'
	salt := rand.generate_bytes(16)!

	// Compare different password hashing methods
	println('Deriving 32-byte keys from password "${password}" with different methods:')

	// PBKDF2
	pbkdf2_params := kdf.default_pbkdf2_parameters()
	pbkdf2_params.salt = salt
	pbkdf2_key := kdf.pbkdf2_string(password, pbkdf2_params)
	println('  PBKDF2-SHA256 (${pbkdf2_params.iterations} iter): ${utils.hex_encode(pbkdf2_key)}')

	// Scrypt
	scrypt_params := kdf.default_scrypt_parameters()
	scrypt_params.salt = salt
	scrypt_key := kdf.scrypt_string(password, salt, scrypt_params, 32)
	println('  Scrypt (N=${scrypt_params.n}, r=${scrypt_params.r}, p=${scrypt_params.p}): ${utils.hex_encode(scrypt_key)}')

	// Argon2id
	argon2_params := kdf.default_argon2_parameters()
	argon2_params.salt = salt
	argon2_key := kdf.argon2_string(password, 32, argon2_params)
	println('  Argon2id (t=${argon2_params.time_cost}, m=${argon2_params.memory_cost}KB, p=${argon2_params.parallelism}): ${utils.hex_encode(argon2_key)}')

	println('\nNote: Each method produces different results. For password hashing in production:')
	println('  - Prefer Argon2id (memory-hard, side-channel resistant)')
	println('  - Scrypt is a good alternative')
	println('  - PBKDF2 is widely supported but less resistant to GPU attacks')
}

fn tls_key_derivation_example() {
	// Simulate TLS key derivation using HKDF
	master_secret := rand.generate_bytes(48)!
	client_random := rand.generate_bytes(32)!
	server_random := rand.generate_bytes(32)!

	// Combine randoms
	mut transcript_hash := []u8{cap: 64}
	transcript_hash << client_random
	transcript_hash << server_random

	// Extract phase
	salt := [u8(0)].repeat(32)
	prk := kdf.hkdf_extract_only(salt, master_secret, .sha256)

	// Expand phase to derive keys
	client_key := kdf.hkdf_expand_only(prk, 'c ap traffic'.bytes(), 32, .sha256)
	server_key := kdf.hkdf_expand_only(prk, 's ap traffic'.bytes(), 32, .sha256)
	client_iv := kdf.hkdf_expand_only(prk, 'c iv'.bytes(), 16, .sha256)
	server_iv := kdf.hkdf_expand_only(prk, 's iv'.bytes(), 16, .sha256)

	println('TLS 1.3-style key derivation:')
	println('  Master Secret: ${utils.hex_encode(master_secret)}')
	println('  Client Key: ${utils.hex_encode(client_key)}')
	println('  Server Key: ${utils.hex_encode(server_key)}')
	println('  Client IV: ${utils.hex_encode(client_iv)}')
	println('  Server IV: ${utils.hex_encode(server_iv)}')

	// Alternative: using expand_label helper
	handshake_secret := rand.generate_bytes(32)!
	derived_secret := kdf.hkdf_expand_label(handshake_secret, 'derived', [u8(0)].repeat(32),
		32, .sha256)

	println('\nTLS 1.3 expand_label example:')
	println('  Handshake Secret: ${utils.hex_encode(handshake_secret)}')
	println('  Derived Secret: ${utils.hex_encode(derived_secret)}')
}

fn get_argon2_description(t kdf.Argon2Type) string {
	match t {
		.d { return 'Data-dependent memory access (best GPU resistance)' }
		.i { return 'Data-independent memory access (best side-channel resistance)' }
		.id { return 'Hybrid approach (balanced security)' }
	}
}
