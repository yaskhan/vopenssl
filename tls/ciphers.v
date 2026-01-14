module tls

// TLS cipher suite identifiers
// TLS 1.2 cipher suites
pub const tls_rsa_with_aes_128_cbc_sha = u16(0x002f)
pub const tls_rsa_with_aes_256_cbc_sha = u16(0x0035)
pub const tls_rsa_with_aes_128_cbc_sha256 = u16(0x003c)
pub const tls_rsa_with_aes_256_cbc_sha256 = u16(0x003d)
pub const tls_rsa_with_aes_128_gcm_sha256 = u16(0x009c)
pub const tls_rsa_with_aes_256_gcm_sha384 = u16(0x009d)

pub const tls_ecdhe_rsa_with_aes_128_cbc_sha = u16(0xc013)
pub const tls_ecdhe_rsa_with_aes_256_cbc_sha = u16(0xc014)
pub const tls_ecdhe_rsa_with_aes_128_cbc_sha256 = u16(0xc027)
pub const tls_ecdhe_rsa_with_aes_128_gcm_sha256 = u16(0xc02f)
pub const tls_ecdhe_rsa_with_aes_256_gcm_sha384 = u16(0xc030)

pub const tls_ecdhe_ecdsa_with_aes_128_cbc_sha = u16(0xc009)
pub const tls_ecdhe_ecdsa_with_aes_256_cbc_sha = u16(0xc00a)
pub const tls_ecdhe_ecdsa_with_aes_128_cbc_sha256 = u16(0xc023)
pub const tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 = u16(0xc02b)
pub const tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 = u16(0xc02c)

// TLS 1.3 cipher suites
pub const tls_aes_128_gcm_sha256 = u16(0x1301)
pub const tls_aes_256_gcm_sha384 = u16(0x1302)
pub const tls_chacha20_poly1305_sha256 = u16(0x1303)
pub const tls_aes_128_ccm_sha256 = u16(0x1304)
pub const tls_aes_128_ccm_8_sha256 = u16(0x1305)

pub enum CipherSuiteType {
	tls_12
	tls_13
}

pub enum KeyExchangeAlgorithm {
	rsa
	dhe
	ecdhe
	psk
}

pub enum BulkCipherAlgorithm {
	aes_128_cbc
	aes_256_cbc
	aes_128_gcm
	aes_256_gcm
	chacha20_poly1305
}

pub enum MACAlgorithm {
	hmac_sha1
	hmac_sha256
	hmac_sha384
	aead // For AEAD ciphers (GCM, ChaCha20-Poly1305)
}

pub struct CipherSuite {
pub:
	id             u16
	name           string
	suite_type     CipherSuiteType
	key_exchange   KeyExchangeAlgorithm
	bulk_cipher    BulkCipherAlgorithm
	mac_algorithm  MACAlgorithm
	key_length     int
	iv_length      int
	hash_algorithm string // "sha256", "sha384", etc.
}

// get_cipher_suite returns the cipher suite details for a given ID
pub fn get_cipher_suite(id u16) ?CipherSuite {
	return match id {
		tls_rsa_with_aes_128_cbc_sha {
			CipherSuite{
				id:             id
				name:           'TLS_RSA_WITH_AES_128_CBC_SHA'
				suite_type:     .tls_12
				key_exchange:   .rsa
				bulk_cipher:    .aes_128_cbc
				mac_algorithm:  .hmac_sha1
				key_length:     16
				iv_length:      16
				hash_algorithm: 'sha1'
			}
		}
		tls_rsa_with_aes_256_cbc_sha {
			CipherSuite{
				id:             id
				name:           'TLS_RSA_WITH_AES_256_CBC_SHA'
				suite_type:     .tls_12
				key_exchange:   .rsa
				bulk_cipher:    .aes_256_cbc
				mac_algorithm:  .hmac_sha1
				key_length:     32
				iv_length:      16
				hash_algorithm: 'sha1'
			}
		}
		tls_rsa_with_aes_128_gcm_sha256 {
			CipherSuite{
				id:             id
				name:           'TLS_RSA_WITH_AES_128_GCM_SHA256'
				suite_type:     .tls_12
				key_exchange:   .rsa
				bulk_cipher:    .aes_128_gcm
				mac_algorithm:  .aead
				key_length:     16
				iv_length:      12
				hash_algorithm: 'sha256'
			}
		}
		tls_rsa_with_aes_256_gcm_sha384 {
			CipherSuite{
				id:             id
				name:           'TLS_RSA_WITH_AES_256_GCM_SHA384'
				suite_type:     .tls_12
				key_exchange:   .rsa
				bulk_cipher:    .aes_256_gcm
				mac_algorithm:  .aead
				key_length:     32
				iv_length:      12
				hash_algorithm: 'sha384'
			}
		}
		tls_ecdhe_rsa_with_aes_128_gcm_sha256 {
			CipherSuite{
				id:             id
				name:           'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
				suite_type:     .tls_12
				key_exchange:   .ecdhe
				bulk_cipher:    .aes_128_gcm
				mac_algorithm:  .aead
				key_length:     16
				iv_length:      12
				hash_algorithm: 'sha256'
			}
		}
		tls_ecdhe_rsa_with_aes_256_gcm_sha384 {
			CipherSuite{
				id:             id
				name:           'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
				suite_type:     .tls_12
				key_exchange:   .ecdhe
				bulk_cipher:    .aes_256_gcm
				mac_algorithm:  .aead
				key_length:     32
				iv_length:      12
				hash_algorithm: 'sha384'
			}
		}
		tls_ecdhe_ecdsa_with_aes_128_gcm_sha256 {
			CipherSuite{
				id:             id
				name:           'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
				suite_type:     .tls_12
				key_exchange:   .ecdhe
				bulk_cipher:    .aes_128_gcm
				mac_algorithm:  .aead
				key_length:     16
				iv_length:      12
				hash_algorithm: 'sha256'
			}
		}
		tls_ecdhe_ecdsa_with_aes_256_gcm_sha384 {
			CipherSuite{
				id:             id
				name:           'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
				suite_type:     .tls_12
				key_exchange:   .ecdhe
				bulk_cipher:    .aes_256_gcm
				mac_algorithm:  .aead
				key_length:     32
				iv_length:      12
				hash_algorithm: 'sha384'
			}
		}
		tls_aes_128_gcm_sha256 {
			CipherSuite{
				id:             id
				name:           'TLS_AES_128_GCM_SHA256'
				suite_type:     .tls_13
				key_exchange:   .ecdhe
				bulk_cipher:    .aes_128_gcm
				mac_algorithm:  .aead
				key_length:     16
				iv_length:      12
				hash_algorithm: 'sha256'
			}
		}
		tls_aes_256_gcm_sha384 {
			CipherSuite{
				id:             id
				name:           'TLS_AES_256_GCM_SHA384'
				suite_type:     .tls_13
				key_exchange:   .ecdhe
				bulk_cipher:    .aes_256_gcm
				mac_algorithm:  .aead
				key_length:     32
				iv_length:      12
				hash_algorithm: 'sha384'
			}
		}
		tls_chacha20_poly1305_sha256 {
			CipherSuite{
				id:             id
				name:           'TLS_CHACHA20_POLY1305_SHA256'
				suite_type:     .tls_13
				key_exchange:   .ecdhe
				bulk_cipher:    .chacha20_poly1305
				mac_algorithm:  .aead
				key_length:     32
				iv_length:      12
				hash_algorithm: 'sha256'
			}
		}
		else {
			none
		}
	}
}

// get_default_cipher_suites returns the default supported cipher suites
pub fn get_default_cipher_suites() []u16 {
	return [
		// TLS 1.3 suites (preferred)
		tls_aes_128_gcm_sha256,
		tls_aes_256_gcm_sha384,
		tls_chacha20_poly1305_sha256,
		// TLS 1.2 ECDHE suites
		tls_ecdhe_rsa_with_aes_128_gcm_sha256,
		tls_ecdhe_rsa_with_aes_256_gcm_sha384,
		tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
		tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
		// TLS 1.2 RSA suites (fallback)
		tls_rsa_with_aes_128_gcm_sha256,
		tls_rsa_with_aes_256_gcm_sha384,
	]
}

// is_cipher_suite_supported checks if a cipher suite is supported
pub fn is_cipher_suite_supported(id u16) bool {
	return get_cipher_suite(id) or { return false } != CipherSuite{}
}
