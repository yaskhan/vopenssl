module x509

import time
import rsa
import ecc
import formats
import hash

// ValidationOptions defines options for certificate validation
pub struct ValidationOptions {
pub:
	current_time       time.Time
	dns_name           string
	email_address      string
	ip_address         string
	allow_expired      bool
	allow_self_signed  bool
	max_path_length    int // Maximum certificate chain length
	key_usage          []KeyUsage
	extended_key_usage []int // OIDs
}

// ValidationResult represents the result of certificate validation
pub struct ValidationResult {
pub mut:
	is_valid   bool
	is_trusted bool
	chain      []X509Certificate
	errors     []string
	warnings   []string
}

// ValidationError represents a validation error
pub enum ValidationError {
	expired
	not_yet_valid
	invalid_signature
	invalid_issuer
	name_mismatch
	key_usage_mismatch
	extended_key_usage_mismatch
	revoked
	invalid_issuer_certificate
}

// validate_certificate validates an X.509 certificate against the given options
//
// Example:
// ```v
// opts := x509.ValidationOptions{
//     current_time: time.now()
//     dns_name: 'example.com'
// }
// result := x509.validate_certificate(cert, [])!
// ```
pub fn validate_certificate(cert X509Certificate, intermediates []X509Certificate, opts ValidationOptions) !ValidationResult {
	mut result := ValidationResult{
		is_valid:   true
		is_trusted: false
		chain:      [cert]
		errors:     []
		warnings:   []
	}

	// Use current time if not specified
	valid_time := if opts.current_time.unix() == 0 { time.now() } else { opts.current_time }

	// Check validity period
	if !opts.allow_expired {
		if cert.is_expired() {
			result.is_valid = false
			result.errors << 'certificate has expired'
		}
	}

	if !cert.is_valid_at(valid_time) && !cert.is_expired() {
		result.is_valid = false
		result.errors << 'certificate is not yet valid'
	}

	// Check key usage if specified
	if opts.key_usage.len > 0 {
		// Check if the certificate has the required key usages
		// This would need to parse the KeyUsage extension
		// For now, skip this check
		result.warnings << 'key usage validation not fully implemented'
	}

	// Check extended key usage if specified
	if opts.extended_key_usage.len > 0 {
		result.warnings << 'extended key usage validation not fully implemented'
	}

	// Check DNS name if specified
	if opts.dns_name != '' {
		// Check if certificate's CN or SAN matches the DNS name
		if cert.subject.common_name != opts.dns_name {
			result.warnings << 'certificate CN (${cert.subject.common_name}) does not match requested DNS name (${opts.dns_name})'
		}
	}

	// Check email address if specified
	if opts.email_address != '' {
		if cert.subject.email_address != opts.email_address {
			result.warnings << 'certificate email does not match requested email'
		}
	}

	// Check if self-signed
	is_self_signed := cert.subject == cert.issuer
	if is_self_signed && !opts.allow_self_signed {
		result.is_valid = false
		result.errors << 'self-signed certificate not allowed'
	} else if is_self_signed {
		result.is_trusted = true
		result.warnings << 'self-signed certificate - trust requires explicit verification'
	}

	// Validate chain if intermediates provided
	if intermediates.len > 0 {
		chain_result := validate_chain(cert, intermediates, opts)
		if !chain_result.is_valid {
			result.is_valid = false
			result.errors << chain_result.errors
		}
		result.chain = chain_result.chain
	}

	return result
}

// validate_chain validates a certificate chain
pub fn validate_chain(cert X509Certificate, intermediates []X509Certificate, opts ValidationOptions) ValidationResult {
	mut result := ValidationResult{
		is_valid:   true
		is_trusted: false
		chain:      [cert]
		errors:     []
		warnings:   []
	}

	// Build chain from end-entity to root
	mut current_cert := cert
	mut chain_built := []X509Certificate{cap: intermediates.len + 1}
	chain_built << cert
	mut visited := map[string]bool{}

	for {
		// Check if we've hit a loop
		issuer_key := get_issuer_identifier(current_cert)
		if visited[issuer_key] {
			result.is_valid = false
			result.errors << 'certificate chain has a loop'
			return result
		}
		visited[issuer_key] = true

		// Check if self-signed (root)
		if current_cert.subject == current_cert.issuer {
			result.is_trusted = true
			break
		}

		// Find issuer in intermediates
		mut issuer_found := false
		for inter in intermediates {
			if is_issuer(inter, current_cert) {
				current_cert = inter
				chain_built << inter
				issuer_found = true
				break
			}
		}

		if !issuer_found {
			result.is_valid = false
			result.errors << 'unable to find certificate issuer'
			break
		}

		// Check max path length
		if chain_built.len > opts.max_path_length {
			result.is_valid = false
			result.errors << 'certificate chain exceeds maximum path length'
			break
		}
	}

	result.chain = chain_built

	return result
}

// verify_signature verifies the cryptographic signature of a certificate using the issuer's public key.
// It parses the SubjectPublicKeyInfo from the issuer certificate to determine the algorithm (RSA, ECDSA, Ed25519)
// and validates that the signature matches the tbs_certificate blob.
// Returns true if the signature is valid, false otherwise.
pub fn verify_signature(cert X509Certificate, issuer_cert X509Certificate) bool {
	// We need the issuer's public key to verify the signature on cert.tbs_certificate
	if issuer_cert.public_key.len == 0 {
		return false
	}
	
	// Parse issuer public key from SPKI
	// SPKI = SEQUENCE { CA: AlgorithmIdentifier, PubKey: BIT STRING }
	spki := issuer_cert.public_key
	parsed_spki := formats.asn1_unmarshal(spki) or { return false }
	
	// Expecting a Sequence of 2 items
	if parsed_spki !is []formats.ASN1Value { return false }
	spki_seq := parsed_spki as []formats.ASN1Value
	if spki_seq.len < 2 { return false }
	
	alg_id := spki_seq[0]
	pub_key_bits := spki_seq[1]
	
	if alg_id !is []formats.ASN1Value { return false }
	alg_seq := alg_id as []formats.ASN1Value
	if alg_seq.len < 1 { return false }
	
	oid_val := alg_seq[0]
	if oid_val !is formats.ASN1OID { return false }
	oid := (oid_val as formats.ASN1OID).ids
	
	// Convert OID to string for comparison (simplified)
	// RSA: 1.2.840.113549.1.1.1
	// P-256: 1.2.840.10045.2.1
	// Ed25519: 1.3.101.112
	
	// Helper to check OID
	is_oid := fn(ids []int, expected []int) bool {
		if ids.len != expected.len { return false }
		for i in 0 .. ids.len { if ids[i] != expected[i] { return false } }
		return true
	}
	
	// Determine Hash Algorithm from cert.signature_algorithm
	// This should be parsed from cert.signature_algorithm OID
	// See RFC 3279, 5758.
	// Common:
	// sha256WithRSAEncryption: 1.2.840.113549.1.1.11
	// ecdsa-with-SHA256: 1.2.840.10045.4.3.2
	// Ed25519: 1.3.101.112 (Signature algorithm same as key OID)
	
	sig_alg_oid := oid_to_string(cert.signature_algorithm)
	hash_alg := match sig_alg_oid {
		'1.2.840.113549.1.1.11', '1.2.840.10045.4.3.2' { hash.HashAlgorithm.sha256 }
		'1.2.840.113549.1.1.12', '1.2.840.10045.4.3.3' { hash.HashAlgorithm.sha384 }
		'1.2.840.113549.1.1.13', '1.2.840.10045.4.3.4' { hash.HashAlgorithm.sha512 }
		else { hash.HashAlgorithm.sha256 } // Default fallback or error
	}
	
	rsa_hash_alg := match hash_alg {
		.sha1 { rsa.HashAlgorithm.sha1 }
		.sha224 { rsa.HashAlgorithm.sha224 }
		.sha256 { rsa.HashAlgorithm.sha256 }
		.sha384 { rsa.HashAlgorithm.sha384 }
		.sha512 { rsa.HashAlgorithm.sha512 }
		.md5 { rsa.HashAlgorithm.md5 }
		else { rsa.HashAlgorithm.sha256 }
	}
	
	if pub_key_bits !is []u8 { return false }
	key_bytes := pub_key_bits as []u8
	
	if is_oid(oid, [1, 2, 840, 113549, 1, 1, 1]) {
		// RSA Encryption
		// Parse RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
		parsed_key := formats.asn1_unmarshal(key_bytes) or { return false }
		if parsed_key !is []formats.ASN1Value { return false }
		key_seq := parsed_key as []formats.ASN1Value
		if key_seq.len < 2 { return false }
		
		n_val := key_seq[0]
		e_val := key_seq[1]
		
		// Helper to extract bytes from Integer (i64 or []u8)
		get_bytes := fn(val formats.ASN1Value) []u8 {
			if val is []u8 { return val }
			if val is i64 { 
				// Convert i64 to bytes (big endian)
				// Minimal implementation for small E
				mut res := []u8{}
				mut v := val
				for v > 0 {
					res.insert(0, u8(v & 0xFF))
					v >>= 8
				}
				if res.len == 0 { return [u8(0)] }
				return res
			}
			return []u8{}
		}

		n := get_bytes(n_val)
		e := get_bytes(e_val)
		
		pub_key := rsa.RSAPublicKey{ n: n, e: e }
		
		// For RSA verify, we typically verify the hash of the TBS certificate
		// Compute hash of tbs_certificate
		hashed := hash.hash_bytes(cert.tbs_certificate, hash_alg)
		
		// x509 signatures usually use PKCS#1 v1.5
		// x509 signatures usually use PKCS#1 v1.5
		return rsa.verify(pub_key, hashed, cert.signature, rsa_hash_alg, .pkcs1_v15) or { false }
		
	} else if is_oid(oid, [1, 2, 840, 10045, 2, 1]) {
		// EC Public Key
		// key_bytes is the SEC1 encoded point
		// We need to parse ECDSASignature from DER signature (Sequence of R, S)
		// cert.signature is usually DER encoded
		
		parsed_sig := formats.asn1_unmarshal(cert.signature) or { return false }
		if parsed_sig !is []formats.ASN1Value { return false }
		sig_seq := parsed_sig as []formats.ASN1Value
		if sig_seq.len < 2 { return false }
		
		get_bytes := fn(val formats.ASN1Value) []u8 {
			if val is []u8 { return val }
			if val is i64 { 
				mut res := []u8{}
				mut v := val
				for v > 0 {
					res.insert(0, u8(v & 0xFF))
					v >>= 8
				}
				if res.len == 0 { return [u8(0)] } // Should handle zero properly
				return res
			}
			return []u8{}
		}

		r := get_bytes(sig_seq[0])
		s := get_bytes(sig_seq[1])
		
		signature := ecc.ECDSASignature{ r: r, s: s }
		
		// Determine curve from Parameters? 
		// AlgIdentifier params for EC is NamedCurve OID.
		// For now we can infer from key length or try P-256 (most common) except if OID implies otherwise.
		// But verify function needs curve. P-256 is .secp256r1.
		
		// Extract curve from SPKI parameters
		// spki_seq[0] is AlgId -> [OID, Params]
		// Params should be NamedCurve OID
		// P-256 OID: 1.2.840.10045.3.1.7
		curve := ecc.EllipticCurve.secp256r1 // Default/Assumption if parsing fails or matched
		
		if alg_seq.len > 1 {
			param_val := alg_seq[1]
			if param_val is formats.ASN1OID {
				p_oid := (param_val as formats.ASN1OID).ids
				if is_oid(p_oid, [1, 2, 840, 10045, 3, 1, 7]) {
					// P-256
				} else if is_oid(p_oid, [1, 3, 132, 0, 34]) {
					// P-384
					// curve = .secp384r1
					return false // Not supporting P-384 verify yet or update code
				}
			}
		}
		
		// Parse Public Key Point (04 || X || Y)
		if key_bytes.len != 65 || key_bytes[0] != 0x04 {
			return false // Only support uncompressed P-256 for now
		}
		x := key_bytes[1..33]
		y := key_bytes[33..65]
		
		pub_key := ecc.ECPublicKey{
			curve: curve
			x: x
			y: y
		}
		
		return ecc.ecdsa_verify(pub_key, cert.tbs_certificate, signature, unsafe { ecc.HashAlgorithm(int(hash_alg)) }) or { false }
		
	} else if is_oid(oid, [1, 3, 101, 112]) {
		// Ed25519
		// key_bytes is raw 32 bytes
		if key_bytes.len != 32 { return false }
		
		pub_key := ecc.ECPublicKey{
			curve: .ed25519
			x: key_bytes
			y: []u8{}
		}
		
		// Ed25519 signature is raw 64 bytes
		if cert.signature.len != 64 { return false }
		
		return ecc.ed25519_verify(pub_key, cert.tbs_certificate, cert.signature) or { false }
	}
	
	// Unsupported algorithm
	return false
}

// check_revocation checks if a certificate has been revoked
pub fn check_revocation(cert X509Certificate, crl_urls []string) bool {
	// Full implementation requires HTTP client and CRL parsing
	// For strictly local validation, we return false (not revoked)
	return false 
}

// check_online_revocation checks OCSP for certificate revocation
pub fn check_online_revocation(cert X509Certificate, issuer_cert X509Certificate, ocsp_urls []string) !bool {
	return error('OCSP checking not implemented - requires network client')
}

// get_issuer_identifier returns a unique identifier for a certificate's issuer
fn get_issuer_identifier(cert X509Certificate) string {
	return '${cert.subject.common_name}:${cert.get_serial_number()}'
}

// is_issuer checks if issuer_cert is the issuer of cert
fn is_issuer(issuer_cert X509Certificate, cert X509Certificate) bool {
	// Simple check: issuer of cert should match subject of issuer_cert
	return cert.issuer.common_name == issuer_cert.subject.common_name
		&& cert.issuer.organization == issuer_cert.subject.organization
		&& cert.issuer.country == issuer_cert.subject.country
}

// validate_host validates that the certificate is valid for the given host
pub fn validate_host(cert X509Certificate, host string) !bool {
	// Check if host matches certificate's CN or SAN
	if cert.subject.common_name != '' && cert.subject.common_name == host {
		return true
	}

	// Check for wildcard certificates
	if cert.subject.common_name.starts_with('*.') {
		domain := cert.subject.common_name[2..]
		if host.ends_with(domain) {
			return true
		}
	}

	return error('certificate does not match host: ${host}')
}

// validate_email validates that the certificate is valid for the given email
pub fn validate_email(cert X509Certificate, email string) bool {
	return cert.subject.email_address != '' && cert.subject.email_address == email
}

// verify_certificate_chain verifies a complete certificate chain to a trusted root
pub fn verify_certificate_chain(chain []X509Certificate, trusted_roots []X509Certificate) ValidationResult {
	mut result := ValidationResult{
		is_valid:   true
		is_trusted: false
		chain:      chain
		errors:     []
		warnings:   []
	}

	if chain.len == 0 {
		result.is_valid = false
		result.errors << 'empty certificate chain'
		return result
	}

	// Verify each signature in the chain
	for i in 0 .. chain.len - 1 {
		if !verify_signature(chain[i], chain[i + 1]) {
			result.is_valid = false
			result.errors << 'invalid signature in certificate chain at position ${i}'
		}
	}

	// Check if last certificate is in trusted roots
	mut is_trusted := false
	for root in trusted_roots {
		if chain.last().get_serial_number() == root.get_serial_number() {
			is_trusted = true
			break
		}
	}

	result.is_trusted = is_trusted

	if !is_trusted {
		result.errors << 'certificate chain does not terminate in a trusted root'
		result.is_valid = false
	}

	return result
}

// get_chain_length returns the length of the certificate chain
pub fn (cert X509Certificate) get_chain_length() int {
	// This would parse the BasicConstraints extension to get the path length
	// For now, return a default value
	return 0
}

// get_basic_constraints returns the basic constraints from the certificate
pub fn (cert X509Certificate) get_basic_constraints() BasicConstraints {
	// Returns (is_ca, path_len_constraint)
	// Parse BasicConstraints extension
	for ext in cert.extensions {
		// BasicConstraints OID: 2.5.29.19
		if ext.oid.len == 3 && ext.oid[0] == 0x55 && ext.oid[1] == 0x1d && ext.oid[2] == 0x13 {
			// Parse the extension value
			// For now, return defaults
			return BasicConstraints{
				is_ca:               cert.is_ca()
				path_len_constraint: 0
			}
		}
	}
	return BasicConstraints{
		is_ca:               false
		path_len_constraint: 0
	}
}

// BasicConstraints represents the basic constraints extension
pub struct BasicConstraints {
pub:
	is_ca               bool
	path_len_constraint int
}

fn oid_to_string(oid []int) string {
	mut s := ''
	for i, v in oid {
		if i > 0 { s += '.' }
		s += v.str()
	}
	return s
}


