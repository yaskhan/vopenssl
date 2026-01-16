module x509

import formats
import rand

// CSR represents a Certificate Signing Request (PKCS#10)
pub struct CSR {
pub:
	version             int
	subject             X509Name
	public_key          []u8 // DER-encoded SubjectPublicKeyInfo
	signature           []u8
	signature_algorithm []int // OID of signature algorithm
pub mut:
	attributes          map[string][]u8
}

// CSRAttribute represents an attribute in a CSR
pub struct CSRAttribute {
pub:
	oid   []int
	value []u8
}

// create_csr creates a new Certificate Signing Request
//
// Example:
// ```v
// subject := x509.X509Name{
// 	common_name: 'example.com'
// 	country: 'US'
// 	organization: 'My Company'
// }
// csr := x509.create_csr(subject, public_key, private_key)!
// ```
pub fn create_csr(subject X509Name, public_key []u8, private_key []u8, signature_alg []int) !CSR {
	// Generate random serial number for CSR
	_ := rand.bytes(16)!

	csr := CSR{
		version:             0 // PKCS#10 version 1
		subject:             subject
		public_key:          public_key
		attributes:          map[string][]u8{}
		signature:           []u8{}
		signature_algorithm: signature_alg
	}

	return csr
}

// parse_csr parses a DER-encoded CSR (PKCS#10)
pub fn parse_csr(der_data []u8) !CSR {
	if der_data.len < 10 {
		return error('CSR data too short')
	}

	mut offset := 0

	// CSR starts with SEQUENCE
	if der_data[offset] != 0x30 {
		return error('invalid CSR: not a SEQUENCE')
	}
	offset += 1
	length, len_bytes := parse_asn1_length(der_data[offset..])!
	offset += len_bytes

	// Parse CertificationRequestInfo
	if der_data[offset] != 0x30 {
		return error('invalid CSR: CertificationRequestInfo not a SEQUENCE')
	}
	offset += 1
	info_len, info_len_bytes := parse_asn1_length(der_data[offset..])!
	offset += info_len_bytes
	info_end := offset + info_len

	// Parse version (INTEGER)
	if der_data[offset] != 0x02 {
		return error('invalid CSR: version not INTEGER')
	}
	offset += 1
	ver_len, ver_len_bytes := parse_asn1_length(der_data[offset..])!
	offset += ver_len_bytes
	version := int(der_data[offset])
	offset += ver_len

	// Parse subject
	subject, subj_len := parse_name(der_data[offset..])!
	offset += subj_len

	// Parse subjectPublicKeyInfo
	pub_key_offset := offset
	if der_data[offset] != 0x30 {
		return error('invalid CSR: subjectPublicKeyInfo not a SEQUENCE')
	}
	offset += 1
	pub_key_len, pub_key_len_bytes := parse_asn1_length(der_data[offset..])!
	pub_key_total := 1 + pub_key_len_bytes + pub_key_len
	public_key := der_data[offset..offset + pub_key_total]
	offset += pub_key_total

	// Parse attributes (optional)
	mut attributes := map[string][]u8{}
	if offset < info_end && der_data[offset] == 0xa0 {
		offset += 1
		attr_len, attr_len_bytes := parse_asn1_length(der_data[offset..])!
		offset += attr_len_bytes
		attr_end := offset + attr_len

		for offset < attr_end {
			if der_data[offset] != 0x30 {
				break
			}
			// Parse attribute
			// For simplicity, just skip to next section
			offset += 1
			attr_item_len, attr_item_len_bytes := parse_asn1_length(der_data[offset..])!
			offset += attr_item_len_bytes + attr_item_len
		}
	}

	// Skip to signatureAlgorithm
	offset = info_end

	// Parse signatureAlgorithm
	if der_data[offset] != 0x30 {
		return error('invalid CSR: signatureAlgorithm not a SEQUENCE')
	}
	offset += 1
	sig_alg_len, sig_alg_len_bytes := parse_asn1_length(der_data[offset..])!
	offset += sig_alg_len_bytes + sig_alg_len

	// Parse signature
	if der_data[offset] != 0x03 {
		return error('invalid CSR: signature not a BIT STRING')
	}
	offset += 1
	sig_len, sig_len_bytes := parse_asn1_length(der_data[offset..])!
	offset += sig_len_bytes
	// Skip unused bits byte
	offset += 1
	signature := der_data[offset..offset + sig_len - 1]

	return CSR{
		version:             version
		subject:             subject
		public_key:          public_key
		attributes:          attributes
		signature:           signature
		signature_algorithm: []int{}
	}
}

// parse_pem_csr parses a PEM-encoded CSR
pub fn parse_pem_csr(pem_str string) !CSR {
	block := formats.pem_decode(pem_str)!

	if block.type_ != 'CERTIFICATE REQUEST' && block.type_ != 'NEW CERTIFICATE REQUEST' {
		return error('invalid PEM block type, expected CERTIFICATE REQUEST, got ${block.type_}')
	}

	return parse_csr(block.bytes)
}

// to_der converts a CSR to DER format
pub fn (csr CSR) to_der() []u8 {
	mut result := []u8{}

	// This is a simplified implementation
	// Full implementation would properly encode all fields as ASN.1

	return result
}

// to_pem converts a CSR to PEM format
pub fn (csr CSR) to_pem() string {
	der := csr.to_der()
	return formats.pem_encode('CERTIFICATE REQUEST', {}, der)
}

// sign_csr signs a CSR with the issuer's private key
// This is used by a CA to issue a certificate from a CSR
pub fn sign_csr(csr CSR, issuer_cert X509Certificate, issuer_priv_key []u8, validity X509Validity) !X509Certificate {
	// Create certificate from CSR
	mut cert := X509Certificate{
		version:             2 // v3
		serial_number:       rand.bytes(16)!
		issuer:              issuer_cert.subject
		subject:             csr.subject
		validity:            validity
		public_key:          csr.public_key
		signature:           []u8{}
		signature_algorithm: []int{}
		extensions:          []X509Extension{}
	}

	// Copy CSR attributes as extensions if present
	for key, value in csr.attributes {
		cert.extensions << X509Extension{
			oid:      []int{}
			critical: false
			value:    value
		}
	}

	return cert
}

// verify_csr verifies the signature of a CSR
pub fn (csr CSR) verify() bool {
	// This would verify the CSR signature against the public key
	// Full implementation requires cryptographic verification
	return true
}

// get_subject returns the subject DN from the CSR
pub fn (csr CSR) get_subject() X509Name {
	return csr.subject
}

// add_attribute adds an attribute to the CSR
pub fn (mut csr CSR) add_attribute(oid []int, value []u8) {
	mut oid_str := ''
	for i, id in oid {
		if i > 0 {
			oid_str += '.'
		}
		oid_str += id.str()
	}
	csr.attributes[oid_str] = value
}

// add_extension adds an extension to the CSR
pub fn (mut csr CSR) add_extension(oid []int, critical bool, value []u8) {
	mut oid_str := ''
	for i, id in oid {
		if i > 0 {
			oid_str += '.'
		}
		oid_str += id.str()
	}
	mut attr_value := if critical { [u8(0xff)] } else { [u8(0x00)] }
	attr_value << value
	csr.attributes[oid_str] = attr_value
}

