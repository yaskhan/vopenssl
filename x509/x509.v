module x509

import time
import formats

// X509Name represents a Distinguished Name (DN)
pub struct X509Name {
pub mut:
	country             string // C
	organization        string // O
	organizational_unit string // OU
	common_name         string // CN
	locality            string // L
	state_or_province   string // ST
	domain_component    string // DC
	email_address       string // EMAILADDRESS
}

// X509Validity represents the validity period of a certificate
pub struct X509Validity {
pub:
	not_before time.Time
	not_after  time.Time
}

// X509Extension represents a certificate extension
pub struct X509Extension {
pub:
	oid      []int
	critical bool
	value    []u8
}

// KeyUsage defines the key usage extension
pub enum KeyUsage {
	digital_signature
	content_commitment
	key_encipherment
	data_encipherment
	key_agreement
	key_cert_sign
	crl_sign
	encipher_only
	decipher_only
}

// X509Certificate represents an X.509 certificate
pub struct X509Certificate {
pub:
	version              int
	serial_number        []u8
	issuer               X509Name
	subject              X509Name
	validity             X509Validity
	public_key           []u8  // DER-encoded SubjectPublicKeyInfo
	public_key_algorithm []int // OID of public key algorithm
	signature_algorithm  []int // OID of signature algorithm
	signature            []u8
	tbs_certificate      []u8  // Raw bytes of tbsCertificate for signature verification
pub mut:
	extensions           []X509Extension
}

// CertificateType represents the type of certificate
pub enum CertificateType {
	ca_certificate
	end_entity_certificate
	intermediate_certificate
}

// parse_certificate parses a DER-encoded X.509 certificate
//
// Example:
// ```v
// cert := x509.parse_certificate(der_data)!
// ```
pub fn parse_certificate(der_data []u8) !X509Certificate {
	if der_data.len < 10 {
		return error('certificate data too short')
	}

	// Parse ASN.1 structure
	mut offset := 0

	// Certificate should start with SEQUENCE tag
	if der_data[offset] != 0x30 {
		return error('invalid certificate: not a SEQUENCE')
	}

	offset += 1
	length, len_bytes := parse_asn1_length(der_data[offset..])!
	offset += len_bytes

	// Parse tbsCertificate
	tbs_offset := offset
	if der_data[offset] != 0x30 {
		return error('invalid certificate: tbsCertificate not a SEQUENCE')
	}

	// Skip tbsCertificate SEQUENCE
	offset += 1
	tbs_len, tbs_len_bytes := parse_asn1_length(der_data[offset..])!
	offset += tbs_len_bytes
	
	// Store pure TBS bytes
	// The TBS certificate starts at tbs_offset and has length: 1 (tag) + tbs_len_bytes (length) + tbs_len (content)
	tbs_total_len := 1 + tbs_len_bytes + tbs_len
	tbs_certificate := der_data[tbs_offset..tbs_offset + tbs_total_len]

	// Parse version (optional)
	mut version := 2 // Default to v3 (0-indexed as 2)
	if der_data[offset] == 0xa0 { // [0] IMPLICIT
		offset += 1
		ver_len, ver_len_bytes := parse_asn1_length(der_data[offset..])!
		offset += ver_len_bytes
		if ver_len == 1 {
			version = int(der_data[offset])
			offset += 1
		}
	}

	// Parse serial number
	if der_data[offset] != 0x02 {
		return error('invalid certificate: serial number not INTEGER')
	}
	offset += 1
	serial_len, serial_len_bytes := parse_asn1_length(der_data[offset..])!
	offset += serial_len_bytes
	serial_number := der_data[offset..offset + serial_len]
	offset += serial_len

	// Parse signature algorithm
	if der_data[offset] != 0x30 {
		return error('invalid certificate: signature algorithm not a SEQUENCE')
	}
	offset += 1
	sig_alg_len, sig_alg_len_bytes := parse_asn1_length(der_data[offset..])!
	offset += sig_alg_len_bytes + sig_alg_len

	// Skip signature algorithm OID
	if der_data[offset] == 0x06 {
		offset += 1
		oid_len, oid_len_bytes := parse_asn1_length(der_data[offset..])!
		offset += oid_len_bytes + oid_len
	}

	// Parse issuer
	issuer, issuer_len := parse_name(der_data[offset..])!
	offset += issuer_len

	// Parse validity
	validity, validity_len := parse_validity(der_data[offset..])!
	offset += validity_len

	// Parse subject
	subject, subject_len := parse_name(der_data[offset..])!
	offset += subject_len

	// Parse subjectPublicKeyInfo
	pub_key_offset := offset
	if der_data[offset] != 0x30 {
		return error('invalid certificate: subjectPublicKeyInfo not a SEQUENCE')
	}
	offset += 1
	pub_key_info_len, pub_key_info_len_bytes := parse_asn1_length(der_data[offset..])!
	pub_key_info_total := 1 + pub_key_info_len_bytes + pub_key_info_len
	public_key := der_data[offset..offset + pub_key_info_total]
	offset += pub_key_info_total

	// Parse extensions (optional)
	mut extensions := []X509Extension{}
	if offset < tbs_offset + tbs_len && der_data[offset] == 0xa3 { // [3] IMPLICIT
		offset += 1
		ext_seq_len, ext_seq_len_bytes := parse_asn1_length(der_data[offset..])!
		offset += ext_seq_len_bytes
		ext_end := offset + ext_seq_len

		for offset < ext_end {
			if der_data[offset] != 0x30 {
				break
			}
			offset += 1
			ext_len, ext_len_bytes := parse_asn1_length(der_data[offset..])!
			offset += ext_len_bytes

			// Parse extension OID
			if der_data[offset] != 0x06 {
				break
			}
			offset += 1
			oid_len, oid_len_bytes := parse_asn1_length(der_data[offset..])!
			offset += oid_len_bytes

			mut oid := []int{}
			for i in 0 .. oid_len {
				oid << int(der_data[offset + i])
			}
			offset += oid_len

			// Parse critical flag (optional)
			mut critical := false
			if der_data[offset] == 0x01 {
				offset += 1
				crit_len, crit_len_bytes := parse_asn1_length(der_data[offset..])!
				offset += crit_len_bytes
				if crit_len == 1 {
					critical = der_data[offset] != 0x00
					offset += 1
				}
			}

			// Parse extension value
			if der_data[offset] != 0x04 {
				break
			}
			offset += 1
			value_len, value_len_bytes := parse_asn1_length(der_data[offset..])!
			offset += value_len_bytes

			value := der_data[offset..offset + value_len]
			offset += value_len

			extensions << X509Extension{
				oid:      oid
				critical: critical
				value:    value
			}
		}
	}

	// Skip to signature
	offset = tbs_offset + tbs_len

	// Parse signatureAlgorithm again
	if der_data[offset] != 0x30 {
		return error('invalid certificate: signatureAlgorithm not a SEQUENCE')
	}
	offset += 1
	sig_alg_len2, sig_alg_len_bytes2 := parse_asn1_length(der_data[offset..])!
	offset += sig_alg_len_bytes2 + sig_alg_len2

	// Parse signature value
	if der_data[offset] != 0x03 {
		return error('invalid certificate: signature not a BIT STRING')
	}
	offset += 1
	sig_len, sig_len_bytes := parse_asn1_length(der_data[offset..])!
	offset += sig_len_bytes
	// First byte is number of unused bits
	sig_unused_bits := der_data[offset]
	if sig_unused_bits != 0 {
		return error('invalid certificate: signature has unused bits')
	}
	offset += 1
	signature := der_data[offset..offset + sig_len - 1]

	return X509Certificate{
		version:              version
		serial_number:        serial_number
		issuer:               issuer
		subject:              subject
		validity:             validity
		public_key:           public_key
		public_key_algorithm: []int{}
		signature_algorithm:  []int{}
		signature:            signature
		tbs_certificate:      tbs_certificate
		extensions:           extensions
	}
}

// parse_pem_certificate parses a PEM-encoded X.509 certificate
//
// Example:
// ```v
// cert := x509.parse_pem_certificate(pem_str)!
// ```
pub fn parse_pem_certificate(pem_str string) !X509Certificate {
	block := formats.pem_decode(pem_str)!

	if block.type_ != 'CERTIFICATE' {
		return error('invalid PEM block type, expected CERTIFICATE, got ${block.type_}')
	}

	return parse_certificate(block.bytes)
}

// to_der converts a certificate to DER format
pub fn (cert X509Certificate) to_der() []u8 {
	mut result := []u8{}

	// This is a simplified implementation
	// Full implementation would properly encode all fields as ASN.1

	return result
}

// to_pem converts a certificate to PEM format
pub fn (cert X509Certificate) to_pem() string {
	der := cert.to_der()
	return formats.pem_encode('CERTIFICATE', {}, der)
}

// is_expired checks if the certificate has expired
pub fn (cert X509Certificate) is_expired() bool {
	return time.now() > cert.validity.not_after
}

// is_valid_at checks if the certificate is valid at a given time
pub fn (cert X509Certificate) is_valid_at(t time.Time) bool {
	return t >= cert.validity.not_before && t <= cert.validity.not_after
}

// is_valid_now checks if the certificate is currently valid
pub fn (cert X509Certificate) is_valid_now() bool {
	return cert.is_valid_at(time.now())
}

// is_ca checks if the certificate is a CA certificate
pub fn (cert X509Certificate) is_ca() bool {
	// Check basic constraints extension
	for ext in cert.extensions {
		if ext.oid.len == 3 && ext.oid[0] == 0x55 && ext.oid[1] == 0x1d && ext.oid[2] == 0x13 {
			// Basic constraints OID: 2.5.29.19
			// Simplified check - full parsing would decode the value
			return ext.critical || ext.value.len > 0
		}
	}
	return false
}

// get_subject returns the subject DN
pub fn (cert X509Certificate) get_subject() X509Name {
	return cert.subject
}

// get_issuer returns the issuer DN
pub fn (cert X509Certificate) get_issuer() X509Name {
	return cert.issuer
}

// get_serial_number returns the serial number as hex string
pub fn (cert X509Certificate) get_serial_number() string {
	mut hex := '0x'
	for b in cert.serial_number {
		hex += hex_byte(b)
	}
	return hex
}

fn hex_byte(b u8) string {
	h := (b >> 4) & 0x0f
	l := b & 0x0f
	hex_chars := ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
	return '${hex_chars[h]}${hex_chars[l]}'
}

// parse_name parses a Name structure from DER data
fn parse_name(data []u8) !(X509Name, int) {
	mut name := X509Name{}
	mut offset := 0

	// Skip SEQUENCE tag and length
	if data[offset] != 0x30 {
		return error('Name not a SEQUENCE')
	}
	offset += 1
	length, len_bytes := parse_asn1_length(data[offset..])!
	offset += len_bytes
	end := offset + length

	// Parse RDNSequence (SET OF RelativeDistinguishedName)
	for offset < end {
		if data[offset] != 0x31 { // SET
			break
		}
		offset += 1
		set_len, set_len_bytes := parse_asn1_length(data[offset..])!
		offset += set_len_bytes

		// Parse RelativeDistinguishedName (SEQUENCE OF AttributeTypeAndValue)
		if data[offset] != 0x30 { // SEQUENCE
			break
		}
		offset += 1
		seq_len, seq_len_bytes := parse_asn1_length(data[offset..])!
		offset += seq_len_bytes
		seq_end := offset + seq_len

		for offset < seq_end {
			// Parse AttributeTypeAndValue
			if data[offset] != 0x30 {
				break
			}
			offset += 1
			attr_len, attr_len_bytes := parse_asn1_length(data[offset..])!
			offset += attr_len_bytes

			// Parse OID
			if data[offset] != 0x06 {
				break
			}
			offset += 1
			oid_len, oid_len_bytes := parse_asn1_length(data[offset..])!
			offset += oid_len_bytes

			// Common name OID: 2.5.4.3
			// Country OID: 2.5.4.6
			// Organization OID: 2.5.4.10
			// Organizational unit OID: 2.5.4.11
			// Locality OID: 2.5.4.7
			// State OID: 2.5.4.8
			// Email OID: 1.2.840.113549.1.9.1

			// For simplicity, just skip OID and get value
			if offset >= data.len {
				break
			}

			// Parse value
			if data[offset] == 0x13 || data[offset] == 0x0c { // PrintableString or UTF8String
				offset += 1
				val_len, val_len_bytes := parse_asn1_length(data[offset..])!
				offset += val_len_bytes

				value := data[offset..offset + val_len].bytestr()
				offset += val_len

				// Try to map value to field (simplified)
				if oid_len >= 4 && data[offset - oid_len - val_len_bytes - 2] == 0x03 {
					// Country
					if val_len == 2 {
						name.country = value
					}
				} else if oid_len >= 4 && data[offset - oid_len - val_len_bytes - 2] == 0x0a {
					// Organization
					name.organization = value
				} else if oid_len >= 4 && data[offset - oid_len - val_len_bytes - 2] == 0x0b {
					// Organizational unit
					name.organizational_unit = value
				} else if oid_len >= 4 && data[offset - oid_len - val_len_bytes - 2] == 0x03 {
					// Common name
					name.common_name = value
				} else {
					// Try to guess based on content
					if value.len == 2 {
						name.country = value
					} else if value.contains('@') {
						name.email_address = value
					} else if name.common_name == '' {
						name.common_name = value
					} else if name.organization == '' {
						name.organization = value
					}
				}
			} else {
				// Skip unknown type
				offset += 1
				skip_len, skip_len_bytes := parse_asn1_length(data[offset..])!
				offset += skip_len_bytes + skip_len
			}
		}
	}

	return name, end
}

// parse_validity parses a Validity structure from DER data
fn parse_validity(data []u8) !(X509Validity, int) {
	mut offset := 0

	// Skip SEQUENCE tag and length
	if data[offset] != 0x30 {
		return error('Validity not a SEQUENCE')
	}
	offset += 1
	length, len_bytes := parse_asn1_length(data[offset..])!
	offset += len_bytes
	end := offset + length

	// Parse notBefore (UTC time or generalized time)
	not_before, nb_len := parse_time(data[offset..])!
	offset += nb_len

	// Parse notAfter
	not_after, na_len := parse_time(data[offset..])!
	offset += na_len

	return X509Validity{
		not_before: not_before
		not_after:  not_after
	}, end
}

// parse_time parses an ASN.1 time (UTCTime or GeneralizedTime)
fn parse_time(data []u8) !(time.Time, int) {
	if data.len == 0 {
		return error('empty time data')
	}

	mut offset := 0
	tag := data[offset]
	offset += 1

	length, len_bytes := parse_asn1_length(data[offset..])!
	offset += len_bytes

	time_str := data[offset..offset + length].bytestr()

	if tag == 0x17 {
		// UTCTime (YYMMDDHHMMSSZ)
		if time_str.len >= 13 {
			yy_str := time_str[0..2]
			mut yy := 70
			if yy_str.len >= 2 {
				yy = yy_str.int()
			}
			year := if yy >= 50 { 1900 + yy } else { 2000 + yy }

			month_str := time_str[2..4]
			mut month := 1
			if month_str.len >= 2 {
				month = month_str.int()
			}

			day_str := time_str[4..6]
			mut day := 1
			if day_str.len >= 2 {
				day = day_str.int()
			}

			hour_str := time_str[6..8]
			mut hour := 0
			if hour_str.len >= 2 {
				hour = hour_str.int()
			}

			minute_str := time_str[8..10]
			mut minute := 0
			if minute_str.len >= 2 {
				minute = minute_str.int()
			}

			second_str := time_str[10..12]
			mut second := 0
			if second_str.len >= 2 {
				second = second_str.int()
			}

			return time.new(time.Time{
				year: year
				month: month
				day: day
				hour: hour
				minute: minute
				second: second
			}), offset + length
		}
	} else if tag == 0x18 {
		// GeneralizedTime (YYYYMMDDHHMMSSZ)
		if time_str.len >= 15 {
			year_str := time_str[0..4]
			mut year := 2024
			if year_str.len >= 4 {
				year = year_str.int()
			}

			month_str := time_str[4..6]
			mut month := 1
			if month_str.len >= 2 {
				month = month_str.int()
			}

			day_str := time_str[6..8]
			mut day := 1
			if day_str.len >= 2 {
				day = day_str.int()
			}

			hour_str := time_str[8..10]
			mut hour := 0
			if hour_str.len >= 2 {
				hour = hour_str.int()
			}

			minute_str := time_str[10..12]
			mut minute := 0
			if minute_str.len >= 2 {
				minute = minute_str.int()
			}

			second_str := time_str[12..14]
			mut second := 0
			if second_str.len >= 2 {
				second = second_str.int()
			}

			return time.new(time.Time{
				year: year
				month: month
				day: day
				hour: hour
				minute: minute
				second: second
			}), offset + length
		}
	}

	return error('invalid time format')
}

// parse_asn1_length helper for parsing ASN.1 length fields
fn parse_asn1_length(data []u8) !(int, int) {
	if data.len == 0 {
		return error('empty length')
	}
	b := data[0]
	if b & 0x80 == 0 {
		return int(b), 1
	}
	num_bytes := int(b & 0x7f)
	if data.len < 1 + num_bytes {
		return error('truncated length')
	}
	if num_bytes > 4 {
		return error('length too large')
	}

	mut length := 0
	for i in 0 .. num_bytes {
		length = (length << 8) | int(data[1 + i])
	}
	return length, 1 + num_bytes
}
