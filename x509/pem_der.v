module x509

import os
import encoding
import strings

// CertificateFormat represents the format of a certificate
pub enum CertificateFormat {
	pem
	der
}

// CertificateBundle represents a bundle of certificates
pub struct CertificateBundle {
pub:
	certificates []X509Certificate
}

// load_certificate loads a certificate from a file (PEM or DER)
//
// Example:
// ```v
// cert := x509.load_certificate('cert.pem')!
// ```
pub fn load_certificate(path string) !X509Certificate {
	if !os.exists(path) {
		return error('certificate file does not exist: ${path}')
	}

	data := os.read_file(path)!

	// Detect format
	if data.contains('-----BEGIN CERTIFICATE-----') {
		return parse_pem_certificate(data)
	}

	// Assume DER format
	return parse_certificate(data.bytes())
}

// load_certificates loads multiple certificates from a file
// Useful for certificate bundles
pub fn load_certificates(path string) ![]X509Certificate {
	if !os.exists(path) {
		return error('certificate file does not exist: ${path}')
	}

	data := os.read_file(path)!
	mut certs := []X509Certificate{}

	// Parse PEM blocks
	if data.contains('-----BEGIN CERTIFICATE-----') {
		mut offset := 0
		for {
			start_idx := data.index_after('-----BEGIN CERTIFICATE-----', offset) or { break }
			end_idx := data.index_after('-----END CERTIFICATE-----', start_idx) or { break }

			pem_block := data[start_idx..end_idx + '-----END CERTIFICATE-----'.len]
			cert := parse_pem_certificate(pem_block)!
			certs << cert

			offset = end_idx
		}
	} else {
		// Single DER certificate
		cert := parse_certificate(data.bytes())!
		certs << cert
	}

	if certs.len == 0 {
		return error('no certificates found in file')
	}

	return certs
}

// save_certificate saves a certificate to a file
//
// Example:
// ```v
// cert.to_pem_file('cert.pem')!
// ```
pub fn (cert X509Certificate) save_to_file(path string, format CertificateFormat) ! {
	match format {
		.pem {
			pem_data := cert.to_pem()
			os.write_file(path, pem_data)!
		}
		.der {
			der_data := cert.to_der()
			os.write_file(path, der_data.bytestr())!
		}
	}
}

// to_pem_file saves a certificate to a PEM file
pub fn (cert X509Certificate) to_pem_file(path string) ! {
	cert.save_to_file(path, .pem)
}

// to_der_file saves a certificate to a DER file
pub fn (cert X509Certificate) to_der_file(path string) ! {
	cert.save_to_file(path, .der)
}

// load_csr loads a CSR from a file (PEM or DER)
//
// Example:
// ```v
// csr := x509.load_csr('request.csr')!
// ```
pub fn load_csr(path string) !CSR {
	if !os.exists(path) {
		return error('CSR file does not exist: ${path}')
	}

	data := os.read_file(path)!

	// Detect format
	if data.contains('-----BEGIN CERTIFICATE REQUEST-----')
		|| data.contains('-----BEGIN NEW CERTIFICATE REQUEST-----') {
		return parse_pem_csr(data)
	}

	// Assume DER format
	return parse_csr(data.bytes())
}

// save_csr saves a CSR to a file
pub fn (csr CSR) save_to_file(path string, format CertificateFormat) ! {
	match format {
		.pem {
			pem_data := csr.to_pem()
			os.write_file(path, pem_data)!
		}
		.der {
			der_data := csr.to_der()
			os.write_file(path, der_data.bytestr())!
		}
	}
}

// to_pem_file saves a CSR to a PEM file
pub fn (csr CSR) to_pem_file(path string) ! {
	csr.save_to_file(path, .pem)
}

// to_der_file saves a CSR to a DER file
pub fn (csr CSR) to_der_file(path string) ! {
	csr.save_to_file(path, .der)
}

// load_certificate_bundle loads a certificate bundle from a file
pub fn load_certificate_bundle(path string) !CertificateBundle {
	certs := load_certificates(path)!
	return CertificateBundle{
		certificates: certs
	}
}

// get_certificates returns all certificates in the bundle
pub fn (bundle CertificateBundle) get_certificates() []X509Certificate {
	return bundle.certificates
}

// find_certificate finds a certificate by serial number
pub fn (bundle CertificateBundle) find_certificate(serial_number []u8) !X509Certificate {
	for cert in bundle.certificates {
		if cert.serial_number == serial_number {
			return cert
		}
	}
	return error('certificate not found with serial number')
}

// find_certificate_by_cn finds a certificate by common name
pub fn (bundle CertificateBundle) find_certificate_by_cn(cn string) !X509Certificate {
	for cert in bundle.certificates {
		if cert.subject.common_name == cn {
			return cert
		}
	}
	return error('certificate not found with common name: ${cn}')
}

// find_ca_certificates returns all CA certificates in the bundle
pub fn (bundle CertificateBundle) find_ca_certificates() []X509Certificate {
	mut ca_certs := []X509Certificate{}
	for cert in bundle.certificates {
		if cert.is_ca() {
			ca_certs << cert
		}
	}
	return ca_certs
}

// save_bundle saves a certificate bundle to a PEM file
pub fn (bundle CertificateBundle) save_to_file(path string) ! {
	mut pem_data := strings.new_builder(1024)
	for cert in bundle.certificates {
		pem_data.write_string(cert.to_pem())
		if cert != bundle.certificates.last() {
			pem_data.write_string('\n')
		}
	}
	os.write_file(path, pem_data.str())!
}

// pem_from_der converts DER data to PEM format
pub fn pem_from_der(der_data []u8, type_ string) string {
	return encoding.pem_encode(type_, {}, der_data)
}

// der_from_pem converts PEM data to DER format
pub fn der_from_pem(pem_str string, expected_type string) ![]u8 {
	block := encoding.pem_decode(pem_str)!
	if expected_type != '' && block.type_ != expected_type {
		return error('invalid PEM type, expected ${expected_type}, got ${block.type_}')
	}
	return block.bytes
}

// encode_certificate_pem encodes a certificate to PEM format
pub fn encode_certificate_pem(cert X509Certificate) string {
	return cert.to_pem()
}

// decode_certificate_pem decodes a PEM-encoded certificate
pub fn decode_certificate_pem(pem_str string) !X509Certificate {
	return parse_pem_certificate(pem_str)
}

// encode_certificate_der encodes a certificate to DER format
pub fn encode_certificate_der(cert X509Certificate) []u8 {
	return cert.to_der()
}

// decode_certificate_der decodes a DER-encoded certificate
pub fn decode_certificate_der(der_data []u8) !X509Certificate {
	return parse_certificate(der_data)
}

// encode_csr_pem encodes a CSR to PEM format
pub fn encode_csr_pem(csr CSR) string {
	return csr.to_pem()
}

// decode_csr_pem decodes a PEM-encoded CSR
pub fn decode_csr_pem(pem_str string) !CSR {
	return parse_pem_csr(pem_str)
}

// encode_csr_der encodes a CSR to DER format
pub fn encode_csr_der(csr CSR) []u8 {
	return csr.to_der()
}

// decode_csr_der decodes a DER-encoded CSR
pub fn decode_csr_der(der_data []u8) !CSR {
	return parse_csr(der_data)
}

// CertificatePair represents a certificate and its private key
pub struct CertificatePair {
pub:
	certificate X509Certificate
	private_key []u8 // DER-encoded private key
}

// load_certificate_pair loads a certificate and private key pair
pub fn load_certificate_pair(cert_path string, key_path string) !CertificatePair {
	cert := load_certificate(cert_path)!
	key_data := os.read_file(key_path)!

	// Decode PEM key
	block := encoding.pem_decode(key_data)!
	private_key := block.bytes

	return CertificatePair{
		certificate: cert
		private_key: private_key
	}
}

// save_certificate_pair saves a certificate and private key pair
pub fn (pair CertificatePair) save_to_files(cert_path string, key_path string) ! {
	pair.certificate.to_pem_file(cert_path)!

	// Determine key type based on certificate
	key_type := 'PRIVATE KEY'
	// This is simplified - full implementation would detect RSA vs EC vs Ed25519
	pem_data := encoding.pem_encode(key_type, {}, pair.private_key)
	os.write_file(key_path, pem_data)!
}
