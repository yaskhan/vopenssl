import vopenssl.x509
import time

fn main() {
	println('VOpenSSL X.509 Certificate Examples')
	println('===================================\n')

	// Example 1: Parse a PEM certificate
	println('Example 1: Parsing a PEM Certificate')
	println('-------------------------------------')

	// This is a simplified example with a placeholder certificate
	// In real usage, you would load from a file
	pem_cert := [
		'-----BEGIN CERTIFICATE-----',
		'MIICLDCCAdKgAwIBAgIBADAKBggqhkjOPQQDAjB9MQswCQYDVQQGEwJVUzELMAkG',
		'A1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHTAbBgNVBAoTFFJhbmRv',
		'bSBIb2xkaW5ncyBMTEMxJTAjBgNVBAMTHHJhbmRvbS1leGFtcGxlLmNyeXB0by5k',
		'ZXYwHhcNMjQwMTE1MDAwMDAwWhcNMjUwMTE1MDAwMDAwWjB9MQswCQYDVQQGEwJV',
		'UzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHTAbBgNVBAoT',
		'FFJhbmRvbSBIb2xkaW5ncyBMTEMxJTAjBgNVBAMTHHJhbmRvbS1leGFtcGxlLmNy',
		'eXB0by5kZXYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARuLr1Bj3OJ3iRqC9C6',
		'Hc0vP4w1J0yJ0yZ3Y2J0yZ3Y2J0yZ3Y2J0yZ3Y2J0yZ3Y2J0yZ3Y2J0o0',
		'IwQDAPBgNVHRMBAf8EBTADAQH/MA0GA1UdDwQwBAUEAAMGA1UdEQQIMAaCBXJh',
		'bmRvbTANBgkqhkiG9w0BAQsFAAOBgQCBAR4CBAR4CBAR4CBAR4CBAR4CBAR4CBA',
		'R4CBAR4CBAR4CBAR4CBAR4CBAR4CBAR4CBAR4CBAR4CBAR4CBA',
		'R4CBAR4CBAR4CBAR4CBAR4CBAR4CBAR4CBAR4CBA==',
		'-----END CERTIFICATE-----',
	].join('\n')

	cert := x509.parse_pem_certificate(pem_cert) or {
		println('Failed to parse certificate: ${err}')
		return
	}

	println('Certificate parsed successfully!')
	println('Subject: ${cert.subject.common_name}')
	println('Issuer: ${cert.issuer.common_name}')
	println('Serial: ${cert.get_serial_number()}')
	println('Version: ${cert.version}')
	println()

	// Example 2: Check certificate validity
	println('Example 2: Certificate Validation')
	println('---------------------------------')

	println('Is currently valid: ${cert.is_valid_now()}')
	println('Is expired: ${cert.is_expired()}')
	println('Is CA: ${cert.is_ca()}')

	validity := cert.validity
	println('Valid from: ${validity.not_before}')
	println('Valid to: ${validity.not_after}')
	println()

	// Example 3: Certificate name information
	println('Example 3: Certificate Subject Information')
	println('-------------------------------------------')

	subject := cert.get_subject()
	if subject.country != '' {
		println('Country: ${subject.country}')
	}
	if subject.state_or_province != '' {
		println('State: ${subject.state_or_province}')
	}
	if subject.locality != '' {
		println('Locality: ${subject.locality}')
	}
	if subject.organization != '' {
		println('Organization: ${subject.organization}')
	}
	if subject.organizational_unit != '' {
		println('Organizational Unit: ${subject.organizational_unit}')
	}
	if subject.common_name != '' {
		println('Common Name: ${subject.common_name}')
	}
	if subject.email_address != '' {
		println('Email: ${subject.email_address}')
	}
	println()

	// Example 4: Create a simple Certificate Signing Request
	println('Example 4: Creating a Certificate Signing Request')
	println('-------------------------------------------------')

	csr_subject := x509.X509Name{
		country:             'US'
		state_or_province:   'California'
		locality:            'San Francisco'
		organization:        'Example Inc'
		organizational_unit: 'Engineering'
		common_name:         'example.com'
		email_address:       'admin@example.com'
	}

	// Note: In a real implementation, you would need actual public/private keys
	// This is a simplified example structure
	println('CSR Subject:')
	println('  Common Name: ${csr_subject.common_name}')
	println('  Organization: ${csr_subject.organization}')
	println('  Email: ${csr_subject.email_address}')
	println()

	// Example 5: Certificate validation options
	println('Example 5: Certificate Validation Options')
	println('-----------------------------------------')

	validation_opts := x509.ValidationOptions{
		current_time:      time.now()
		dns_name:          'example.com'
		allow_expired:     false
		allow_self_signed: true
		max_path_length:   5
	}

	println('Validation Options:')
	println('  Current Time: ${validation_opts.current_time}')
	println('  DNS Name: ${validation_opts.dns_name}')
	println('  Allow Expired: ${validation_opts.allow_expired}')
	println('  Allow Self-Signed: ${validation_opts.allow_self_signed}')
	println('  Max Path Length: ${validation_opts.max_path_length}')
	println()

	// Example 6: Convert certificate to PEM
	println('Example 6: Certificate PEM/DER Conversion')
	println('------------------------------------------')

	pem_output := cert.to_pem()
	println('Certificate PEM (first 200 chars):')
	max_len := 200.min(pem_output.len)
	println(pem_output[..max_len])
	println('...')

	// Example 7: Certificate validation result
	println('\nExample 7: Validation Result')
	println('----------------------------')

	result := x509.validate_certificate(cert, [], validation_opts) or {
		println('Validation failed: ${err}')
		return
	}

	println('Is Valid: ${result.is_valid}')
	println('Is Trusted: ${result.is_trusted}')
	println('Chain Length: ${result.chain.len}')

	for error_msg in result.errors {
		println('Error: ${error_msg}')
	}

	for warning in result.warnings {
		println('Warning: ${warning}')
	}

	println('\nX.509 Examples Completed!')
}

fn min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
