import vopenssl.x509
import time

fn main() {
	println('VOpenSSL CSR (Certificate Signing Request) Examples')
	println('===================================================\n')

	// Example 1: Create a CSR subject
	println('Example 1: Creating CSR Subject Information')
	println('---------------------------------------------')

	subject := x509.X509Name{
		country:             'US'
		state_or_province:   'California'
		locality:            'San Francisco'
		organization:        'My Company Inc'
		organizational_unit: 'IT Department'
		common_name:         'example.com'
		email_address:       'admin@example.com'
	}

	println('CSR Subject:')
	println('  Country (C): ${subject.country}')
	println('  State (ST): ${subject.state_or_province}')
	println('  Locality (L): ${subject.locality}')
	println('  Organization (O): ${subject.organization}')
	println('  Organizational Unit (OU): ${subject.organizational_unit}')
	println('  Common Name (CN): ${subject.common_name}')
	println('  Email: ${subject.email_address}')
	println()

	// Example 2: Create CSR (simplified - would need actual keys)
	println('Example 2: Creating a Certificate Signing Request')
	println('---------------------------------------------------')

	// In a real implementation, you would need:
	// 1. Generate a key pair (RSA, ECC, etc.)
	// 2. Create CSR with the public key and sign with private key
	// 3. Submit CSR to a Certificate Authority

	// Placeholder for public key (would be DER-encoded SubjectPublicKeyInfo)
	// public_key := key_pair.public

	// Placeholder for private key (would be DER-encoded PrivateKey)
	// private_key := key_pair.private

	// Signature algorithm OID for SHA256withRSA
	// signature_alg := [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]

	// csr := x509.create_csr(subject, public_key, private_key, signature_alg)!

	println('CSR creation requires:')
	println('  1. Generate a key pair (RSA or ECC)')
	println('  2. Create CSR with subject DN and public key')
	println('  3. Sign CSR with private key')
	println('  4. Submit to Certificate Authority for signing')
	println('  5. Receive signed certificate')
	println()

	// Example 3: Certificate validity period
	println('Example 3: Defining Certificate Validity Period')
	println('-------------------------------------------------')

	now := time.now()
	not_before := now
	not_after := now.add_days(365)

	validity := x509.X509Validity{
		not_before: not_before
		not_after:  not_after
	}

	println('Certificate Validity:')
	println('  Not Before: ${validity.not_before}')
	println('  Not After: ${validity.not_after}')
	println('  Duration: 365 days (1 year)')
	println()

	// Example 4: Certificate types
	println('Example 4: Certificate Types')
	println('------------------------------')

	ca_cert_type := x509.CertificateType.ca_certificate
	end_entity_type := x509.CertificateType.end_entity_certificate
	intermediate_type := x509.CertificateType.intermediate_certificate

	println('Certificate Types:')
	println('  CA Certificate: ${ca_cert_type}')
	println('  End Entity Certificate: ${end_entity_type}')
	println('  Intermediate Certificate: ${intermediate_type}')
	println()

	// Example 5: Key Usage
	println('Example 5: Key Usage Extension')
	println('--------------------------------')

	key_usages := [
		x509.KeyUsage.digital_signature,
		x509.KeyUsage.key_encipherment,
		x509.KeyUsage.data_encipherment,
	]

	println('Key Usage for server certificate:')
	for ku in key_usages {
		println('  - ${ku}')
	}
	println()

	// Example 6: Validation options
	println('Example 6: Certificate Validation Options')
	println('-------------------------------------------')

	validation_opts := x509.ValidationOptions{
		current_time:       time.now()
		dns_name:           'example.com'
		email_address:      'admin@example.com'
		allow_expired:      false
		allow_self_signed:  false
		max_path_length:    5
		key_usage:          key_usages
		extended_key_usage: []int{} // Server auth OID would go here
	}

	println('Validation Options:')
	println('  Current Time: ${validation_opts.current_time}')
	println('  DNS Name: ${validation_opts.dns_name}')
	println('  Email: ${validation_opts.email_address}')
	println('  Allow Expired: ${validation_opts.allow_expired}')
	println('  Allow Self-Signed: ${validation_opts.allow_self_signed}')
	println('  Max Path Length: ${validation_opts.max_path_length}')
	println('  Key Usage Count: ${validation_opts.key_usage.len}')
	println()

	// Example 7: Loading and saving CSR (file operations)
	println('Example 7: Loading and Saving CSR')
	println('----------------------------------')

	// Load CSR from file
	// csr := x509.load_csr('request.csr')!
	// println('Loaded CSR from file')
	// println('Subject: ${csr.get_subject().common_name}')

	// Save CSR to file
	// csr.to_pem_file('my_request.csr')!
	// println('Saved CSR to file')

	println('CSR File Operations:')
	println('  Load: csr := x509.load_csr("request.csr")!')
	println('  Save: csr.to_pem_file("my_request.csr")!')
	println('  PEM: csr.to_pem() -> returns PEM string')
	println('  DER: csr.to_der() -> returns DER bytes')
	println()

	// Example 8: Certificate extensions
	println('Example 8: Common Certificate Extensions')
	println('------------------------------------------')

	extension_descriptions := [
		'Basic Constraints: CA:TRUE, pathlen:0',
		'Key Usage: Digital Signature, Key Encipherment',
		'Extended Key Usage: Server Authentication',
		'Subject Alternative Name: DNS:example.com, DNS:www.example.com',
		'Authority Key Identifier: KeyID=...',
	]

	println('Common Certificate Extensions:')
	for ext in extension_descriptions {
		println('  ${ext}')
	}
	println()

	// Example 9: CSR verification
	println('Example 9: CSR Verification')
	println('----------------------------')

	// After loading a CSR
	// csr := x509.load_csr('request.csr')!

	// Verify CSR signature
	// is_valid := csr.verify()
	// println('CSR signature valid: ${is_valid}')

	// Get subject from CSR
	// subject := csr.get_subject()
	// println('CSR Subject CN: ${subject.common_name}')

	println('CSR Verification:')
	println('  Verify signature: csr.verify() -> bool')
	println('  Get subject: csr.get_subject() -> X509Name')
	println('  Get public key: csr.public_key -> []u8')
	println('  Get signature: csr.signature -> []u8')
	println()

	// Example 10: Signing a CSR (CA operation)
	println('Example 10: Signing a CSR (CA Operation)')
	println('-----------------------------------------')

	// This would be done by a Certificate Authority
	// issuer_cert := x509.load_certificate('ca_cert.pem')!
	// issuer_priv_key := load_private_key('ca_key.pem')

	// Define validity for issued certificate
	// cert_validity := x509.X509Validity{
	//     not_before: time.now()
	//     not_after: time.now().add_days(365)
	// }

	// Sign the CSR
	// issued_cert := x509.sign_csr(csr, issuer_cert, issuer_priv_key, cert_validity)!

	// Save issued certificate
	// issued_cert.to_pem_file('issued_cert.pem')!

	println('CA Operations:')
	println('  1. Load CA certificate and private key')
	println('  2. Validate CSR')
	println('  3. Define certificate validity period')
	println('  4. Sign CSR with CA private key')
	println('  5. Issue certificate')
	println('  6. Save issued certificate')
	println()

	println('CSR Examples Completed!')
}
