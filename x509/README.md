# VOpenSSL X.509 Module

The X.509 module provides comprehensive support for X.509 certificates, Certificate Signing Requests (CSRs), and certificate validation.

## Features

- ✅ Parse X.509 certificates from PEM and DER formats
- ✅ Create Certificate Signing Requests (CSRs)
- ✅ Validate certificates (validity period, signature, chain)
- ✅ Extract certificate information (subject, issuer, validity)
- ✅ Certificate validation with customizable options
- ✅ Certificate chain validation
- ✅ PEM/DER encoding and decoding utilities
- ✅ Certificate bundle support
- ✅ Certificate and private key pair management

## Usage

### Loading a Certificate

```v
import vopenssl.x509

// Load from PEM file
cert := x509.load_certificate('cert.pem')!

// Parse from PEM string
pem_data := os.read_file('cert.pem')!
cert := x509.parse_pem_certificate(pem_data)!

// Parse from DER bytes
der_data := os.read_bytes('cert.der')!
cert := x509.parse_certificate(der_data)!
```

### Certificate Information

```v
// Check validity
is_valid := cert.is_valid_now()
is_expired := cert.is_expired()

// Get subject information
subject := cert.get_subject()
println('CN: ${subject.common_name}')
println('O: ${subject.organization}')
println('C: ${subject.country}')

// Get issuer information
issuer := cert.get_issuer()
println('Issuer: ${issuer.common_name}')

// Check if certificate is a CA
is_ca := cert.is_ca()

// Get serial number
serial := cert.get_serial_number()
```

### Certificate Validation

```v
import vopenssl.x509
import time

// Set validation options
opts := x509.ValidationOptions{
	current_time: time.now()
	dns_name: 'example.com'
	email_address: 'admin@example.com'
	allow_expired: false
	allow_self_signed: false
	max_path_length: 5
	key_usage: [
		x509.KeyUsage.digital_signature,
		x509.KeyUsage.key_encipherment,
	]
}

// Validate certificate
result := x509.validate_certificate(cert, [], opts)!

if result.is_valid {
	println('Certificate is valid')
	println('Is trusted: ${result.is_trusted}')
} else {
	for error_msg in result.errors {
		println('Error: ${error_msg}')
	}
}
```

### Creating a Certificate Signing Request

```v
import vopenssl.x509

// Define subject
subject := x509.X509Name{
	country: 'US'
	state_or_province: 'California'
	locality: 'San Francisco'
	organization: 'My Company Inc'
	organizational_unit: 'IT Department'
	common_name: 'example.com'
	email_address: 'admin@example.com'
}

// Create CSR (requires actual key pair in production)
// public_key := key_pair.public
// private_key := key_pair.private
// signature_alg := [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] // SHA256withRSA

// csr := x509.create_csr(subject, public_key, private_key, signature_alg)!

// Save CSR to file
// csr.to_pem_file('request.csr')!
```

### Loading and Parsing CSRs

```v
import vopenssl.x509

// Load CSR from file
csr := x509.load_csr('request.csr')!

// Parse from PEM string
pem_data := os.read_file('request.csr')!
csr := x509.parse_pem_csr(pem_data)!

// Get subject from CSR
subject := csr.get_subject()
println('Subject: ${subject.common_name}')

// Verify CSR signature
is_valid := csr.verify()
```

### Signing a CSR (CA Operation)

```v
import vopenssl.x509
import time

// Load CSR
csr := x509.load_csr('request.csr')!

// Load CA certificate and private key
issuer_cert := x509.load_certificate('ca_cert.pem')!
issuer_priv_key := os.read_bytes('ca_key.der')!

// Define validity
validity := x509.X509Validity{
	not_before: time.now()
	not_after: time.now().add_days(365)
}

// Sign CSR
cert := x509.sign_csr(csr, issuer_cert, issuer_priv_key, validity)!

// Save issued certificate
cert.to_pem_file('issued_cert.pem')!
```

### Certificate Chain Validation

```v
import vopenssl.x509

// Load certificate chain
intermediates := x509.load_certificates('intermediate_bundle.pem')!

// Validate chain
result := x509.validate_chain(cert, intermediates, opts)

if result.is_valid {
	println('Certificate chain is valid')
	println('Chain length: ${result.chain.len}')
} else {
	for error_msg in result.errors {
		println('Error: ${error_msg}')
	}
}
```

### Certificate Bundles

```v
import vopenssl.x509

// Load certificate bundle
bundle := x509.load_certificate_bundle('bundle.pem')!

// Get all certificates
certs := bundle.get_certificates()

// Find CA certificates
ca_certs := bundle.find_ca_certificates()

// Find by common name
cert := bundle.find_certificate_by_cn('example.com')!

// Save bundle
bundle.save_to_file('output_bundle.pem')!
```

### PEM/DER Conversion

```v
import vopenssl.x509

// Certificate PEM to DER
cert := x509.parse_pem_certificate(pem_str)!
der_data := cert.to_der()

// Certificate DER to PEM
cert := x509.parse_certificate(der_data)!
pem_str := cert.to_pem()

// CSR PEM to DER
csr := x509.parse_pem_csr(pem_str)!
der_data := csr.to_der()

// CSR DER to PEM
csr := x509.parse_csr(der_data)!
pem_str := csr.to_pem()
```

## Data Structures

### X509Name
Represents a Distinguished Name (DN):
```v
pub struct X509Name {
	country            string // C
	organization       string // O
	organizational_unit string // OU
	common_name        string // CN
	locality           string // L
	state_or_province  string // ST
	domain_component   string // DC
	email_address      string // EMAILADDRESS
}
```

### X509Validity
Represents certificate validity period:
```v
pub struct X509Validity {
	not_before time.Time
	not_after  time.Time
}
```

### X509Certificate
Represents an X.509 certificate:
```v
pub struct X509Certificate {
	version              int
	serial_number        []u8
	issuer               X509Name
	subject              X509Name
	validity             X509Validity
	public_key           []u8
	public_key_algorithm []int
	signature_algorithm  []int
	signature            []u8
	extensions           []X509Extension
}
```

### CSR
Represents a Certificate Signing Request:
```v
pub struct CSR {
	version      int
	subject      X509Name
	public_key   []u8
	attributes   map[string][]u8
	signature    []u8
	signature_algorithm []int
}
```

### ValidationOptions
Options for certificate validation:
```v
pub struct ValidationOptions {
	current_time        time.Time
	dns_name           string
	email_address      string
	ip_address         string
	allow_expired      bool
	allow_self_signed  bool
	max_path_length    int
	key_usage          []KeyUsage
	extended_key_usage []int
}
```

## Key Usage

The module supports the following key usage types:

```v
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
```

## Notes

- This implementation provides X.509 certificate parsing, validation, and CSR management
- Certificate creation and signing requires actual key pairs (RSA, ECC, or Ed25519)
- Full signature verification requires cryptographic operations not yet fully implemented
- Certificate revocation checking (CRL/OCSP) is not yet implemented
- Extension parsing is simplified; full extension support requires additional ASN.1 parsing

## Examples

See the examples directory:
- `x509_example.v` - Comprehensive X.509 examples
- `csr_example.v` - CSR creation and management examples

## Security Considerations

- Always validate certificates before use, especially for TLS connections
- Check certificate validity periods and revocation status in production
- Verify the full certificate chain when possible
- Be cautious with self-signed certificates in security-sensitive contexts
- Use proper key usage and extended key usage validation for specific applications
