module x509

import time

// Test file for X.509 module
// This file demonstrates the functionality of the X.509 module

// Basic test for X509Name creation
fn test_x509_name() {
	name := X509Name{
		country:           'US'
		state_or_province: 'California'
		locality:          'San Francisco'
		organization:      'Test Company'
		common_name:       'test.example.com'
		email_address:     'admin@test.example.com'
	}

	assert name.country == 'US'
	assert name.common_name == 'test.example.com'
	assert name.email_address == 'admin@test.example.com'
}

// Basic test for X509Validity
fn test_x509_validity() {
	now := time.now()
	validity := X509Validity{
		not_before: now
		not_after:  now.add_days(365)
	}

	assert validity.not_before == now
	assert validity.not_after > validity.not_before
}

// Basic test for X509Extension
fn test_x509_extension() {
	ext := X509Extension{
		oid:      [0x55, 0x1d, 0x13] // Basic constraints
		critical: true
		value:    [u8(0x30), 0x03, 0x01, 0x01, 0xff]
	}

	assert ext.oid.len == 3
	assert ext.critical == true
	assert ext.value.len == 5
}

// Test for ValidationOptions
fn test_validation_options() {
	opts := ValidationOptions{
		current_time:      time.now()
		dns_name:          'example.com'
		allow_expired:     false
		allow_self_signed: false
		max_path_length:   5
	}

	assert opts.dns_name == 'example.com'
	assert opts.allow_expired == false
	assert opts.max_path_length == 5
}

// Test for ValidationResult
fn test_validation_result() {
	result := ValidationResult{
		is_valid:   true
		is_trusted: true
		errors:     []
		warnings:   []
	}

	assert result.is_valid == true
	assert result.is_trusted == true
	assert result.errors.len == 0
}
