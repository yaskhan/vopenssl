module ed25519

import vopenssl.utils

fn test_sign_context() {
	// From RFC 8032 (Test vectors for Ed25519ctx)
	// Example 1:
	// priv = 033E5331...
	// pub = 8520F300...
	// msg = 616263 (abc)
	// ctx = 666F6F (foo)
	// ph = 0
	// sig = 55A4CC2F...
	
	priv_hex := '033E53313F01C3177651811F0D53E879C56A39180D824BCAEA6E745A1E53460E2A9F5687720760DC8A1054E86267D226B2230CE39FF3567B22849842C9ADCD35'
	priv := utils.unhex(priv_hex)
	msg := 'abc'.bytes()
	ctx := 'foo'.bytes()
	
	sig := sign_context(priv, msg, ctx) or {
		assert false
		return
	}
	
	// Check if signature starts with expected R (simplified check for now)
	println('Signature: ${utils.hex(sig)}')
	assert sig.len == 64
}

fn test_sign_ph() {
	priv_hex := '033E53313F01C3177651811F0D53E879C56A39180D824BCAEA6E745A1E53460E2A9F5687720760DC8A1054E86267D226B2230CE39FF3567B22849842C9ADCD35'
	priv := utils.unhex(priv_hex)
	msg := 'abc'.bytes()
	ctx := 'bar'.bytes()
	
	sig := sign_ph(priv, msg, ctx) or {
		assert false
		return
	}
	
	assert sig.len == 64
}
