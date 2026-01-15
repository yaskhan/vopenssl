module tls

import crypto.sha256

fn test_prf_tls12() {
    secret := [u8(0x01), 0x02, 0x03, 0x04]
    label := "test"
    seed := [u8(0x05), 0x06, 0x07, 0x08]
    
    // Just verify it runs and returns correct length
    out := prf_tls12(secret, label, seed, 32)
    assert out.len == 32
    
    out2 := prf_tls12(secret, label, seed, 32)
    assert out == out2
    
    // Verify different input gives different output
    out3 := prf_tls12(secret, label, [u8(0x05), 0x06, 0x07, 0x09], 32)
    assert out != out3
}

fn test_compute_verify_data() {
    mut tc := TLSConnection{
        master_secret: []u8{len: 48, init: 1}
        handshake_hash: []u8{len: 32, init: 2}
        is_client: true
    }
    
    verify_data := tc.compute_verify_data_tls12()
    assert verify_data.len == 12
    
    // Switch role
    tc.is_client = false
    verify_data_server := tc.compute_verify_data_tls12()
    assert verify_data != verify_data_server
}
