module main

import encoding
import utils

fn main() {
	println('=== VOpenSSL Encoding Tests ===\n')
	
	test_base64()
	test_pem()
	test_asn1()
	
	println('\n=== All Encoding Tests Passed! ===')
}

fn test_base64() {
	println('Test 1: Base64')
	data := 'Hello VOpenSSL'.bytes()
	encoded := encoding.base64_encode(data)
	println('Encoded: ${encoded}')
	
	decoded := encoding.base64_decode(encoded) or {
		panic(err)
	}
	println('Decoded: ${decoded.bytestr()}')
	
	assert decoded.bytestr() == 'Hello VOpenSSL'
	println('✓ Base64 passed\n')
}

fn test_pem() {
	println('Test 2: PEM')
	data := 'Secret Key Data'.bytes()
	pem_str := encoding.pem_encode('PRIVATE KEY', {'Proc-Type': '4,ENCRYPTED'}, data)
	println('PEM Output:\n${pem_str}')
	
	block := encoding.pem_decode(pem_str) or {
		panic(err)
	}
	
	println('Decoded Type: ${block.type_}')
	println('Decoded Headers: ${block.headers}')
	println('Decoded Data: ${block.bytes.bytestr()}')
	
	assert block.type_ == 'PRIVATE KEY'
	assert block.headers['Proc-Type'] == '4,ENCRYPTED'
	assert block.bytes.bytestr() == 'Secret Key Data'
	println('✓ PEM passed\n')
}

fn test_asn1() {
	println('Test 3: ASN.1 Primitive Parsing')
	// Construct a manual DER sequence:
	// SEQUENCE (0x30) + Length
	//   INTEGER (0x02) + Len (0x01) + Val (0x2A = 42)
	//   OCTET STRING (0x04) + Len (0x03) + Val (ABC)
	
	mut der := []u8{}
	der << 0x30 // SEQUENCE
	der << 0x08 // Length of sequence body (3 + 5 = 8)
	
	// Integer 42
	der << 0x02
	der << 0x01
	der << 0x2A
	
	// Octet String 'ABC'
	der << 0x04
	der << 0x03
	der << 'ABC'.bytes()
	
	println('DER input: ${utils.hex(der)}')
	
	val := encoding.asn1_unmarshal(der) or {
		panic(err)
	}
	
	// Check root is array (Sequence)
	if val is []encoding.ASN1Value {
		println('Root is Sequence with ${val.len} items')
		assert val.len == 2
		
		item0 := val[0]
		if item0 is i64 {
			println('Item 0: Integer ${item0}')
			assert item0 == 42
		} else {
			panic('Item 0 should be Integer')
		}
		
		item1 := val[1]
		if item1 is []u8 {
			println('Item 1: OctetString ${item1.bytestr()}')
			assert item1.bytestr() == 'ABC'
		} else {
			println('Item 1 type: ${item1.type_name()}')
			panic('Item 1 should be OctetString')
		}
	} else {

		panic('Root should be Sequence')
	}
	println('✓ ASN.1 passed\n')
}
