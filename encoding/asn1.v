module encoding

import strings


// ASN.1 Tags
pub const (
	tag_boolean          = u8(0x01)
	tag_integer          = u8(0x02)
	tag_bit_string       = u8(0x03)
	tag_octet_string     = u8(0x04)
	tag_null             = u8(0x05)
	tag_object_identifier = u8(0x06)
	tag_utf8_string      = u8(0x0c)
	tag_sequence         = u8(0x30) // 0x10 | 0x20 (constructed)
	tag_set              = u8(0x31) // 0x11 | 0x20
	tag_printable_string = u8(0x13)
	tag_utc_time         = u8(0x17)
)

pub struct OID {
pub:
	ids []int
}

pub fn (o OID) str() string {
	mut sb := strings.new_builder(20)
	for i, id in o.ids {
		if i > 0 { sb.write_string('.') }
		sb.write_string(id.str())
	}
	return sb.str()
}

pub struct ASN1Null {}

pub type ASN1Value = bool | i64 | []u8 | string | OID | ASN1Null | []ASN1Value

// asn1_unmarshal parses basic DER-encoded ASN.1 data.
// It returns a generic ASN1Value structure.
pub fn asn1_unmarshal(data []u8) !ASN1Value {
	if data.len < 2 {
		return error('truncated ASN.1 data')
	}
	
	val, _ := parse_asn1_item(data)!
	return val
}

fn parse_asn1_item(data []u8) !(ASN1Value, int) {
	if data.len < 2 { return error('truncated') }
	
	tag := data[0]
	length, len_bytes := parse_length(data[1..])!
	
	total_len := 1 + len_bytes + length
	if data.len < total_len {
		return error('ASN.1 length mismatch')
	}
	
	content := data[1+len_bytes .. total_len]
	
	val := match tag {
		tag_boolean {
			ASN1Value(content[0] != 0x00)
		}
		tag_integer {
			parse_integer(content)!
		}
		tag_octet_string {
			ASN1Value(content.clone())
		}
		tag_bit_string {
			// First byte is number of unused bits
			if content.len < 1 {
				ASN1Value([]u8{})
			} else {
				ASN1Value(content[1..].clone())
			}
		}
		tag_null {
			ASN1Value(ASN1Null{})
		}
		tag_object_identifier {
			parse_oid(content)!
		}
		tag_utf8_string, tag_printable_string {
			ASN1Value(content.bytestr())
		}
		tag_sequence, tag_set {
			parse_sequence(content)!
		}
		else {
			// Unknown tag, return as bytes for now or error?
			// Return as bytes (Octet String equivalent) to be safe for unhandled types
			ASN1Value(content.clone())
		}
	}
	
	return val, total_len
}

fn parse_length(data []u8) !(int, int) {
	if data.len == 0 { return error('empty length') }
	b := data[0]
	if b & 0x80 == 0 {
		return int(b), 1
	}
	num_bytes := int(b & 0x7f)
	if data.len < 1 + num_bytes { return error('truncated length') }
	if num_bytes > 4 { return error('length too large') }
	
	mut length := 0
	for i in 0 .. num_bytes {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + num_bytes
}

fn parse_integer(data []u8) !ASN1Value {
	if data.len == 0 { return ASN1Value(i64(0)) }
	if data.len > 8 {
		// For now, only support up to 64-bit integers.
		// BigInt support needed for larger.
		// Return bytes if too large?
		return ASN1Value(data.clone()) 
	}
	
	mut res := i64(0)
	for b in data {
		res = (res << 8) | i64(b)
	}
	return ASN1Value(res)
}

fn parse_oid(data []u8) !ASN1Value {
	if data.len == 0 { return error('empty OID') }
	
	mut ids := []int{}
	val1 := int(data[0])
	ids << val1 / 40
	ids << val1 % 40
	
	mut val := 0
	for i in 1 .. data.len {
		b := int(data[i])
		val = (val << 7) | (b & 0x7f)
		if b & 0x80 == 0 {
			ids << val
			val = 0
		}
	}
	
	return ASN1Value(OID{ids: ids})
}

fn parse_sequence(data []u8) !ASN1Value {
	mut list := []ASN1Value{}
	mut offset := 0
	for offset < data.len {
		val, consumed := parse_asn1_item(data[offset..])!
		list << val
		offset += consumed
	}
	return ASN1Value(list)
}
