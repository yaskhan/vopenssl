module encoding

import strings
import encoding.base64

// PEMBlock represents a PEM encoded block.
pub struct PEMBlock {
pub:
	type_   string            // The type of the block (e.g. "PUBLIC KEY")
	headers map[string]string // Optional headers
	bytes   []u8              // The decoded data
}

// pem_encode encodes data to PEM format.
//
// Example:
// ```v
// pem_str := encoding.pem_encode('PUBLIC KEY', {}, data)
// ```
pub fn pem_encode(type_ string, headers map[string]string, data []u8) string {
	mut sb := strings.new_builder(1024)
	sb.writeln('-----BEGIN ${type_}-----')
	
	for key, value in headers {
		sb.writeln('${key}: ${value}')
	}
	if headers.len > 0 {
		sb.writeln('')
	}
	
	encoded := base64.encode(data)
	// Split into lines of 64 characters
	mut i := 0
	for i < encoded.len {
		end := if i + 64 < encoded.len { i + 64 } else { encoded.len }
		sb.writeln(encoded[i..end])
		i += 64
	}
	
	sb.writeln('-----END ${type_}-----')
	return sb.str()
}

// pem_decode parses a PEM encoded string and returns the first block found.
// returns (PEMBlock) or error if no PEM block is found.
//
// Example:
// ```v
// block := encoding.pem_decode(pem_str)!
// println(block.type_)
// ```
pub fn pem_decode(data string) !PEMBlock {
	// Simple parser
	start_marker := '-----BEGIN '
	end_marker := '-----END '
	
	start_idx := data.index(start_marker) or {
		return error('no PEM block found')
	}
	
	// Parse type from header
	// Parse type from header
	header_end_idx := data.index_after('\n', start_idx) or {
		return error('malformed PEM header')
	}
	
	header_line := data[start_idx..header_end_idx].trim_space()
	if !header_line.ends_with('-----') {
		return error('malformed PEM header')
	}
	
	type_ := header_line.replace('-----BEGIN ', '').replace('-----', '')
	
	// Find footer
	footer_tag := '${end_marker}${type_}-----'
	footer_idx := data.index(footer_tag) or {
		return error('PEM footer not found for type ${type_}')
	}
	
	// Skip the newline after header
	body := data[header_end_idx + 1 .. footer_idx]
	lines := body.split_into_lines()

	
	mut headers := map[string]string{}
	mut base64_data := strings.new_builder(1024)
	mut in_headers := true
	
	for line in lines {
		trimmed := line.trim_space()
		if trimmed == '' {
			if in_headers {
				in_headers = false
				continue
			}
			continue
		}
		
		if in_headers && trimmed.contains(':') {
			parts := trimmed.split_nth(':', 2)
			if parts.len == 2 {
				headers[parts[0].trim_space()] = parts[1].trim_space()
				continue
			}
		}
		
		// If we reach here, we are in body or we decided headers are done
		in_headers = false
		base64_data.write_string(trimmed)
	}
	
	decoded_bytes := base64.decode(base64_data.str())
	
	return PEMBlock{
		type_:   type_
		headers: headers
		bytes:   decoded_bytes
	}
}
