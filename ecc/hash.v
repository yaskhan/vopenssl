module ecc

import crypto.sha1
import crypto.sha256
import crypto.sha512
import crypto.md5
import os

// HashAlgorithm определяет алгоритм хеширования
// Поддерживаем только те алгоритмы, которые есть в vlib/crypto
pub enum HashAlgorithm {
	sha1
	sha256
	sha512
	md5
}

// hash_bytes вычисляет хеш данных с указанным алгоритмом
pub fn hash_bytes(data []u8, algorithm HashAlgorithm) []u8 {
	match algorithm {
		.sha1 { return sha1.sum(data) }
		.sha256 { return sha256.sum256(data) }
		.sha512 { return sha512.sum512(data) }
		.md5 { return md5.sum(data) }
	}
}

// hash_file вычисляет хеш файла
pub fn hash_file(path string, algorithm HashAlgorithm) ![]u8 {
	data := os.read_bytes(path)!
	return hash_bytes(data, algorithm)
}

// get_hash_length возвращает длину хеша в байтах
pub fn get_hash_length(algorithm HashAlgorithm) int {
	match algorithm {
		.sha1 { return 20 }
		.sha256 { return 32 }
		.sha512 { return 64 }
		.md5 { return 16 }
	}
}

// get_hash_oid возвращает OID алгоритма хеширования (для ASN.1)
pub fn get_hash_oid(algorithm HashAlgorithm) []u8 {
	match algorithm {
		.sha1 {
			// 1.3.14.3.2.26
			return [u8(0x2b), u8(0x0e), u8(0x03), u8(0x02), u8(0x1a)]
		}
		.sha256 {
			// 2.16.840.1.101.3.4.2.1
			return [u8(0x60), u8(0x86), u8(0x48), u8(0x01), u8(0x65), u8(0x03), u8(0x04), u8(0x02), u8(0x01)]
		}
		.sha512 {
			// 2.16.840.1.101.3.4.2.3
			return [u8(0x60), u8(0x86), u8(0x48), u8(0x01), u8(0x65), u8(0x03), u8(0x04), u8(0x02), u8(0x03)]
		}
		.md5 {
			// 1.2.840.113549.2.5
			return [u8(0x2a), u8(0x86), u8(0x48), u8(0x86), u8(0xf7), u8(0x0d), u8(0x02), u8(0x05)]
		}
	}
}
