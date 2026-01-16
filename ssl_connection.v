//use this file for embed in vlib net
module vopenssl

import net
import net.vopenssl.tls

pub struct SSLConn {
pub:
	config SSLConnectConfig
pub mut:
	tls_conn tls.TLSConnection
	handle   int
}

@[params]
pub struct SSLConnectConfig {
pub:
	verify   string 
	cert     string 
	cert_key string 
	validate bool   
	in_memory_verification bool 
}

pub fn new_ssl_conn(config SSLConnectConfig) !&SSLConn {
	return &SSLConn{
		config: config
	}
}

pub fn (mut s SSLConn) dial(hostname string, port int) ! {
	mut tcp_conn := net.dial_tcp('${hostname}:${port}')!
	s.connect(mut tcp_conn, hostname)!
}

pub fn (mut s SSLConn) connect(mut tcp_conn net.TcpConn, hostname string) ! {
	s.handle = tcp_conn.sock.handle
	
	mut certs := [][]u8{}
	if s.config.cert != '' {
		certs << s.config.cert.bytes()
	}
	mut root_cas := [][]u8{}
	if s.config.verify != '' {
		root_cas << s.config.verify.bytes()
	}

	mut tls_config := tls.TLSConfig{
		server_name: hostname
		insecure_skip_verify: !s.config.validate
		certificates: certs
		private_key: s.config.cert_key.bytes()
		root_cas: root_cas
	}

	s.tls_conn = tls.new_client(tcp_conn, tls_config)
	s.tls_conn.handshake()!
}

pub fn (mut s SSLConn) socket_read_into_ptr(buf_ptr &u8, len int) !int {
	mut buffer := unsafe { buf_ptr.vbytes(len) }
	return s.tls_conn.read(mut buffer)
}

pub fn (mut s SSLConn) read(mut buffer []u8) !int {
	return s.socket_read_into_ptr(&u8(buffer.data), buffer.len)
}

pub fn (mut s SSLConn) write_ptr(bytes &u8, len int) !int {
	buffer := unsafe { bytes.vbytes(len) }
	return s.tls_conn.write(buffer)
}

pub fn (mut s SSLConn) write(bytes []u8) !int {
	return s.write_ptr(&u8(bytes.data), bytes.len)
}

pub fn (mut s SSLConn) write_string(str string) !int {
	return s.write_ptr(str.str, str.len)
}

pub fn (mut s SSLConn) close() ! {
	s.tls_conn.close()!
}

pub fn (mut s SSLConn) shutdown() ! {
	s.tls_conn.close()!
}

pub fn (s &SSLConn) addr() !net.Addr {
	return net.addr_from_socket_handle(s.handle)
}

pub fn (s &SSLConn) peer_addr() !net.Addr {
	return net.peer_addr_from_socket_handle(s.handle)
}
