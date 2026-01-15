module main
import vopenssl.formats
fn main() {
    println('Testing formats...')
    encoded := formats.pem_encode('TEST', {}, [u8(0)])
    println(encoded)
}
