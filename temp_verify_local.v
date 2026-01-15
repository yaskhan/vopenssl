module main
import formats
fn main() {
    println('Testing formats local...')
    encoded := formats.pem_encode('TEST', {}, [u8(0)])
    println(encoded)
}
