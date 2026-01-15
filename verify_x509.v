module main
import x509

fn main() {
    println('Compiling x509 verification test...')
    c := x509.X509Certificate{}
    // Self-signed check (should be false as keys are empty)
    res := x509.verify_signature(c, c)
    println('Verification result: ${res}')
}
