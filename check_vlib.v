module main
import crypto.sha256
import crypto.sha512
import crypto.md5
import crypto.sha1

fn main() {
    d256 := sha256.new()
    println('SHA256 type: ${typeof(d256).name}')
    
    d512 := sha512.new()
    println('SHA512 type: ${typeof(d512).name}')

    d1 := sha1.new()
    println('SHA1 type: ${typeof(d1).name}')

    dmd5 := md5.new()
    println('MD5 type: ${typeof(dmd5).name}')
}
