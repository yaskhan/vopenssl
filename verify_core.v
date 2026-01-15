module main

fn main() {
    x := u32(0x510e527f)
    println('x: ${x:08x}')
    println('rotr(x, 6): ${rotr(x, 6):08x}')
    println('rotr(x, 11): ${rotr(x, 11):08x}')
    println('rotr(x, 25): ${rotr(x, 25):08x}')
    println('big_sigma1(x): ${big_sigma1(x):08x}')
    
    e := u32(0x510e527f)
    f := u32(0x9b05688c)
    g := u32(0x1f83d9ab)
    println('ch(e,f,g): ${ch(e,f,g):08x}')
    
    s1 := big_sigma1(e)
    c := ch(e,f,g)
    println('s1 + c: ${(s1+c):08x}')
    
    h := u32(0x5be0cd19)
    k := u32(0x428a2f98)
    w := u32(0x80000000)
    
    t1 := h + s1 + c + k + w
    println('t1: ${t1:08x}')
}

fn rotr(x u32, n int) u32 { return (x >> n) | (x << (32 - n)) }
fn shr(x u32, n int) u32 { return x >> n }
fn big_sigma1(x u32) u32 { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25) }
fn ch(x u32, y u32, z u32) u32 { return (x & y) ^ ((~x) & z) }
