import math.big

fn main() {
    $for method in big.Integer.methods {
        if method.name == 'mod_pow' || method.name == 'big_mod_pow' {
            println('${method.name} args: ${method.args.len}')
            $for arg in method.args {
                println('  arg: ${arg.typ}')
            }
            println('  returns: ${method.return_type}')
        }
    }
}
