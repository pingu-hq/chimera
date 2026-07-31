use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() != 1 {
        eprintln!("usage: embroider <policy.chmp>");
        process::exit(1);
    }

    match chimera::embroider::compile(&args[0]) {
        Ok(code) => print!("{code}"),
        Err(e) => {
            eprintln!("embroider: {e}");
            process::exit(1);
        }
    }
}
