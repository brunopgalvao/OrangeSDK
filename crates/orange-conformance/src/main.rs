//! `orange-conformance`: see [`orange_conformance::cli`].

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = String::new();
    let code = orange_conformance::cli::main(&args, &mut out);
    print!("{out}");
    std::process::exit(code);
}
