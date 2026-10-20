//! Command line: `solo-recompile <input.elf> <output.solo>`.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: solo-recompile <input.elf> <output.solo>");
        std::process::exit(2);
    }
    eprintln!("not implemented yet: {} -> {}", args[1], args[2]);
    std::process::exit(1);
}
