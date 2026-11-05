//! Command line: `orange-recompile <input.elf> <output.orange>`.

use std::process::ExitCode;

fn run(args: &[String]) -> Result<(), String> {
    let [_, input, output] = args else {
        return Err("usage: orange-recompile <input.elf> <output.orange>".to_owned());
    };
    let bytes = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    let loaded = orange_recompile::Input::load(&bytes).map_err(|e| format!("{input}: {e}"))?;
    let module = orange_recompile::recompile(&loaded, &orange_recompile::Options::default())
        .map_err(|e| format!("{input}: {e}"))?;
    std::fs::write(output, &module).map_err(|e| format!("{output}: {e}"))?;
    eprintln!("{output}: {} bytes", module.len());
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}
