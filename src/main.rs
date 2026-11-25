mod aa;
mod cli;
mod cmd;
mod completions;
mod decmpfs;
mod envelope;
mod exit;
mod extract;
mod kdf;
mod prof;
mod sigverify;
mod spool;
mod xz;

use clap::Parser;
use cli::{Cli, Commands};
use std::process::ExitCode;

fn main() -> ExitCode {
    // clap handles --help/--version (exit 0) and usage errors (exit 2) itself.
    let cli = Cli::parse();
    exit::report(match &cli.cmd {
        Commands::Inspect(args) => cmd::inspect::run(args),
        Commands::Decrypt(args) => cmd::decrypt::run(args),
        Commands::Cat(args) => cmd::cat::run(args),
        Commands::Extract(args) => cmd::extract::run(args),
        Commands::Completions(args) => {
            completions::print(args.shell);
            Ok(())
        }
    })
}
