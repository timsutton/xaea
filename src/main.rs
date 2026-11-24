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

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use std::process::ExitCode;

fn main() -> ExitCode {
    // Version requested via --version/-V keeps clap's own convention, but
    // gains the --json envelope for consistency with `xaea version --json`.
    if std::env::args()
        .skip(1)
        .any(|a| a == "-V" || a == "--version")
    {
        let v = env!("CARGO_PKG_VERSION");
        if argv_has_flag("--json") {
            println!("{}", serde_json::json!({ "version": v }));
        } else {
            println!("xaea {v}");
        }
        return ExitCode::SUCCESS;
    }
    // try_parse + the error-kind match let us print JSON errors when --json
    // was passed; clap's own exit() path can't. DisplayHelp prints to
    // stdout and exits 0; anything else is a usage error (exit 2).
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => return handle_clap_error(&e),
    };
    let json = match &cli.cmd {
        Some(Commands::Inspect(a)) => a.json,
        Some(Commands::Extract(a)) => a.json,
        Some(Commands::Version(a)) => a.json,
        _ => false,
    };
    match &cli.cmd {
        // Concise help on stdout, exit 0 — see #25 of cli.style.
        None => {
            let mut cmd = Cli::command();
            // A closed pipe on the help print is not a failure.
            let _ = cmd.print_help();
            ExitCode::SUCCESS
        }
        Some(Commands::Inspect(args)) => exit::report(cmd::inspect::run(args), json),
        Some(Commands::Cat(args)) => exit::report(cmd::cat::run(args), json),
        Some(Commands::Extract(args)) => exit::report(cmd::extract::run(args), json),
        Some(Commands::Completions(args)) => {
            completions::print(args.shell);
            ExitCode::SUCCESS
        }
        Some(Commands::Version(args)) => {
            let v = env!("CARGO_PKG_VERSION");
            if args.json {
                println!("{}", serde_json::json!({ "version": v }));
            } else {
                println!("xaea {v}");
            }
            ExitCode::SUCCESS
        }
    }
}

/// clap's own error path, with the JSON-error envelope (#46): when `--json`
/// is on the command line, usage errors go to stderr as a JSON object.
fn handle_clap_error(e: &clap::Error) -> ExitCode {
    use clap::error::ErrorKind;
    match e.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            // Print help to stdout, exit 0 (clap's own convention).
            let _ = e.print();
            ExitCode::SUCCESS
        }
        _ => {
            if argv_has_flag("--json") {
                let message = e
                    .to_string()
                    .lines()
                    .next()
                    .unwrap_or("invalid command line")
                    .trim_start_matches("error: ")
                    .to_string();
                eprintln!(
                    "{}",
                    serde_json::json!({ "error": { "code": "USAGE", "exit_code": 2, "message": message } })
                );
            } else {
                let _ = e.print();
            }
            ExitCode::from(2)
        }
    }
}

/// Whether argv carries `--json` (a literal token, or `--json=true`).
fn argv_has_flag(flag: &str) -> bool {
    std::env::args()
        .skip(1)
        .any(|a| a == flag || a == format!("{flag}=true") || a == format!("{flag}=false"))
}
