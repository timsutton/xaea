//! Shell-completion script generation for `xaea completions <SHELL>`.
//!
//! The scripts come from `clap_complete` fed with the real [`crate::cli::Cli`]
//! definition (via the derive's `CommandFactory`), so they track the actual
//! argument parser — including `--decoder`'s value enum — and can never
//! drift from it.

use crate::cli::Cli;
use clap::CommandFactory;
use clap_complete::{Shell, generate};
use std::io;

/// Write the completion script for `shell` to stdout. Write errors are
/// silently ignored: `clap_complete`'s generator writes to a `&mut dyn
/// Write` and cannot report them, so there is nothing to propagate.
pub fn print(shell: Shell) {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "xaea", &mut io::stdout());
}
