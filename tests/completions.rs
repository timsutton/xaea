//! `xaea completions <SHELL>`. The script contents and the shell argument's
//! parsing belong to clap and clap_complete, so this only covers our wiring.

use std::process::Command;

#[test]
fn every_shell_generates_a_script() {
    // A generator can panic on an argument definition it can't express,
    // which only running it reveals.
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let out = Command::new(env!("CARGO_BIN_EXE_xaea"))
            .args(["completions", shell])
            .output()
            .expect("run xaea");
        assert!(
            out.status.success(),
            "{shell}: exit {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let script = String::from_utf8(out.stdout).expect("utf-8 script");
        assert!(script.contains("xaea"), "{shell}: script never names xaea");
    }
}
