//! Fallback build orchestrator, mirroring the classic `aya-template`
//! `cargo xtask build-ebpf` / `cargo xtask run` workflow.
//!
//! `cyber-patrol-loader/build.rs` already compiles the eBPF crate
//! automatically via `aya-build` as part of a normal `cargo build`. This
//! `xtask` exists purely as a documented escape hatch: if your pinned
//! `aya-build` version's API doesn't match what `build.rs` expects (it's a
//! young crate), you can build the two halves explicitly instead:
//!
//! ```text
//! cargo xtask build-ebpf --release
//! cargo build --release -p cyber-patrol-loader
//! cargo xtask run -- --pin-dir /sys/fs/bpf/cyber_patrol
//! ```
use std::process::{Command, ExitStatus};

use anyhow::{bail, Context, Result};

#[derive(Debug)]
enum Cmd {
    BuildEbpf { release: bool },
    Run { extra_args: Vec<String> },
}

fn main() -> Result<()> {
    let cmd = parse_args()?;
    match cmd {
        Cmd::BuildEbpf { release } => build_ebpf(release),
        Cmd::Run { extra_args } => run(extra_args),
    }
}

fn parse_args() -> Result<Cmd> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build-ebpf") => Ok(Cmd::BuildEbpf {
            release: args.any(|a| a == "--release"),
        }),
        Some("run") => {
            let extra: Vec<String> = args.skip_while(|a| a != "--").skip(1).collect();
            Ok(Cmd::Run { extra_args: extra })
        }
        other => bail!(
            "usage: cargo xtask <build-ebpf [--release] | run [-- <loader args>]>, got: {:?}",
            other
        ),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["+nightly", "build", "-p", "cyber-patrol-ebpf", "-Z", "build-std=core"])
        .args(["--target", "bpfel-unknown-none"]);
    if release {
        cmd.arg("--release");
    }
    run_checked(cmd, "building cyber-patrol-ebpf")
}

fn run(extra_args: Vec<String>) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--release", "-p", "cyber-patrol-loader"]);
    run_checked(cmd, "building cyber-patrol-loader")?;

    let mut run_cmd = Command::new("sudo");
    run_cmd
        .arg("-E")
        .arg("target/release/cyber-patrol-loader")
        .args(extra_args);
    run_checked(run_cmd, "running cyber-patrol-loader (needs root for eBPF load)")
}

fn run_checked(mut cmd: Command, context: &str) -> Result<()> {
    let status: ExitStatus = cmd.status().with_context(|| format!("failed to spawn: {context}"))?;
    if !status.success() {
        bail!("{context} failed with {status}");
    }
    Ok(())
}
