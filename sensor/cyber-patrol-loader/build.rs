//! Compiles the `cyber-patrol-ebpf` crate to `bpfel-unknown-none`/`bpfeb-unknown-none`
//! bytecode as part of `cargo build` for this crate, via `aya-build`. The
//! resulting object ends up under `$OUT_DIR/cyber-patrol-ebpf`, which
//! `src/main.rs` embeds with `include_bytes_aligned!`.
//!
//! If your pinned `aya-build` version's API has drifted from this (it is a
//! young, fast-moving crate), fall back to the classic two-step workflow
//! documented at https://aya-rs.dev :
//!     cargo xtask build-ebpf --release
//!     cargo build --release -p cyber-patrol-loader
//! (the `xtask` crate in this workspace is kept as that fallback.)
use std::path::PathBuf;

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let workspace_dir = manifest_dir
        .parent()
        .expect("cyber-patrol-loader must live one level below the workspace root");

    let metadata = cargo_metadata::MetadataCommand::new()
        .current_dir(workspace_dir)
        .no_deps()
        .exec()
        .expect("`cargo metadata` failed -- is this crate part of the sensor/ workspace?");

    let ebpf_package = metadata
        .packages
        .into_iter()
        .find(|p| p.name == "cyber-patrol-ebpf")
        .expect("cyber-patrol-ebpf package not found in workspace metadata");

    aya_build::build_ebpf([ebpf_package]).expect("failed to build cyber-patrol-ebpf");
}
