//! User-space loader for the Cyber Patrol exec sensor.
//!
//! Responsibilities, and *only* these:
//!   1. Load the compiled `cyber-patrol-ebpf` object into the kernel.
//!   2. Attach it to `syscalls:sys_enter_execve`.
//!   3. Pin the `EVENTS` ring buffer map to bpffs so the Go broker can open
//!      it independently, in a separate process (and separate container,
//!      if deployed that way).
//!   4. Stay alive, holding the program attachment open, until terminated.
//!
//! This process deliberately does **not** read the ring buffer itself --
//! BPF ring buffers support a single logical consumer (the `consumer_pos`
//! cursor is shared map state; two independent readers would race and each
//! observe a corrupted/partial stream). The Go broker is the sole consumer;
//! see `broker/internal/ingest/ringbuf_reader.go`.
use anyhow::{Context, Result};
use aya::{programs::TracePoint, EbpfLoader};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

/// bpffs directory the EVENTS ring buffer map is pinned under. Must match
/// `-map-path` passed to the Go broker (default there appends `/EVENTS`).
const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/cyber_patrol";

#[derive(Parser, Debug)]
#[command(
    name = "cyber-patrol-loader",
    about = "Loads and attaches the Cyber Patrol sys_enter_execve sensor"
)]
struct Args {
    /// Tracepoint category.
    #[arg(long, default_value = "syscalls")]
    category: String,
    /// Tracepoint name.
    #[arg(long, default_value = "sys_enter_execve")]
    tracepoint: String,
    /// bpffs directory to pin maps under.
    #[arg(long, default_value = DEFAULT_PIN_DIR)]
    pin_dir: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    let args = Args::parse();

    bump_memlock_rlimit();

    std::fs::create_dir_all(&args.pin_dir).with_context(|| {
        format!(
            "failed to create bpffs pin directory {} -- is /sys/fs/bpf mounted? \
             (run scripts/verify_caps.sh)",
            args.pin_dir
        )
    })?;

    // The eBPF object is compiled by cyber-patrol-ebpf and embedded here at
    // build time via aya-build (see build.rs). `map_pin_path` makes any map
    // declared with `PinningType::ByName` in the kernel-space program (our
    // `EVENTS` RingBuf) get pinned under this directory on load, and
    // *reused* from there on subsequent loads instead of erroring on
    // "already exists" -- so restarting the loader doesn't orphan the map
    // or force the broker to reconnect to a new one.
    let mut ebpf = EbpfLoader::new()
        .map_pin_path(&args.pin_dir)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/cyber-patrol-ebpf"
        )))
        .context("failed to load eBPF object into the kernel")?;

    // Best-effort: surfaces any aya_log_ebpf::info!/warn! calls added to
    // the kernel-space program during development. Not required for
    // correctness of the sensor itself.
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("continuing without eBPF debug logs: {e}");
    }

    let program: &mut TracePoint = ebpf
        .program_mut("sys_enter_execve")
        .context("sys_enter_execve program not found in compiled eBPF object")?
        .try_into()
        .context("sys_enter_execve is not a tracepoint program")?;
    program
        .load()
        .context("failed to verify/load sys_enter_execve into the kernel")?;
    program
        .attach(&args.category, &args.tracepoint)
        .with_context(|| format!("failed to attach to {}:{}", args.category, args.tracepoint))?;

    info!(
        "sensor attached to {}:{} -- EVENTS ring buffer pinned at {}/EVENTS",
        args.category, args.tracepoint, args.pin_dir
    );
    info!("start the Go broker pointed at that path to begin consuming events");
    info!("press Ctrl+C to detach and exit (the pinned map persists on bpffs)");

    signal::ctrl_c().await.context("failed to await ctrl-c")?;
    info!("shutting down: eBPF programs will detach; pinned map remains until removed");
    Ok(())
}

/// Raises `RLIMIT_MEMLOCK` to unlimited. Kernels before ~5.11 charge BPF
/// map memory against this rlimit rather than the memory cgroup; on those
/// kernels map creation can fail under a tight default limit. This is a
/// defensive no-op on newer kernels.
fn bump_memlock_rlimit() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: standard, well-defined libc call with a valid, fully
    // initialized `rlimit` struct.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!(
            "failed to raise RLIMIT_MEMLOCK ({}); map creation may fail on kernels < 5.11",
            std::io::Error::last_os_error()
        );
    }
}
