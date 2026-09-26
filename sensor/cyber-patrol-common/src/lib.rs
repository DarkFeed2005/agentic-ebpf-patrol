//! Types shared between `cyber-patrol-ebpf` (kernel-space, `no_std`) and
//! `cyber-patrol-loader` (user-space, `std`).
//!
//! `ExecEvent` is the wire format written into the `EVENTS` ring buffer by
//! the kernel-space program and read back out by *both* the Rust loader
//! (for local debug logging) and, independently, the Go broker, which opens
//! the map at its pinned bpffs path (see `RingBuf::pinned` in
//! `cyber-patrol-ebpf/src/main.rs`) and decodes these bytes itself using
//! `cilium/ebpf`.
//!
//! Because the Go side has no access to Rust's `#[repr(C)]` layout rules at
//! compile time, we treat this struct's byte layout as a hand-verified ABI
//! contract rather than relying on FFI/bindgen:
//!
//!   * every field is ordered largest-alignment-first so `repr(C)` inserts
//!     **zero** padding (verified by the `LAYOUT_CHECK` const-assert below),
//!   * `broker/internal/events/events.go` decodes the same bytes via fixed
//!     `encoding/binary` offsets, documented there in lock-step with this
//!     file.
//!
//! **If you change this struct, update the offsets in
//! `broker/internal/events/events.go` and `hunter/models.py` in the same
//! commit.**
#![cfg_attr(not(feature = "user"), no_std)]

/// Linux's `TASK_COMM_LEN` (see `include/linux/sched.h`).
pub const TASK_COMM_LEN: usize = 16;

/// Truncation length for the exec'd binary's path. `PATH_MAX` is 4096 on
/// Linux, but we cap far below that to keep the ring buffer entry small and
/// bounded for the verifier; long paths are flagged via `truncated`.
pub const MAX_FILENAME_LEN: usize = 256;

/// Maximum argv entries captured per event. Bounded (rather than looping
/// until NULL) so the eBPF verifier can prove the loop terminates.
pub const MAX_ARGS: usize = 6;

/// Truncation length for each captured argv entry.
pub const MAX_ARG_LEN: usize = 32;

/// Expected `size_of::<ExecEvent>()`, asserted at compile time below and
/// relied upon by the Go broker's decoder and the Python model's docs.
pub const EVENT_SIZE: usize = 504;

/// A single `sys_enter_execve` observation, captured entirely in
/// kernel-space and handed to user-space via a `BPF_MAP_TYPE_RINGBUF`.
///
/// Field order is deliberate: `u64` (align 8) first, then all `u32`s
/// (align 4), then byte arrays / `u16`s / `u8`s, so that `repr(C)` needs no
/// inter-field padding and the struct's total size lands on an 8-byte
/// boundary without a trailing pad either. See `LAYOUT_CHECK`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    /// `bpf_ktime_get_ns()` at capture time -- nanoseconds since boot
    /// (`CLOCK_MONOTONIC`), NOT a wall-clock timestamp. Consumers anchor
    /// this to wall-clock time themselves (the Go broker does this via
    /// `/proc/uptime`; see `events.computeBootWallTime`).
    pub timestamp_ns: u64, // offset 0

    /// The thread-group ID (`tgid`) -- i.e. the PID as reported by `ps`,
    /// `/proc/<pid>`, etc.
    pub pid: u32, // offset 8
    /// The raw kernel thread ID (`current->pid`). Equal to `pid` for the
    /// (overwhelmingly common) single-threaded-at-exec-time case.
    pub tid: u32, // offset 12
    pub uid: u32, // offset 16
    pub gid: u32, // offset 20

    /// `current->comm` at the moment the syscall was entered -- i.e. the
    /// *calling* process's name, captured **before** the exec image swap
    /// takes effect (the new image's name isn't available until
    /// `sched_process_exec` fires on syscall *return*, which this sensor
    /// does not hook; see README for the trade-off).
    pub comm: [u8; TASK_COMM_LEN], // offset 24..40

    /// The path passed to `execve(2)`, read from user-space memory via
    /// `bpf_probe_read_user_str_bytes`. Truncated at `MAX_FILENAME_LEN`.
    pub filename: [u8; MAX_FILENAME_LEN], // offset 40..296
    /// Actual byte length written into `filename` (excludes the NUL).
    pub filename_len: u16, // offset 296

    /// Up to `MAX_ARGS` leading `argv` entries, each truncated at
    /// `MAX_ARG_LEN` bytes. This is intentionally partial (not full
    /// command-line reconstruction) -- see README "Kernel capture
    /// trade-offs" for why, and how to raise the ceiling safely.
    pub args: [[u8; MAX_ARG_LEN]; MAX_ARGS], // offset 298..490
    pub arg_lens: [u16; MAX_ARGS], // offset 490..502

    /// Number of `args` entries actually populated (0..=MAX_ARGS).
    pub argc: u8, // offset 502
    /// Bitfield; bit 0 set if `filename` and/or any `args` entry was
    /// truncated or could not be fully read from user memory.
    pub truncated: u8, // offset 503
}

// Compile-time layout guarantee. If this assertion ever fails (e.g. after
// adding a field), the Go and Python offset tables MUST be updated before
// merging -- grep both repos for `EVENT_SIZE` / `EventSize`.
const _LAYOUT_CHECK: () = assert!(core::mem::size_of::<ExecEvent>() == EVENT_SIZE);
