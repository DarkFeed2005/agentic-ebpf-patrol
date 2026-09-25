//! Kernel-space half of the sensor: a tracepoint program attached to
//! `syscalls:sys_enter_execve` that captures PID/UID/comm/filename/argv and
//! publishes an `ExecEvent` per invocation into a `BPF_MAP_TYPE_RINGBUF`.
//!
//! # Why a raw tracepoint over a kprobe
//! `sys_enter_execve` is a *stable* tracepoint ABI (kprobes attach to
//! function symbols, which can be renamed/inlined/removed across kernel
//! versions; tracepoints are a documented, versioned kernel interface).
//! That stability is worth the (mild) extra bookkeeping of parsing the raw
//! tracepoint argument buffer by hand.
//!
//! # Reading the tracepoint's raw arguments
//! For `sys_enter_*` tracepoints, pointer-typed syscall arguments (here:
//! `filename`, `argv`, `envp`) are recorded as **raw user-space pointers**,
//! not inlined strings -- unlike e.g. `sched_process_exec`, whose
//! `filename` field *is* inlined via the `__data_loc` mechanism. You can
//! confirm the byte layout for any host with:
//!
//! ```text
//! cat /sys/kernel/tracing/events/syscalls/sys_enter_execve/format
//! ```
//!
//! which (on every mainline x86_64/arm64 kernel we've checked) reports:
//!
//! ```text
//! field:int __syscall_nr;              offset:8;  size:4;
//! field:const char * filename;         offset:16; size:8;
//! field:const char *const * argv;      offset:24; size:8;
//! field:const char *const * envp;      offset:32; size:8;
//! ```
//!
//! We read those raw pointers out of the tracepoint context at their fixed
//! offsets, then `bpf_probe_read_user*` through them to pull the actual
//! bytes from the calling process's user-space memory.
//!
//! # Why we write directly into ring-buffer memory instead of the stack
//! `ExecEvent` is 504 bytes. The eBPF verifier caps total per-program stack
//! at `MAX_BPF_STACK` = 512 bytes -- a stack-local `ExecEvent` would alone
//! consume nearly the entire budget, leaving no room for anything else and
//! very likely tripping "invalid stack access" or "combined stack size
//! exceeded" verifier errors once inlining is accounted for. Instead we
//! `reserve()` the event directly in ring-buffer-owned memory and write
//! into it field-by-field through a raw pointer, so the struct is never
//! materialized on the BPF stack at all. This is the same technique used by
//! Falco's and Tetragon's eBPF probes for their (larger) event structs.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use cyber_patrol_common::{ExecEvent, MAX_ARGS};

/// 1 MiB ring buffer (must be a power-of-two multiple of the page size;
/// 2^20 = 256 * 4096). Sized generously so a burst of forks/execs (e.g. a
/// build system or a fork bomb -- exactly the kind of thing we want to
/// observe) doesn't overrun the buffer before the Go broker drains it.
///
/// `RingBuf::pinned` (rather than `with_byte_size`) declares this map as
/// bpffs-pinned; the loader's `EbpfLoader::map_pin_path(...)` controls
/// *where* it gets pinned (see cyber-patrol-loader/src/main.rs). Pinning is
/// the IPC bridge to the Go broker: Go never talks to this Rust program
/// directly, it opens `EVENTS` off bpffs via `cilium/ebpf` and reads the
/// same ring buffer the kernel is writing into.
#[map]
static EVENTS: RingBuf = RingBuf::pinned(1 << 20, 0);

/// Byte offset of the `filename` field within the raw
/// `syscalls:sys_enter_execve` tracepoint record (see module docs).
const FILENAME_OFFSET: usize = 16;
/// Byte offset of the `argv` field.
const ARGV_OFFSET: usize = 24;

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    match try_sys_enter_execve(ctx) {
        Ok(ret) => ret,
        // A tracing program must never fail the syscall path it observes.
        // Any error here means "we missed an event", not "deny the exec".
        Err(_) => 0,
    }
}

fn try_sys_enter_execve(ctx: TracePointContext) -> Result<u32, i64> {
    let mut entry = match EVENTS.reserve::<ExecEvent>(0) {
        Some(e) => e,
        // Consumer (the Go broker) isn't keeping up and the ring buffer is
        // full. Drop this event rather than block or spin -- back-pressure
        // and loss-accounting are handled entirely in user-space (see
        // broker/internal/pipeline: QueueOverflows / EventsLost metrics).
        None => return Ok(0),
    };

    // SAFETY: `ptr` is non-null, correctly aligned for `ExecEvent`, and
    // exclusively ours for the lifetime of `entry` -- guaranteed by the
    // ring buffer allocator's `reserve()` contract. We zero it first so
    // every field (including ones we bail out of populating early, e.g. on
    // a `read_at` failure) is left in a well-defined state before
    // `submit()` makes it visible to user-space.
    let ptr = entry.as_mut_ptr();
    unsafe { core::ptr::write_bytes(ptr, 0, 1) };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();

    // SAFETY: `ptr` valid per above; each field access below is in-bounds
    // of the zeroed `ExecEvent` allocation.
    unsafe {
        (*ptr).timestamp_ns = bpf_ktime_get_ns();
        (*ptr).pid = (pid_tgid >> 32) as u32;
        (*ptr).tid = pid_tgid as u32;
        (*ptr).uid = uid_gid as u32;
        (*ptr).gid = (uid_gid >> 32) as u32;
        if let Ok(comm) = bpf_get_current_comm() {
            (*ptr).comm = comm;
        }
    }

    let mut truncated = 0u8;

    // `ctx.read_at::<T>(offset)` reads `T` out of the tracepoint's raw
    // argument buffer -- this is NOT a user-space read (that comes next),
    // it's reading the syscall-entry record the kernel already copied into
    // the trace buffer for us.
    match unsafe { ctx.read_at::<*const u8>(FILENAME_OFFSET) } {
        Ok(filename_ptr) => {
            // SAFETY: `filename_ptr` is a user-space pointer captured from
            // the current task's own syscall arguments; `bpf_probe_read_user_str_bytes`
            // safely handles faults (e.g. the page having been unmapped
            // between syscall entry and now) by returning an error rather
            // than crashing the kernel.
            let write_result =
                unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut (*ptr).filename) };
            match write_result {
                Ok(bytes) => unsafe { (*ptr).filename_len = bytes.len() as u16 },
                Err(_) => truncated |= 1,
            }
        }
        Err(_) => truncated |= 1,
    }

    // argv is `const char *const *` -- an array of user-space pointers.
    // We walk up to MAX_ARGS entries; the loop bound is a compile-time
    // constant so the verifier can fully unroll and bound it.
    let mut argc = 0u8;
    if let Ok(argv_ptr) = unsafe { ctx.read_at::<*const *const u8>(ARGV_OFFSET) } {
        for i in 0..MAX_ARGS {
            // SAFETY: reading one pointer-sized value from the argv array
            // at a bounded offset; `bpf_probe_read_user` returns Err rather
            // than faulting on an invalid/unmapped address.
            let arg_ptr: *const u8 = match unsafe { bpf_probe_read_user(argv_ptr.add(i)) } {
                Ok(p) if !p.is_null() => p,
                _ => break, // NULL terminator (end of argv) or unreadable -- stop
            };
            let write_result =
                unsafe { bpf_probe_read_user_str_bytes(arg_ptr, &mut (*ptr).args[i]) };
            match write_result {
                Ok(bytes) => {
                    unsafe { (*ptr).arg_lens[i] = bytes.len() as u16 };
                    argc += 1;
                }
                Err(_) => {
                    truncated |= 1;
                    break;
                }
            }
        }
    }

    unsafe {
        (*ptr).argc = argc;
        (*ptr).truncated = truncated;
    }

    entry.submit(0);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
