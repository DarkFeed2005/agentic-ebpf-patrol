# Agentic eBPF Cyber Patrol System

A kernel-level Linux process-execution sensor, a high-throughput Go event
broker, and an LLM-backed threat-hunting service, wired end-to-end:

```
 ┌─────────────────────┐  bpffs-pinned   ┌──────────────────────┐  HTTPS   ┌───────────────────────┐
 │  Rust / aya-ebpf     │  ring buffer    │  Go broker           │  POST    │  Python / FastAPI      │
 │  sys_enter_execve    │ ──────────────▶ │  decode → triage →   │ ──────── │  Claude tool-use →     │
 │  tracepoint sensor   │  (kernel IPC)   │  bounded worker pool │  /v1/    │  MITRE-grounded verdict │
 └─────────────────────┘                 └──────────┬───────────┘evaluate  └───────────┬────────────┘
                                                      │  action=kill                    │ action=kill
                                                      ▼                                  ▼
                                          SIGKILL (PID-reuse-checked)     SIGKILL (PID-reuse-checked,
                                          -- broker/internal/hunter        same-namespace deployments)
                                          /respond.go                     -- hunter/responder.py
```

## Why this architecture

- **Rust ↔ Go IPC is the kernel ring buffer itself**, not a socket or RPC.
  The loader pins `EVENTS` to bpffs (`RingBuf::pinned` +
  `EbpfLoader::map_pin_path`); the broker opens that pinned map directly
  via `cilium/ebpf` and is the *sole* consumer (BPF ring buffers have one
  logical reader — the loader deliberately never drains it itself).
- **Go ↔ Rust struct layout is a hand-verified byte contract**, not FFI.
  `cyber-patrol-common::ExecEvent` is asserted at Rust compile time to be
  exactly 504 bytes with zero padding; `broker/internal/events/events.go`
  decodes those same bytes via fixed `encoding/binary` offsets. See the
  round-trip note in `cyber-patrol-common/src/lib.rs`.
- **The LLM never has unilateral kill authority.** `action=kill` verdicts
  are only honored if they *also* clear a server-side confidence floor
  (`CYBER_PATROL_KILL_CONFIDENCE_FLOOR`, default 0.85) set independently of
  anything the model claims — see `hunter/llm_engine.py`'s
  `_parse_tool_input`.
- **PID-reuse safety.** Between an exec event firing and an LLM verdict
  coming back, the original process may have exited and its PID been
  recycled. Both response paths (`broker/internal/hunter/respond.go`,
  `hunter/responder.py`, `scripts/kill_pid.sh`) re-verify `/proc/<pid>/comm`
  against what the sensor captured before signaling.
- **Backpressure never means data loss.** The Go pipeline's in-memory
  dispatch queue is bounded; when it's saturated, events spill to a
  disk-backed JSONL overflow log instead of being dropped, and are replayed
  on a timer. The *full* telemetry stream is separately, unconditionally
  written to a local audit log regardless of AI-triage outcome.

## Kernel capture trade-offs (read before extending)

- **We hook `sys_enter_execve`, not `sched_process_exec`.** Entry-side
  hooking means `comm` reflects the *calling* process (pre-image-swap);
  the new binary's `comm` isn't available until the kernel's internal
  `bprm_execve` completes. If you need the post-exec comm, additionally
  hook the `sched:sched_process_exec` tracepoint (its `filename` field
  *is* inlined via `__data_loc`, unlike `sys_enter_execve`'s raw pointer —
  a genuinely different parsing path, not a copy-paste of this one).
- **argv capture is intentionally partial** (`MAX_ARGS=6` ×
  `MAX_ARG_LEN=32` bytes). This bounds both the ring buffer entry size and
  the eBPF verifier's loop-unrolling cost. Raise these constants if you
  need full command-line reconstruction, but recompute `EVENT_SIZE` and
  update `broker/internal/events/events.go`'s offsets to match.
- **No `execveat`, `posix_spawn`, or `io_uring`-mediated exec coverage.**
  A determined adversary aware of this sensor could exec via one of those
  paths instead. Production deployments should hook
  `sys_enter_execveat` too (same parsing approach, different arg offsets)
  and consider an LSM-based (`bpf_lsm`) hook for exec authorization
  decisions rather than pure tracepoint observation.
- **No process-tree (`ppid`) capture.** Deliberately left out of the
  kernel-space struct to avoid a fragile hand-rolled `task_struct` offset
  read. To add it properly: `aya-tool generate task_struct > vmlinux.rs`
  (BTF-based CO-RE bindings), then read
  `(*bpf_get_current_task_btf().real_parent).tgid`. The Go/Python sides
  already have an untouched `EventSize`-agnostic decode path, so this is a
  contained change: bump `EVENT_SIZE`, add the field last (preserves the
  no-padding property), update three offset tables.

## Prerequisites

| Component | Requires |
|---|---|
| Sensor | Linux kernel ≥ 5.8 (ring buffer maps), BTF (`CONFIG_DEBUG_INFO_BTF=y`), `bpffs` mounted at `/sys/fs/bpf`, Rust **stable** (loader) + **nightly** w/ `rust-src` (eBPF crate), `bpf-linker` (`cargo install bpf-linker`; needs `clang`/`llvm`/`libelf-dev`/`zlib1g-dev`) |
| Broker | Go ≥ 1.23 |
| Hunter | Python ≥ 3.11, an Anthropic API key |
| All | root / `CAP_BPF`+`CAP_PERFMON` for the sensor only |

Run `./scripts/verify_caps.sh` on a new host before anything else.

## Execution plan

### 1. Build and run the sensor (needs root)

```bash
./scripts/verify_caps.sh                       # confirm BTF, bpffs, tracefs are present

cd sensor
rustup toolchain install nightly --component rust-src
cargo install bpf-linker                        # one-time; needs clang/llvm/libelf-dev/zlib1g-dev

cargo build --release -p cyber-patrol-loader     # aya-build compiles cyber-patrol-ebpf as part of this
sudo ./target/release/cyber-patrol-loader
```

You should see:
```
sensor attached to syscalls:sys_enter_execve -- EVENTS ring buffer pinned at /sys/fs/bpf/cyber_patrol/EVENTS
```

**If `aya-build`'s API doesn't match your pinned version** (it's a young,
fast-moving crate — check `cargo tree -p aya-build` if `build.rs` fails to
compile), use the `xtask` fallback instead:
```bash
cargo xtask build-ebpf --release
cargo xtask run -- --pin-dir /sys/fs/bpf/cyber_patrol
```

Leave this running in its own terminal (or install it as a systemd
service — see "Running as a daemon" below).

### 2. Build and run the broker

In a second terminal:
```bash
cd broker
go mod tidy                                      # resolves go.sum against the pinned cilium/ebpf version
go build -o bin/broker .

sudo mkdir -p /var/lib/cyber-patrol
sudo chown "$(id -u)":"$(id -g)" /var/lib/cyber-patrol

./bin/broker \
  -map-path=/sys/fs/bpf/cyber_patrol/EVENTS \
  -hunter-url=http://localhost:8000 \
  -overflow-path=/var/lib/cyber-patrol/overflow.jsonl \
  -audit-path=/var/lib/cyber-patrol/audit.jsonl
```
(Reading the pinned ring buffer map itself needs the same elevated
privilege as the sensor; run this with `sudo` too, or grant the binary
`CAP_BPF` via `sudo setcap cap_bpf+ep ./bin/broker`.)

### 3. Install and run the AI hunter

In a third terminal:
```bash
cd hunter
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export CYBER_PATROL_ANTHROPIC_API_KEY=sk-ant-...
uvicorn app:app --host 0.0.0.0 --port 8000
```

### 4. Or: run all three with Docker Compose

```bash
cp .env.example .env    # fill in ANTHROPIC_API_KEY
docker compose up --build
```
See the topology note at the top of `docker-compose.yml` for why the
`sensor` service needs `privileged: true` + `pid: host` + bpffs/tracefs
bind mounts, and why running it directly on the host is often simpler for
local development.

### 5. Generate a test detection

With all three components running, trigger a benign-but-suspicious pattern
(hidden path + `chmod +x`, one of the triage heuristics in
`broker/internal/triage/triage.go`) and watch the broker's log:

```bash
mkdir -p /tmp/.cp-demo
cp /bin/bash /tmp/.cp-demo/.hidden-tool
chmod +x /tmp/.cp-demo/.hidden-tool
/tmp/.cp-demo/.hidden-tool -c 'echo cyber-patrol demo'
```

Expected broker output:
```
verdict pid=<pid> comm="bash" cmd="/tmp/.cp-demo/.hidden-tool -c echo cyber-patrol demo" severity=... action=... technique=... confidence=...
```

Check aggregate throughput and loss accounting at any time:
```bash
curl -s localhost:9090/metrics | python3 -m json.tool
```

Clean up the demo artifact:
```bash
rm -rf /tmp/.cp-demo
```

### Running the sensor as a daemon

For anything beyond a demo session, run the loader under `systemd` rather
than a foreground terminal, so it survives logout and restarts on crash:

```ini
# /etc/systemd/system/cyber-patrol-sensor.service
[Unit]
Description=Cyber Patrol eBPF exec sensor
After=network.target

[Service]
ExecStart=/opt/cyber-patrol/cyber-patrol-loader
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

## Observability

- `GET http://localhost:9090/healthz` — broker liveness
- `GET http://localhost:9090/metrics` — JSON counters: `events_total`,
  `suspicious_total`, `queue_overflows`, `hunter_errors`, `events_lost`,
  `actions_kill`, `decode_errors`, `overflow_replays`, current queue depth
- `GET http://localhost:8000/healthz` — hunter liveness
- `GET http://localhost:8000/docs` — FastAPI's interactive OpenAPI UI

`events_lost` should be 0 in steady state; a nonzero value means the
overflow log itself failed to write (disk full/permission issue) — treat
it as a paging-worthy alert in a real deployment.

## Extending this for a portfolio write-up

Good next additions, roughly in order of effort:
1. Hook `sched_process_exit` too, so the broker can correlate a
   short-lived process's exec *and* exit code (useful signal: a payload
   that execs, does something, and exits within milliseconds).
2. Add `T1547` persistence coverage: a second tracepoint on file writes
   under `/etc/cron.d`, `~/.config/systemd/user`, etc.
3. Swap the JSONL overflow/audit logs for an embedded KV store
   (BoltDB/BadgerDB) once event volume outgrows single-file-replay
   economics — see the note atop `broker/internal/pipeline/appendlog.go`.
4. Add the `ppid` CO-RE capture described above and use it to build a
   process-ancestry chain in the LLM prompt — genealogy (e.g. "spawned by
   sshd, which was spawned by cron") is often stronger evidence than any
   single event in isolation.
