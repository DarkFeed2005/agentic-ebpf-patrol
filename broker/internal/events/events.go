// Package events decodes the raw ExecEvent wire format produced by the
// Rust eBPF sensor (cyber-patrol-common::ExecEvent) into a normalized,
// JSON-friendly Go struct.
//
// We deliberately do NOT decode via a Go struct + binary.Read/unsafe cast.
// Go and Rust have no shared ABI, and binary.Read's struct-field-order
// decoding is fragile against alignment/padding differences between the
// two languages' compilers. Instead we treat the byte layout as an
// explicit, hand-verified contract: fixed offsets, read with
// encoding/binary calls. This is slightly more verbose and considerably
// more robust -- there is no layout to accidentally get out of sync via a
// compiler version bump on either side.
//
// If cyber-patrol-common::ExecEvent changes, update the offset constants
// below AND hunter/models.py in the same commit. The Rust side asserts
// size_of::<ExecEvent>() == EVENT_SIZE at compile time; EventSize here
// must match that constant.
package events

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Layout constants -- must mirror cyber-patrol-common/src/lib.rs exactly.
const (
	TaskCommLen = 16
	MaxFilename = 256
	MaxArgs     = 6
	MaxArgLen   = 32

	// EventSize is the full, unpadded size of ExecEvent as asserted by
	// Rust's `const _LAYOUT_CHECK`. Any raw record shorter than this is
	// rejected as corrupt/truncated rather than partially decoded.
	EventSize = 504

	offTimestamp  = 0   // u64
	offPID        = 8   // u32
	offTID        = 12  // u32
	offUID        = 16  // u32
	offGID        = 20  // u32
	offComm       = 24  // [16]u8
	offFilename   = 40  // [256]u8
	offFilenameLn = 296 // u16
	offArgs       = 298 // [6][32]u8
	offArgLens    = 490 // [6]u16
	offArgc       = 502 // u8
	offTruncated  = 503 // u8
)

// Event is the normalized representation forwarded to the AI hunter and
// written to the local audit log. JSON field names here are the contract
// with hunter/models.py's ExecEvent -- keep them in sync.
type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	PID         uint32    `json:"pid"`
	TID         uint32    `json:"tid"`
	UID         uint32    `json:"uid"`
	GID         uint32    `json:"gid"`
	Comm        string    `json:"comm"`
	Filename    string    `json:"filename"`
	Args        []string  `json:"args"`
	Argc        uint8     `json:"argc"`
	Truncated   bool      `json:"truncated"`
	CommandLine string    `json:"command_line"`
}

// procBootWall anchors bpf_ktime_get_ns() (nanoseconds since boot,
// CLOCK_MONOTONIC) to wall-clock time, computed once at process start from
// /proc/uptime. Good to well under a second of accuracy, which is more
// than sufficient for security-alert ordering and display.
var (
	procBootWallOnce sync.Once
	procBootWall     time.Time
)

func bootWallTime() time.Time {
	procBootWallOnce.Do(func() {
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			log.Printf("events: could not read /proc/uptime (%v); event timestamps will be approximate", err)
			procBootWall = time.Now()
			return
		}
		fields := strings.Fields(string(data))
		if len(fields) == 0 {
			procBootWall = time.Now()
			return
		}
		uptimeSeconds, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			procBootWall = time.Now()
			return
		}
		procBootWall = time.Now().Add(-time.Duration(uptimeSeconds * float64(time.Second)))
	})
	return procBootWall
}

// Decode parses a raw ring buffer record into an Event. Returns an error
// (never a panic) for any malformed input -- this function processes bytes
// written by kernel-space code we trust, but "trust, then verify" costs
// nothing here and turns a would-be crash-the-broker bug into a metric.
func Decode(raw []byte) (Event, error) {
	if len(raw) < EventSize {
		return Event{}, fmt.Errorf("short ring buffer record: got %d bytes, want >= %d", len(raw), EventSize)
	}

	bootNS := binary.LittleEndian.Uint64(raw[offTimestamp : offTimestamp+8])

	ev := Event{
		Timestamp: bootWallTime().Add(time.Duration(bootNS)),
		PID:       binary.LittleEndian.Uint32(raw[offPID : offPID+4]),
		TID:       binary.LittleEndian.Uint32(raw[offTID : offTID+4]),
		UID:       binary.LittleEndian.Uint32(raw[offUID : offUID+4]),
		GID:       binary.LittleEndian.Uint32(raw[offGID : offGID+4]),
		Comm:      cString(raw[offComm : offComm+TaskCommLen]),
	}

	fnLen := int(binary.LittleEndian.Uint16(raw[offFilenameLn : offFilenameLn+2]))
	ev.Filename = cStringN(raw[offFilename:offFilename+MaxFilename], fnLen)

	argc := int(raw[offArgc])
	if argc > MaxArgs {
		argc = MaxArgs // defensive: never trust a count past its bound
	}
	ev.Argc = uint8(argc)
	ev.Args = make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		start := offArgs + i*MaxArgLen
		argLen := int(binary.LittleEndian.Uint16(raw[offArgLens+i*2 : offArgLens+i*2+2]))
		ev.Args = append(ev.Args, cStringN(raw[start:start+MaxArgLen], argLen))
	}

	ev.Truncated = raw[offTruncated] != 0
	ev.CommandLine = strings.TrimSpace(strings.Join(append([]string{ev.Filename}, ev.Args...), " "))

	return ev, nil
}

// cString returns the NUL-terminated prefix of b as a string.
func cString(b []byte) string {
	if i := indexZero(b); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// cStringN is cString bounded to at most n bytes of b (n is the
// kernel-reported byte length for this field; used as a sanity cap so a
// corrupt length field can't read past the field's own buffer).
func cStringN(b []byte, n int) string {
	if n < 0 || n > len(b) {
		n = len(b)
	}
	return cString(b[:n])
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
