#!/usr/bin/env python3
"""Live terminal dashboard for the Cyber Patrol stack (rich TUI).

Run with: ./hunter/.venv/bin/python scripts/dashboard.py   (or `make dash`)

Shows, in a single refreshing screen:
  - service health (sensor / broker / hunter)
  - broker counters (+ queue utilization bar)
  - the newest threat verdicts, color-coded by severity/action

Everything it needs is read over HTTP (localhost:9090, localhost:8000) and
from the broker's log file, so the dashboard itself is read-only.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

BROKER_LOG = os.environ.get("CYBER_PATROL_BROKER_LOG", "/var/lib/cyber-patrol/broker.log")
METRICS_URL = "http://localhost:9090/metrics"
HEALTH = {"broker": "http://localhost:9090/healthz", "hunter": "http://localhost:8000/healthz"}
SENSOR_MAP = "/sys/fs/bpf/cyber_patrol/EVENTS"
REFRESH_SECS = 1.5
MAX_ROWS = 24

VERDICT_RE = re.compile(
    r'verdict\s+pid=(\d+)\s+comm="([^"]*)"\s+cmd="([^"]*)"\s+'
    r"severity=(\S+)\s+action=(\S+)\s+technique=(\S+)\s+confidence=([\d.]+)"
)

SEV_STYLE = {
    "benign": "green",
    "low": "green",
    "medium": "yellow",
    "high": "bright_magenta",
    "critical": "red",
}
ACTION_STYLE = {
    "kill": "white on red",
    "alert": "yellow",
    "monitor": "bright_cyan",
    "ignore": "dim",
}


def fetch_json(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def is_up(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def queued_bar(depth: int, capacity: int) -> Text:
    frac = min(1.0, depth / max(capacity, 1))
    width = 12
    filled = round(frac * width)
    style = "green" if frac < 0.7 else ("yellow" if frac < 0.9 else "red")
    bar = Text("\u2588" * filled + "\u2591" * (width - filled), style=style)
    bar.append(Text(f" {depth}/{capacity} ({frac*100:.1f}%)", style=style))
    return bar


def services_panel() -> Panel:
    services = [
        ("sensor (eBPF)", os.path.exists(SENSOR_MAP)),
        ("broker (Go)", is_up(HEALTH["broker"])),
        ("hunter (Claude)", is_up(HEALTH["hunter"])),
    ]
    grid = Table.grid(padding=(0, 1))
    grid.add_column(justify="left")
    grid.add_column(justify="right")
    for name, good in services:
        dot = Text("\u25cf", style="green" if good else "red")
        status = Text("UP" if good else "DOWN", style="green bold" if good else "red bold")
        grid.add_row(Text(f"{dot} {name}"), status)
    return Panel(
        grid,
        title=Text(" SERVICES ", style="bold cyan"),
        border_style="cyan",
        box=box.ROUNDED,
    )


def metrics_panel() -> Panel:
    m = fetch_json(METRICS_URL)
    if m is None:
        return Panel(
            Text("broker unreachable \u2014 is it running?", style="red"),
            title=Text(" METRICS ", style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        )
    capacity = int(m.get("queue_capacity", 4096))
    depth = int(m.get("queue_depth", 0))
    grid = Table.grid(padding=(0, 1))
    grid.add_column(justify="left", style="dim")
    grid.add_column(justify="right")

    def row(label: str, value: str) -> None:
        grid.add_row(label, Text(value, style="bold"))

    def row_num(label: str, key: str, color: str = "white") -> None:
        grid.add_row(label, Text(str(m.get(key, 0)), style=f"bold {color}"))

    row_num("events_total", "events_total", "bright_cyan")
    row_num("suspicious_total", "suspicious_total", "yellow")
    row_num("actions_kill", "actions_kill", "red")
    row_num("hunter_errors", "hunter_errors", "bright_magenta")
    row_num("decode_errors", "decode_errors", "bright_magenta")
    row_num("events_lost", "events_lost", "red")
    row_num("overflow_replays", "overflow_replays", "green")
    row_num("queue_overflows", "queue_overflows", "red")
    grid.add_row("queue depth", queued_bar(depth, capacity))
    return Panel(
        grid,
        title=Text(" BROKER METRICS ", style="bold cyan"),
        border_style="cyan",
        box=box.ROUNDED,
    )


def verdict_rows() -> list[tuple[str, ...]]:
    try:
        with open(BROKER_LOG, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []
    found = []
    for line in lines:
        m = VERDICT_RE.search(line)
        if m:
            found.append(m.groups())
    return found[-MAX_ROWS:]


def trimmed(s: str, limit: int) -> str:
    return s if len(s) <= limit else s[: limit - 1] + "\u2026"


def verdict_panel() -> Panel:
    rows = verdict_rows()
    if not rows:
        return Panel(
            Text("no verdicts yet \u2014 trigger some exec activity", style="dim"),
            title=Text(" VERDICT STREAM ", style="bold cyan"),
            border_style="cyan",
            box=box.ROUNDED,
        )
    table = Table(box=box.SIMPLE, expand=True, padding=(0, 1), show_edge=False)
    table.add_column("pid", justify="right", style="dim", no_wrap=True)
    table.add_column("comm", style="bold", no_wrap=True)
    table.add_column("severity", justify="center")
    table.add_column("action", justify="center")
    table.add_column("technique", justify="center")
    table.add_column("conf", justify="right")
    table.add_column("command", style="dim")
    for pid, comm, cmd, sev, act, tech, conf in rows:
        sev_text = Text(sev.upper(), style=SEV_STYLE.get(sev, "white"))
        act_text = Text(act.upper(), style=ACTION_STYLE.get(act, "white"))
        table.add_row(
            pid,
            comm,
            sev_text,
            act_text,
            tech,
            conf,
            trimmed(cmd, 42),
        )
    return Panel(
        table,
        title=Text(" VERDICT STREAM ", style="bold cyan"),
        border_style="cyan",
        box=box.ROUNDED,
    )


def header() -> Panel:
    title = Text(" CYBER PATROL ", style="bold white on dark_blue")
    sub = Text(" kernel exec sensor \u25cf Go broker \u25cf Claude threat hunter ")
    return Panel(
        Group(title, sub),
        border_style="bright_blue",
        box=box.HEAVY_EDGE,
    )


def footer(log_path: str) -> Panel:
    text = Text(
        f" broker.log: {log_path}   |   refresh {REFRESH_SECS:.1f}s   |   Ctrl+C to quit ",
        style="dim",
    )
    return Panel(text, box=box.SQUARE)


def build() -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(header(), name="header", size=4),
        Layout(name="body"),
        Layout(footer(BROKER_LOG), name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(services_panel(), name="left", ratio=1),
        Layout(metrics_panel(), name="mid", ratio=2),
        Layout(verdict_panel(), name="right", ratio=3),
    )
    return layout


def main() -> None:
    console = Console()
    if "--once" in sys.argv:
        console.print(build())
        return
    with Live(build(), console=console, refresh_per_second=2, screen=False) as live:
        try:
            while True:
                live.update(build(), refresh=True)
                time.sleep(REFRESH_SECS)
        except KeyboardInterrupt:
            console.print("\n[cornflower_blue]dashboard stopped. cyber-patrol keeps running.[/]")
            console.print(
                "[dim]re-attach anytime: ./hunter/.venv/bin/python scripts/dashboard.py[/]"
            )


if __name__ == "__main__":
    main()