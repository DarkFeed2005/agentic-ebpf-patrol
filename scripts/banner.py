#!/usr/bin/env python3
"""Rich startup banner for `make up` / scripts/run_all.sh.

Prints a styled status card with the key URLs and stop hint. Falls back to
plain text if `rich` isn't installed, so it never breaks the harness.
"""

from __future__ import annotations

import os
import urllib.request

BROKER_LOG = os.environ.get("CYBER_PATROL_BROKER_LOG", "/var/lib/cyber-patrol/broker.log")
HEALTH = {"broker": "http://localhost:9090/healthz", "hunter": "http://localhost:8000/healthz"}
SENSOR_MAP = "/sys/fs/bpf/cyber_patrol/EVENTS"


def is_up(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


def plain_fallback() -> None:
    print("== cyber-patrol is UP ==")
    print("  browser  : http://localhost:8000/docs  (hunter API)")
    print("            : http://localhost:9090/metrics (broker counters)")
    print("  dashboard: ./hunter/.venv/bin/python scripts/dashboard.py")
    print(f"  verdicts : tail -f {BROKER_LOG}")
    print("  stop     : sudo bash scripts/stop_all.sh")


def main() -> None:
    try:
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        plain_fallback()
        return

    console = Console()

    statuses = [
        ("sensor (eBPF)", os.path.exists(SENSOR_MAP)),
        ("broker (Go)", is_up(HEALTH["broker"])),
        ("hunter (Claude)", is_up(HEALTH["hunter"])),
    ]

    grid = Table.grid(padding=(0, 1))
    grid.add_column(justify="left")
    grid.add_column(justify="right")
    for name, good in statuses:
        dot = Text("\u25cf", style="green" if good else "red")
        grid.add_row(Text(f"{dot} {name}"), Text("UP" if good else "DOWN",
                                                 style="green bold" if good else "red bold"))

    body = Table.grid(padding=(0, 2))
    body.add_column(justify="left", style="bold cyan")
    body.add_column()
    body.add_row("dashboard", "./hunter/.venv/bin/python scripts/dashboard.py")
    body.add_row("hunter API", "http://localhost:8000/docs")
    body.add_row("broker metrics", "http://localhost:9090/metrics")
    body.add_row("verdict stream", f"sudo tail -f {BROKER_LOG}")
    body.add_row("stop", "sudo bash scripts/stop_all.sh")

    console.print()
    console.print(Panel(grid, title=Text(" CYBER PATROL ", style="bold white on dark_blue"),
                        border_style="bright_blue", box=box.ROUNDED))
    console.print(Panel(body, title=Text(" go to ", style="bold cyan"),
                        border_style="cyan", box=box.ROUNDED))
    console.print()


if __name__ == "__main__":
    main()