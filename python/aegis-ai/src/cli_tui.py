"""
AEGIS CLI Terminal UI  –  v2.0
================================
Cyberpunk-themed interactive TUI with live file monitoring and policy CRUD.

Usage:
    python -m src.cli_tui              # Full live mode (WebSocket + backend)
    python -m src.cli_tui --demo       # Demo mode (no backend needed)
    python -m src.cli_tui --scan       # One-shot orchestration scan and exit

Key bindings (interactive mode):
    S          Fire a demo orchestration scan
    F          Switch to File Monitor panel
    P          Switch to Policy Manager panel
    T          Switch to Telemetry panel (default)
    A <path>   Allow a file path (in File Monitor panel)
    B <path>   Block a file path (in File Monitor panel)
    +          Add new policy (in Policy panel)
    D <id>     Delete policy by ID (in Policy panel)
    Q / Ctrl-C Quit
"""

import argparse
import asyncio
import json
import time
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Literal

import httpx
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt
from rich import box

BACKEND = "http://127.0.0.1:8000"
WS_URL  = "ws://127.0.0.1:8000/ws/telemetry"

console = Console()

# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class FileEvent:
    path:        str
    agent:       str
    access_type: str          # read | write | exec | delete | network
    status:      str          # allowed | blocked | pending
    ts:          str = field(default_factory=lambda: time.strftime("%H:%M:%S"))

@dataclass
class Policy:
    id:          str
    name:        str
    description: str
    tier:        int
    severity:    str          # critical | high | medium | low
    enabled:     bool = True
    triggers:    int  = 0

# ─── Demo seed data ───────────────────────────────────────────────────────────

DEMO_FILES: list[FileEvent] = [
    FileEvent("src/orchestrator/router.py",        "aegis-core",   "read",    "allowed"),
    FileEvent(".git/hooks/pre-commit",              "git-hook",     "exec",    "blocked"),
    FileEvent("tools/sync.ts",                      "mcp-client",   "network", "blocked"),
    FileEvent("python/aegis-ai/.env",               "llm-provider", "read",    "blocked"),
    FileEvent("src/os/kernel.py",                   "aegis-core",   "read",    "allowed"),
    FileEvent("dashboard/dist/index.html",          "dev-server",   "read",    "allowed"),
    FileEvent("/etc/passwd",                        "unknown",      "read",    "blocked"),
    FileEvent("src/telemetry.py",                   "aegis-core",   "write",   "allowed"),
    FileEvent("memory/session_handoff/current.md",  "aegis-core",   "write",   "pending"),
]

DEMO_POLICIES: list[Policy] = [
    Policy("p1", "Hostile-by-Default",      "All requests denied unless explicitly approved.", 0, "critical", True,  142),
    Policy("p2", "ProcessSpawn Block",      "Child-process spawns require human review.",      2, "critical", True,  7),
    Policy("p3", "NetworkAccess Restrict",  "Outbound calls blocked without capability.",      2, "high",     True,  23),
    Policy("p4", "Git Hook Block",          "git lifecycle hooks treated as untrusted.",       1, "critical", True,  4),
    Policy("p5", "MCP Sandbox Isolation",   "MCP tools routed through gVisor kernel.",         3, "high",     True,  18),
    Policy("p6", "Secret Access Intercept", "Credential access is intercepted & audited.",     1, "high",     True,  2),
    Policy("p7", "Latency Hard Limit",      "Responses >2 s trigger performance alert.",       3, "medium",   True,  0),
    Policy("p8", "AST Deterministic Parse", "All agent code parsed via AST before exec.",      1, "medium",   True,  89),
]

DEMO_TELEMETRY = [
    ("SandboxExecution",    "cmd=['python','-c','print(1)']",           "Clean"),
    ("OrchestrationRouted", "caps=['FilesystemRead']  approved=True",   "Allowed"),
    ("ThreatIntelLookup",   "hash=abc123  vt_score=0/72",              "Clean"),
    ("PolicyEnforced",      "NetworkAccess denied for sync.ts",         "Blocked"),
    ("MemoryPaged",         "LTM compressed 128 tokens → vector store", "OK"),
    ("SandboxExecution",    "cmd=['curl','evil.sh']  BLOCKED",          "Blocked"),
    ("OrchestrationRouted", "caps=['ProcessSpawn']  escalation=True",   "Blocked"),
]

# ─── Colour helpers ───────────────────────────────────────────────────────────

SEV_STYLE = {"critical": "bold red", "high": "yellow", "medium": "cyan", "low": "green"}
ACC_STYLE = {"read": "green", "write": "yellow", "exec": "red", "delete": "red", "network": "cyan"}
STA_STYLE = {"allowed": "green", "blocked": "red", "pending": "yellow", "OK": "green",
             "Clean": "green", "Allowed": "green", "Blocked": "red", "Error": "red",
             "Warn": "yellow", "Pending": "yellow"}

def sts(val: str) -> Text:
    return Text(val, style=STA_STYLE.get(val, "white"))

def status_badge(ok: bool) -> Text:
    return Text("● ONLINE", style="bold green") if ok else Text("● OFFLINE", style="bold red")

# ─── Layout builders ──────────────────────────────────────────────────────────

def _header(health: dict, panel: str) -> Panel:
    t = Text()
    t.append("╔══ AEGIS COMMAND CENTER ══╗\n", style="bold bright_green")
    t.append("  Status: ", style="dim")
    t.append_text(status_badge(health.get("ok", False)))
    t.append(f"   Tier: {health.get('tier','—')}  Component: {health.get('component','—')}", style="dim cyan")
    t.append(f"   Panel: [{panel}]", style="dim magenta")
    return Panel(t, style="bright_green")

def _footer_telemetry() -> Panel:
    return Panel(
        Text("  [S] Scan    [F] Files    [P] Policies    [T] Telemetry    [H] Help    [Q] Quit", style="dim yellow"),
        style="bright_black",
    )

def _footer_files() -> Panel:
    return Panel(
        Text("  [A <path>] Allow    [B <path>] Block    [T] Telemetry    [P] Policies    [H] Help    [Q] Quit", style="dim yellow"),
        style="bright_black",
    )

def _footer_policies() -> Panel:
    return Panel(
        Text("  [+] Add    [D <id>] Delete    [E <id>] Enable/Disable    [T] Telemetry    [H] Help    [Q] Quit", style="dim yellow"),
        style="bright_black",
    )

def build_help_layout(health: dict) -> Layout:
    """Full in-TUI help panel — rendered when user presses H or ?."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["header"].update(_header(health, "HELP"))

    table = Table(
        show_header=True, header_style="bold magenta",
        box=box.SIMPLE_HEAVY, expand=True,
        title="[bold bright_green]AEGIS CLI — Interactive Command Reference[/bold bright_green]",
    )
    table.add_column("Command",     style="bold cyan",   width=22)
    table.add_column("Panel",       style="dim magenta", width=12)
    table.add_column("Description", style="white",       ratio=1)
    table.add_column("Example",     style="dim green",   width=28)

    rows = [
        # ── Navigation ──────────────────────────────────────────────────────
        ("H  or  ?",    "any",      "Show this help screen",                       "H"),
        ("T",           "any",      "Switch to Telemetry panel",                    "T"),
        ("F",           "any",      "Switch to File Monitor panel",                 "F"),
        ("P",           "any",      "Switch to Policy Manager panel",               "P"),
        ("Q",           "any",      "Quit the TUI",                                "Q"),
        # ── Scanning ────────────────────────────────────────────────────────
        ("S",           "any",      "Fire a demo orchestration capability scan",    "S"),
        # ── File Monitor ────────────────────────────────────────────────────
        ("A <path>",    "Files",    "Allow file access (path substring match)",     "A .git/hooks"),
        ("B <path>",    "Files",    "Block file access (path substring match)",     "B /etc/passwd"),
        # ── Policy Manager ──────────────────────────────────────────────────
        ("+",           "Policies", "Add a new policy (guided prompts)",           "+"),
        ("D <id>",      "Policies", "Delete policy by ID",                         "D p3"),
        ("E <id>",      "Policies", "Toggle policy enabled / disabled",             "E p2"),
    ]

    section = ""
    for cmd, panel, desc, example in rows:
        # Print a divider row when the section changes
        if panel != section:
            section = panel
            label = {"any": "── Navigation & Global", "Files": "── File Monitor",
                     "Policies": "── Policy Manager"}.get(panel, panel)
            table.add_row("", "", f"[bold dim]{label}[/bold dim]", "")
        table.add_row(cmd, panel, desc, example)

    tips = Text()
    tips.append("\n  Tips:\n", style="bold bright_green")
    tips.append("  • Commands are case-insensitive.\n", style="dim")
    tips.append("  • In File Monitor: path matching is a substring search — 'passwd' matches '/etc/passwd'.\n", style="dim")
    tips.append("  • Policy IDs are shown in the Policy Manager panel (p1, p2 … pN).\n", style="dim")
    tips.append("  • Press Enter alone to refresh the display without executing any command.\n", style="dim")
    tips.append("  • Run with --demo flag (no backend) for offline testing.\n", style="dim")

    from rich.console import Group  # local import to avoid top-level cycle
    layout["body"].update(Panel(Group(table, tips), title="[bold]Help[/bold]", style="bright_black"))
    layout["footer"].update(Panel(
        Text("  Press any navigation key to leave help: T=Telemetry  F=Files  P=Policies  Q=Quit", style="dim yellow"),
        style="bright_black",
    ))
    return layout


def build_telemetry_layout(logs: list[dict], health: dict) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["header"].update(_header(health, "TELEMETRY"))


    table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Time",   style="dim",       width=10)
    table.add_column("Event",  style="bold cyan",  width=28)
    table.add_column("Detail", style="white",      ratio=1)
    table.add_column("Status", style="bold",       width=12)
    for entry in reversed(logs[-20:]):
        table.add_row(
            entry.get("ts", "—"), entry.get("type", "—"),
            entry.get("detail", ""), sts(entry.get("status", "OK")),
        )
    layout["body"].update(Panel(table, title="[bold]Live Telemetry Stream[/bold]", style="bright_black"))
    layout["footer"].update(_footer_telemetry())
    return layout

def build_file_layout(files: list[FileEvent], health: dict) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["header"].update(_header(health, "FILE MONITOR"))

    table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Time",    style="dim",  width=10)
    table.add_column("Path",    style="white", ratio=1)
    table.add_column("Agent",   style="cyan",  width=16)
    table.add_column("Access",  style="bold",  width=10)
    table.add_column("Status",  style="bold",  width=10)

    for f in reversed(files[-25:]):
        acc_text = Text(f.access_type, style=ACC_STYLE.get(f.access_type, "white"))
        layout["body"]  # forward ref; set below
        table.add_row(f.ts, f.path[-55:] if len(f.path) > 55 else f.path,
                      f.agent, acc_text, sts(f.status))

    counts = (
        f"[green]{sum(1 for f in files if f.status=='allowed')} allowed[/green]  "
        f"[red]{sum(1 for f in files if f.status=='blocked')} blocked[/red]  "
        f"[yellow]{sum(1 for f in files if f.status=='pending')} pending[/yellow]  "
        f"[dim]{len(files)} total[/dim]"
    )
    layout["body"].update(Panel(
        table,
        title=f"[bold]File Access Monitor[/bold]  {counts}",
        style="bright_black",
    ))
    layout["footer"].update(_footer_files())
    return layout

def build_policy_layout(policies: list[Policy], health: dict) -> Layout:
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["header"].update(_header(health, "POLICY MANAGER"))

    table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("ID",       style="dim",        width=5)
    table.add_column("Name",     style="bold white",  ratio=1)
    table.add_column("Severity", style="bold",        width=10)
    table.add_column("Tier",     style="dim cyan",    width=6)
    table.add_column("Triggers", style="dim",         width=10)
    table.add_column("State",    style="bold",        width=10)

    for p in policies:
        state = Text("● ON",  style="green") if p.enabled else Text("○ OFF", style="dim")
        sev   = Text(p.severity.upper(), style=SEV_STYLE.get(p.severity, "white"))
        table.add_row(p.id, p.name, sev, str(p.tier), str(p.triggers), state)

    active = sum(1 for p in policies if p.enabled)
    layout["body"].update(Panel(
        table,
        title=f"[bold]Policy Registry[/bold]  [dim]{active}/{len(policies)} active[/dim]",
        style="bright_black",
    ))
    layout["footer"].update(_footer_policies())
    return layout

# ─── Core TUI ─────────────────────────────────────────────────────────────────

class AegisTUI:
    def __init__(self, demo: bool = False):
        self.logs:     list[dict]     = []
        self.files:    list[FileEvent]= list(DEMO_FILES)
        self.policies: list[Policy]   = list(DEMO_POLICIES)
        self.health:   dict           = {"ok": False, "tier": "—", "component": "—"}
        self.demo      = demo
        self.panel     = "telemetry"   # telemetry | files | policy
        self._running  = True
        self._next_pid = f"p{len(DEMO_POLICIES)+1}"

    # ── helpers ──────────────────────────────────────────────────────────────
    def _add(self, etype: str, detail: str, status: str = "OK"):
        self.logs.append({"ts": time.strftime("%H:%M:%S"), "type": etype,
                          "detail": detail, "status": status})

    def _current_layout(self) -> Layout:
        if self.panel == "files":
            return build_file_layout(self.files, self.health)
        if self.panel == "policy":
            return build_policy_layout(self.policies, self.health)
        if self.panel == "help":
            return build_help_layout(self.health)
        return build_telemetry_layout(self.logs, self.health)

    # ── file monitor controls ─────────────────────────────────────────────────
    def allow_file(self, path: str):
        for f in self.files:
            if path.lower() in f.path.lower():
                f.status = "allowed"
                self._add("FileAllowed", f.path, "Allowed")
                return
        self._add("FileAllow:NotFound", path, "Warn")

    def block_file(self, path: str):
        for f in self.files:
            if path.lower() in f.path.lower():
                f.status = "blocked"
                self._add("FileBlocked", f.path, "Blocked")
                return
        self._add("FileBlock:NotFound", path, "Warn")

    # ── policy CRUD ──────────────────────────────────────────────────────────
    def add_policy(self, name: str, desc: str, severity: str, tier: int):
        pid = self._next_pid
        self._next_pid = f"p{int(pid[1:]) + 1}"
        self.policies.append(Policy(pid, name, desc, tier, severity))
        self._add("PolicyAdded", f"id={pid}  name={name}", "OK")

    def delete_policy(self, pid: str):
        before = len(self.policies)
        self.policies = [p for p in self.policies if p.id != pid]
        if len(self.policies) < before:
            self._add("PolicyDeleted", f"id={pid}", "OK")
        else:
            self._add("PolicyDelete:NotFound", f"id={pid}", "Warn")

    def toggle_policy(self, pid: str):
        for p in self.policies:
            if p.id == pid:
                p.enabled = not p.enabled
                state = "enabled" if p.enabled else "disabled"
                self._add("PolicyToggled", f"id={pid}  {state}", "OK")
                return
        self._add("PolicyToggle:NotFound", f"id={pid}", "Warn")

    # ── health & scan ────────────────────────────────────────────────────────
    async def _refresh_health(self):
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                r = await client.get(f"{BACKEND}/health")
                if r.status_code == 200:
                    self.health = {"ok": True, **r.json()}
                    return
        except Exception:
            pass
        self.health = {"ok": False, "tier": "—", "component": "—"}

    async def demo_scan(self):
        payload = {
            "session_id":             f"cli_scan_{int(time.time())}",
            "context_payload":        {"source": "cli_tui", "target": "demo_repo"},
            "requested_capabilities": ["FilesystemRead", "NetworkAccess"],
        }
        self._add("ScanStarted", f"session={payload['session_id']}", "Pending")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r    = await client.post(f"{BACKEND}/orchestrate/route", json=payload)
                data = r.json()
                approved = data.get("approved", False)
                self._add("OrchestrationResult",
                          f"approved={approved}  escalation={data.get('escalation_required')}",
                          "Allowed" if approved else "Blocked")
        except Exception as exc:
            self._add("ScanError", str(exc), "Error")

    # ── demo loops ───────────────────────────────────────────────────────────
    async def _demo_telemetry_loop(self, live: Live):
        idx = 0
        while self._running:
            await asyncio.sleep(1.8)
            etype, detail, status = DEMO_TELEMETRY[idx % len(DEMO_TELEMETRY)]
            self._add(etype, detail, status)
            idx += 1
            live.update(self._current_layout())

    async def _demo_file_loop(self, live: Live):
        live_files = [
            FileEvent("src/llm/provider.py",           "llm-provider", "read",    "allowed"),
            FileEvent("/tmp/aegis_sandbox_xyz",         "sandbox",      "write",   "allowed"),
            FileEvent("secrets/api_keys.json",          "unknown",      "read",    "blocked"),
            FileEvent("src/orchestrator/governance.py", "aegis-core",   "read",    "allowed"),
            FileEvent("/bin/bash",                      "unknown",      "exec",    "blocked"),
        ]
        idx = 0
        while self._running:
            await asyncio.sleep(3.5)
            base = live_files[idx % len(live_files)]
            self.files.insert(0, FileEvent(base.path, base.agent, base.access_type, base.status))
            self.files = self.files[:200]
            idx += 1
            live.update(self._current_layout())

    # ── real WS loop ─────────────────────────────────────────────────────────
    async def _ws_loop(self, live: Live):
        try:
            import websockets  # type: ignore
            async with websockets.connect(WS_URL) as ws:
                self._add("WS", f"Connected to {WS_URL}", "OK")
                async for raw in ws:
                    try:
                        payload = json.loads(raw)
                        self._add(payload.get("event", "Unknown"),
                                  json.dumps(payload.get("data", {}))[:80], "OK")
                        # Auto-feed file events from WS
                        d = payload.get("data", {})
                        if "path" in d:
                            self.files.insert(0, FileEvent(
                                d["path"], d.get("agent", "ws-event"),
                                d.get("access_type", "read"), "pending",
                            ))
                            self.files = self.files[:200]
                    except Exception:
                        self._add("WS:ParseError", str(raw)[:80], "Error")
                    live.update(self._current_layout())
        except Exception as exc:
            self._add("WS:Unavailable", str(exc)[:80], "Warn")
            self._add("Fallback", "Switching to demo simulation", "OK")
            await asyncio.gather(
                self._demo_telemetry_loop(live),
                self._demo_file_loop(live),
            )

    async def _health_loop(self, live: Live):
        while self._running:
            await self._refresh_health()
            live.update(self._current_layout())
            await asyncio.sleep(5)

    # ── command input loop ───────────────────────────────────────────────────
    async def _input_loop(self, live: Live):
        """Non-blocking key reader. Reads a line from stdin asynchronously."""
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)
                cmd  = line.strip()
                if not cmd:
                    continue

                upper = cmd.upper()
                if upper in ("Q",):
                    self._running = False
                    break
                elif upper in ("H", "?"):
                    self.panel = "help"
                elif upper == "T":
                    self.panel = "telemetry"
                elif upper == "F":
                    self.panel = "files"
                elif upper == "P":
                    self.panel = "policy"
                elif upper == "S":
                    asyncio.create_task(self.demo_scan())
                elif upper.startswith("A "):
                    self.allow_file(cmd[2:].strip())
                    self.panel = "files"
                elif upper.startswith("B "):
                    self.block_file(cmd[2:].strip())
                    self.panel = "files"
                elif upper == "+":
                    # Prompt for new policy (runs synchronously via executor)
                    name = (await loop.run_in_executor(None, lambda: input("Policy name: "))).strip()
                    desc = (await loop.run_in_executor(None, lambda: input("Description: "))).strip()
                    sev  = (await loop.run_in_executor(None, lambda: input("Severity (critical/high/medium/low): "))).strip() or "medium"
                    tier = int((await loop.run_in_executor(None, lambda: input("Tier (0-3): "))).strip() or "1")
                    self.add_policy(name, desc, sev, tier)
                    self.panel = "policy"
                elif upper.startswith("D "):
                    self.delete_policy(cmd[2:].strip())
                    self.panel = "policy"
                elif upper.startswith("E "):
                    self.toggle_policy(cmd[2:].strip())
                    self.panel = "policy"
                else:
                    self._add("UnknownCmd", cmd, "Warn")

                live.update(self._current_layout())
            except Exception as exc:
                self._add("InputError", str(exc), "Error")

    # ── main entry ───────────────────────────────────────────────────────────
    async def run(self):
        if not self.demo:
            await self._refresh_health()

        self._add("AEGIS", "Terminal UI v2.0 initialised", "OK")
        self._add("AEGIS", "Commands: T=Telemetry  F=Files  P=Policies  S=Scan  Q=Quit", "OK")
        self._add("AEGIS", "File cmds: A <path>=Allow  B <path>=Block", "OK")
        self._add("AEGIS", "Policy cmds: +=Add  D <id>=Delete  E <id>=Toggle", "OK")

        with Live(self._current_layout(), refresh_per_second=4, screen=True) as live:
            tasks = [
                asyncio.create_task(self._health_loop(live)),
                asyncio.create_task(self._input_loop(live)),
            ]
            if self.demo:
                tasks.append(asyncio.create_task(self._demo_telemetry_loop(live)))
                tasks.append(asyncio.create_task(self._demo_file_loop(live)))
            else:
                tasks.append(asyncio.create_task(self._ws_loop(live)))

            try:
                await asyncio.gather(*tasks)
            except asyncio.CancelledError:
                pass
            finally:
                self._running = False
                for t in tasks:
                    t.cancel()


# ─── One-shot scan ────────────────────────────────────────────────────────────

async def _scan_only():
    console.rule("[bold green]AEGIS Demo Scan[/bold green]")
    payload = {
        "session_id":             f"cli_scan_{int(time.time())}",
        "context_payload":        {"source": "cli", "target": "test_repo"},
        "requested_capabilities": ["FilesystemRead", "NetworkAccess"],
    }
    console.print(f"[dim]POST {BACKEND}/orchestrate/route[/dim]")
    console.print_json(json.dumps(payload))
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(f"{BACKEND}/orchestrate/route", json=payload)
        console.print(f"\n[bold]HTTP {r.status_code}[/bold]")
        console.print_json(r.text)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")


# ─── CLI entry-point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AEGIS CLI TUI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Interactive commands (type then press Enter):
              H / ?      -> Show this help screen inside the TUI
              T          -> Telemetry panel
              F          -> File Monitor panel
              P          -> Policy Manager panel
              S          -> Fire demo orchestration scan
              A <path>   -> Allow file access by path substring
              B <path>   -> Block file access by path substring
              +          -> Add new policy (interactive prompts)
              D <id>     -> Delete policy by ID  (e.g.  D p3)
              E <id>     -> Enable/disable policy toggle
              Q          -> Quit
        """),
    )
    parser.add_argument("--demo", action="store_true", help="Demo mode (no backend needed)")
    parser.add_argument("--scan", action="store_true", help="One-shot scan and exit")
    args = parser.parse_args()

    try:
        if args.scan:
            asyncio.run(_scan_only())
        else:
            tui = AegisTUI(demo=args.demo)
            asyncio.run(tui.run())
    except KeyboardInterrupt:
        console.print("\n[bold red]AEGIS TUI terminated.[/bold red]")
