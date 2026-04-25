from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme

from .orchestrator import AegisOrchestrator

app = typer.Typer(no_args_is_help=True)
console = Console(theme=Theme({"ok": "bold green", "bad": "bold red", "accent": "bold cyan"}))


@app.command()
def run(
    cve: str = typer.Option(..., help="CVE identifier, e.g. CVE-2021-44228"),
    target: str = typer.Option(..., help="Authorized target URL"),
    targets_file: str = typer.Option("ethical_targets.yaml", help="Authorized targets allowlist file"),
) -> None:
    """Run production defensive validation against an authorized target."""
    orch = AegisOrchestrator()
    state = orch.run(cve, target, targets_file)

    tone = "ok" if not str(state.verdict).startswith("FAIL") else "bad"
    console.print(Panel.fit(f"[accent]CVE:[/accent] {state.cve.cve_id}\n[accent]Target:[/accent] {target}\n[{tone}]{state.verdict}[/{tone}]", title="Aegis Defensive Run", border_style="magenta"))


if __name__ == "__main__":
    app()
