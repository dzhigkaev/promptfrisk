"""Command-line interface for promptfrisk.

Frisk a prompt or response from a file or stdin, print findings, and (optionally)
fail the process for CI gating.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from promptfrisk import __version__
from promptfrisk.engine import Guardrail
from promptfrisk.models import Action, Direction, GuardrailConfig, GuardResult, ScanContext

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2

_ACTION_STYLE = {
    Action.ALLOW: "green",
    Action.FLAG: "yellow",
    Action.REDACT: "cyan",
    Action.BLOCK: "bold red",
}


@click.group()
@click.version_option(__version__, prog_name="promptfrisk")
def cli() -> None:
    """Frisk the LLM boundary for prompt injection, PII, secrets, and tool-call risks."""


@cli.command("scan")
@click.argument("input_file", type=click.Path(dir_okay=False), required=False)
@click.option(
    "--direction", "-d",
    type=click.Choice(["input", "output"]),
    default="input",
    show_default=True,
    help="Treat the text as a model input or output.",
)
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--show-redacted", is_flag=True, help="Print the redacted text after scanning.")
@click.option(
    "--fail-on",
    type=click.Choice(["flag", "redact", "block"]),
    default="block",
    show_default=True,
    help="Exit non-zero if the action reaches this level.",
)
def scan_cmd(
    input_file: str | None,
    direction: str,
    fmt: str,
    show_redacted: bool,
    fail_on: str,
) -> None:
    """Scan text from INPUT_FILE (or '-'/omitted for stdin)."""
    console = Console()
    err = Console(stderr=True)

    from_stdin = input_file in (None, "", "-")
    try:
        text = sys.stdin.read() if from_stdin else Path(input_file).read_text()
    except FileNotFoundError as exc:
        err.print(f"[red]error:[/] {exc}")
        sys.exit(EXIT_ERROR)

    guard = Guardrail(GuardrailConfig())
    context = ScanContext(direction=Direction(direction))
    result = guard.scan(text, context)

    if fmt == "json":
        console.print(json.dumps(_to_dict(result), indent=2), markup=False, highlight=False)
    else:
        _render_table(result, console)

    if show_redacted and result.text != text:
        console.print("\n[bold]Redacted text:[/]")
        console.print(result.text, markup=False, highlight=False)

    threshold = {"flag": Action.FLAG, "redact": Action.REDACT, "block": Action.BLOCK}[fail_on]
    if result.action >= threshold:
        err.print(
            f"\n[red]promptfrisk: action {result.action.label} "
            f"reached --fail-on {fail_on}[/]"
        )
        sys.exit(EXIT_FAILED)
    sys.exit(EXIT_OK)


def _render_table(result: GuardResult, console: Console) -> None:
    table = Table(title="promptfrisk", header_style="bold")
    table.add_column("Scanner")
    table.add_column("Category")
    table.add_column("Conf", justify="right")
    table.add_column("Detail")
    for f in result.findings:
        table.add_row(f.scanner, f.category, f"{f.confidence:.2f}", f.message)
    if result.findings:
        console.print(table)
    style = _ACTION_STYLE[result.action]
    console.print(
        f"action: [{style}]{result.action.label}[/] · "
        f"confidence {result.confidence:.2f} · {len(result.findings)} finding(s)"
    )


def _to_dict(result: GuardResult) -> dict:
    return {
        "action": result.action.label,
        "confidence": result.confidence,
        "findings": [
            {
                "scanner": f.scanner,
                "category": f.category,
                "message": f.message,
                "confidence": f.confidence,
                "start": f.start,
                "end": f.end,
            }
            for f in result.findings
        ],
        "text": result.text,
    }


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
