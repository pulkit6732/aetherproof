"""Terminal display helpers using Rich."""

import os
import sys
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from typing import Dict, Any
from datetime import datetime

# force utf-8 so box-drawing / · / ✓ encode under any Windows codepage
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass


console = Console()

BRAND = "#7fffd4"
LINK = "#1a3aff"

_LOGO_MARK = r"""      .+######+.
    ##          ##
   #      /\      #
  #      /  \      #
  #     / /\ \     #
  #    / /  \ \    #
  #   /______\ \   #
   #  \______/  #
    ##          ##
      '######'"""

_LOGO_LINES = [
    ("AETHERPROOF", f"bold {BRAND}"),
    ("v0.2.0", "dim white"),
    ("Cryptographic receipt engine", "white"),
    ("Prototype of Signet · R0/L2", "dim"),
    ("", None),
    ("github.com/pulkit6732/aetherproof", LINK),
    ("Verify(receipt, pk, log) = TRUE", "dim"),
]

_ACTIONS = "Sign · Verify · Inspect · Log · Keygen"


def print_logo() -> None:
    no_color = (not console.is_terminal) or bool(os.environ.get("NO_COLOR"))

    if no_color:
        print()
        print(_LOGO_MARK)
        print()
        for text, _ in _LOGO_LINES:
            print(text)
        print("-" * 56)
        print(_ACTIONS)
        print()
        return

    # side-by-side: mark left, identity block right
    right = Group(*[Text(t, style=s) if s else Text("") for t, s in _LOGO_LINES])
    grid = Table.grid(padding=(0, 4))
    grid.add_column()
    grid.add_column(vertical="middle")
    grid.add_row(Text(_LOGO_MARK, style=BRAND), right)

    console.print()
    console.print(grid)
    console.rule(style="dim")
    console.print(Text(_ACTIONS, style="dim"), justify="center")
    console.print()


def run_about() -> None:
    invariant = Panel(
        Group(
            Text("Verify(receipt, public_key, log) = TRUE"),
            Text("using only those three inputs — offline, forever."),
        ),
        border_style="dim cyan",
    )
    body = Group(
        Text("AetherProof is the open-source cryptographic receipt engine."),
        Text("The prototype of Signet — the AI inference trust layer."),
        Text(""),
        invariant,
        Text(""),
        Text("Version:  v0.2.0"),
        Text("GitHub:   github.com/pulkit6732/aetherproof"),
    )
    console.print(Panel(body, title="About AetherProof", border_style="dim"))


def header() -> None:
    """Print branded header."""
    title_text = Text("AETHERPROOF", style="cyan bold")
    subtitle = Text("the open-source receipt engine", style="dim cyan")
    console.print(f"\n{title_text}")
    console.print(subtitle)
    console.print("Prototype of Signet • v0.2.0\n", style="dim")


def receipt_table(receipt: "Receipt") -> None:
    """Display receipt fields in a table.

    Args:
        receipt: Receipt object to display
    """
    table = Table(title="Receipt — Cryptographic Proof", show_header=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Receipt ID", receipt.receipt_id)
    table.add_row("Model Weight Root", receipt.model_weight_root[:32] + "...")
    table.add_row("Output Hash", receipt.output_hash[:32] + "...")
    table.add_row("Input Commitment", receipt.input_commitment[:32] + "..." if receipt.input_commitment else "(hidden)")
    table.add_row("Timestamp", datetime.fromtimestamp(receipt.timestamp_ms / 1000).isoformat())
    table.add_row("Log Sequence", str(receipt.log_sequence))
    table.add_row("Signature Valid", "✓ YES" if receipt.signature else "✗ NO")

    console.print(table)


def success_box(title: str, message: str) -> None:
    """Display a green success box.

    Args:
        title: box title
        message: box message
    """
    panel = Panel(message, title=title, style="bold green", border_style="green")
    console.print(panel)


def error_box(title: str, message: str) -> None:
    """Display a red error box.

    Args:
        title: box title
        message: box message
    """
    panel = Panel(message, title=title, style="bold red", border_style="red")
    console.print(panel)


def warning_box(title: str, message: str) -> None:
    """Display a yellow warning box.

    Args:
        title: box title
        message: box message
    """
    panel = Panel(message, title=title, style="bold yellow", border_style="yellow")
    console.print(panel)


def info_box(title: str, message: str) -> None:
    """Display a cyan info box.

    Args:
        title: box title
        message: box message
    """
    panel = Panel(message, title=title, style="bold cyan", border_style="cyan")
    console.print(panel)


def spinner_progress(description: str = "Processing...") -> Progress:
    """Create a spinner progress bar.

    Args:
        description: progress description

    Returns:
        Progress context manager
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    )


def verification_result(receipt_id: str, is_valid: bool) -> None:
    """Display verification result.

    Args:
        receipt_id: the receipt ID
        is_valid: whether receipt is valid
    """
    if is_valid:
        success_box(
            "✓ VERIFIED",
            f"Receipt {receipt_id[:16]}... is valid and unmodified.",
        )
    else:
        error_box(
            "✗ INVALID",
            f"Receipt {receipt_id[:16]}... failed verification (tampered?).",
        )


def main_menu() -> str:
    """Display main menu and get user choice.

    Returns:
        Choice: 'easy', 'expert', or 'quit'
    """
    console.print("\n[cyan bold]Choose your mode:[/cyan bold]")
    console.print("[green][1][/green] Easy Mode   — for anyone (wizard)")
    console.print("[cyan][2][/cyan] Expert Mode — for developers (CLI)")
    console.print("[red][Q][/red] Quit")
    console.print()

    choice = console.input("[cyan]Choose (1, 2, or Q): [/cyan]").strip().lower()
    return choice


def multiline_input(prompt: str = "Enter text (Ctrl+D or blank line to end):") -> str:
    """Get multiline input from user.

    Args:
        prompt: prompt text

    Returns:
        Combined input lines
    """
    console.print(f"[cyan]{prompt}[/cyan]")
    lines = []
    try:
        while True:
            line = console.input()
            if line:
                lines.append(line)
            else:
                break
    except EOFError:
        pass

    return "\n".join(lines)


def get_input(prompt: str, default: str = "") -> str:
    """Get a single line of input.

    Args:
        prompt: prompt text
        default: default value if user enters nothing

    Returns:
        User input
    """
    text = console.input(f"[cyan]{prompt}[/cyan] ").strip()
    return text if text else default


def table_from_list(items: list, headers: list = None) -> Table:
    """Create a Rich table from a list of dicts.

    Args:
        items: list of dictionaries
        headers: list of header names (if None, use dict keys from first item)

    Returns:
        Rich Table object
    """
    if not items:
        return Table()

    if headers is None:
        headers = list(items[0].keys())

    table = Table(show_header=True)
    for header in headers:
        table.add_column(header, style="cyan")

    for item in items:
        row = [str(item.get(h, "")) for h in headers]
        table.add_row(*row)

    return table
