"""CLI entry point — bare interactive menu or direct subcommands."""

import sys
import json
from pathlib import Path

import questionary
from rich.table import Table

from .ui.display import console, print_logo, run_about
from .ui.menus import show_main_menu
from .ui.easy_mode import (
    run_easy_mode,
    run_verify_wizard,
    PathValidator,
    _save_last_pubkey,
)
from .ui.expert_mode import run_expert_mode
from .core.log import ReceiptLog
from .core.keystore import KEY_DIR, load_or_create_signer


def _app_state():
    # persistent app signing key + transparency log (shared keystore)
    signer = load_or_create_signer(KEY_DIR)
    pub = KEY_DIR / "signing_key.pub"
    if pub.exists():
        _save_last_pubkey(pub)  # verify wizard defaults to the app key
    return signer, ReceiptLog()


def _ask_path(message):
    try:
        return questionary.path(message, validate=PathValidator(is_file=True)).ask()
    except KeyboardInterrupt:
        return None


def _ask_text(message, default=""):
    try:
        return questionary.text(message, default=default).ask()
    except KeyboardInterrupt:
        return None


def run_expert_shell():
    console.print("[dim]Expert shell — type a command, or 'exit' to return.[/dim]")
    while True:
        try:
            line = console.input("[cyan bold]aetherproof>[/cyan bold] ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not line:
            continue
        if line.lower() in ("exit", "quit"):
            return
        run_expert_mode(line.split())


def run_inspect_wizard():
    p = _ask_path("Receipt file path:")
    if p:
        run_expert_mode(["inspect", p])


def run_log_viewer():
    run_expert_mode(["log", "list"])
    run_expert_mode(["log", "verify"])


def run_keygen_wizard():
    prefix = _ask_text("Key name (prefix):", default="aetherproof_key")
    if not prefix:
        return
    run_expert_mode(["keygen", "--output", prefix])
    pub = Path(f"{prefix}.pub")
    if pub.exists():
        _save_last_pubkey(pub)  # becomes the verify-wizard default


def _help_table():
    table = Table(title="AetherProof — commands", show_header=True, header_style="cyan")
    table.add_column("Command")
    table.add_column("Description")
    table.add_row("aetherproof", "Launch the interactive menu")
    table.add_row("sign <model> <output> [--quiet]", "Sign a model output → receipt")
    table.add_row("verify <receipt> [--pubkey K] [--output F] [--quiet]", "Verify a receipt (+ output file) offline")
    table.add_row("inspect <receipt>", "Show all receipt fields decoded")
    table.add_row("log <list|verify|count>", "Inspect the transparency log")
    table.add_row("keygen [--output NAME]", "Generate an Ed25519 keypair")
    table.add_row("export <receipt> --format <json|hex|cbor>", "Export a receipt")
    table.add_row("tamper <receipt>", "Test tamper detection")
    table.add_row("--debug", "Show full tracebacks on error")
    console.print(table)


def _run(argv):
    if argv:  # direct subcommand
        if argv[0] in ("-h", "--help", "help"):
            _help_table()
            return
        ok = run_expert_mode(argv)
        if ok is False:  # failed verification / broken log / error -> exit 1
            sys.exit(1)
        return

    # the bare command launches the interactive menu, which needs a real
    # terminal. in a pipe / CI / redirected context, fail clearly instead of
    # with a confusing prompt_toolkit traceback.
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        console.print("AetherProof needs an interactive terminal for the menu.")
        console.print("Run a direct command instead, e.g. "
                      "[cyan]aetherproof --help[/cyan] or "
                      "[cyan]aetherproof sign <model> <output>[/cyan].")
        sys.exit(2)

    signer, log = _app_state()
    print_logo()
    routes = {
        "Sign an AI output": lambda: run_easy_mode(signer, log),
        "Verify a receipt": lambda: run_verify_wizard(signer.get_public_key(), log),
        "Expert CLI mode": run_expert_shell,
        "Inspect a receipt": run_inspect_wizard,
        "View transparency log": run_log_viewer,
        "Generate keypair": run_keygen_wizard,
        "About AetherProof": run_about,
        "Quit": lambda: sys.exit(0),
    }
    while True:
        routes[show_main_menu()]()


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    debug = "--debug" in argv
    argv = [a for a in argv if a != "--debug"]

    try:
        _run(argv)
        return 0
    except KeyboardInterrupt:
        if debug:
            raise
        console.print("Cancelled. Nothing was written.")
        sys.exit(0)
    except FileNotFoundError as e:
        if debug:
            raise
        console.print(f"[red]File not found:[/red] {e.filename}")
        sys.exit(1)
    except json.JSONDecodeError:
        if debug:
            raise
        console.print("[red]Could not read file. May be corrupted.[/red]")
        sys.exit(1)
    except Exception as e:
        if debug:
            raise
        console.print(f"[red]Unexpected error:[/red] {e}  (run with --debug for details)")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main())
