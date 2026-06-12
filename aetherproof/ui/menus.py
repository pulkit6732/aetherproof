"""Menu navigation helpers."""

import sys
import questionary
from .display import console


def show_main_menu() -> str:
    try:
        choice = questionary.select(
            "What would you like to do?",
            choices=[
                "Sign an AI output",
                "Verify a receipt",
                questionary.Separator("─" * 18),
                "Expert CLI mode",
                "Inspect a receipt",
                "View transparency log",
                questionary.Separator("─" * 18),
                "Generate keypair",
                "About AetherProof",
                "Quit",
            ],
        ).ask()
    except KeyboardInterrupt:
        choice = None

    if choice is None:  # Ctrl+C / Esc
        console.print("Cancelled.")
        sys.exit(0)
    return choice


def main_menu() -> str:
    """Display main menu and get user choice.

    Returns:
        Choice: '1' (easy), '2' (expert), or 'q' (quit)
    """
    console.print("\n[cyan bold]Choose your mode:[/cyan bold]\n")
    console.print("[green][1][/green] Easy Mode   — for anyone (step-by-step wizard)")
    console.print("[cyan][2][/cyan] Expert Mode — for developers (CLI subcommands)")
    console.print("[red][Q][/red] Quit\n")

    choice = console.input("[cyan]Enter choice (1, 2, or Q): [/cyan]").strip().lower()
    return choice


def confirm(prompt: str = "Continue?") -> bool:
    """Get yes/no confirmation.

    Args:
        prompt: question to ask

    Returns:
        True if yes, False if no
    """
    response = (
        console.input(f"[cyan]{prompt} [y/N]: [/cyan]").strip().lower()
    )
    return response in ("y", "yes")


def back_to_main() -> None:
    """Pause and prompt to return to main menu."""
    console.input("\n[dim]Press Enter to return to main menu...[/dim]")
