"""Expert mode subcommands for developers."""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List

from rich.panel import Panel
from rich.table import Table

from .display import console, header
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer, Verifier
from aetherproof.core.log import ReceiptLog
from aetherproof.core.keystore import load_or_create_signer, issue_receipt
from aetherproof.core.verifier import (
    verify_receipt,
    verify_receipt_file,
    verify_output_unmodified,
    tamper_detect,
)
from aetherproof.core.hash import hash_output, compute_model_weight_root


def _ok(msg: str) -> None:
    console.print(f"[green]✓[/green] {msg}")


def _err(msg: str) -> None:
    console.print(f"[red]Error:[/red] {msg}")


def _emit_err(msg: str, quiet: bool) -> None:
    if quiet:
        print(json.dumps({"error": msg}))
    else:
        _err(msg)


def _pop_quiet(args: List[str]):
    return [a for a in args if a != "--quiet"], ("--quiet" in args)


def _extract_opt(args: List[str], flag: str):
    # pull "<flag> VALUE" out of args, return (remaining_args, value_or_None)
    if flag in args:
        i = args.index(flag)
        value = args[i + 1] if i + 1 < len(args) else None
        return args[:i] + args[i + 2:], value
    return args, None


def _receipt_panel(receipt: Receipt, title: str = None) -> None:
    inner = Table.grid(padding=(0, 2))
    inner.add_column(style="dim", justify="right")
    inner.add_column()
    for field, value in receipt.to_dict().items():
        inner.add_row(field, str(value))
    console.print(Panel(inner, title=title or f"Receipt {receipt.receipt_id}", border_style="cyan"))


def _log_table(rows) -> None:
    table = Table(show_header=True, header_style="cyan")
    table.add_column("Sequence", justify="right")
    table.add_column("Receipt ID")
    table.add_column("Timestamp")
    table.add_column("Model")
    for r in rows:
        ts = datetime.fromtimestamp(r["timestamp_ms"] / 1000, timezone.utc).isoformat()
        table.add_row(str(r["sequence"]), r["receipt_id"], ts, r["model_weight_root"][:12] + "…")
    console.print(table)


def run_expert_mode(args: List[str]) -> bool:
    """Dispatch a subcommand. Returns False if it represents a failure
    (invalid verification, broken log, unknown command, error) so the
    direct-subcommand path can exit non-zero; True otherwise."""
    if "--quiet" not in args:
        header()

    if not args or args[0] in ("-h", "--help", "help"):
        show_help()
        return True

    command = args[0]
    rest = args[1:]

    try:
        if command == "sign":
            cmd_sign(rest)
        elif command == "verify":
            return cmd_verify(rest)
        elif command == "inspect":
            cmd_inspect(rest)
        elif command == "log":
            return cmd_log(rest)
        elif command == "keygen":
            cmd_keygen(rest)
        elif command == "export":
            cmd_export(rest)
        elif command == "tamper":
            return cmd_tamper(rest)
        else:
            _err(f"Unknown command '{command}'.")
            show_help()
            return False
    except Exception as e:
        _err(str(e))
        return False
    return True


def show_help() -> None:
    console.print(
        """
[cyan bold]EXPERT MODE COMMANDS[/cyan bold]

[yellow]sign[/yellow] <model_path> <output_file> [--quiet]
  Generate a signed receipt for a model and output
  Example: aetherproof sign model.onnx output.txt

[yellow]verify[/yellow] <receipt_file> [--pubkey PATH] [--output FILE] [--quiet]
  Verify a receipt's signature; with --output, also check the output file
  still matches the receipt (detects a tampered output)
  Example: aetherproof verify receipt.json --output out.txt

[yellow]inspect[/yellow] <receipt_file>
  Show all receipt fields decoded
  Example: aetherproof inspect receipt.json

[yellow]log[/yellow] <subcommand>
  Manage the local transparency log
  - log list          : show all receipts
  - log verify        : check log integrity (no gaps)
  - log count         : total receipts

[yellow]keygen[/yellow] [--output PATH]
  Generate a new Ed25519 keypair
  Example: aetherproof keygen --output mykey

[yellow]export[/yellow] <receipt_file> <--format FORMAT>
  Export receipt in different formats
  Formats: json, hex, cbor
  Example: aetherproof export receipt.json --format hex

[yellow]tamper[/yellow] <receipt_file>
  Test tamper detection (should FAIL on tampered receipt)
  Example: aetherproof tamper receipt.json
"""
    )


def cmd_sign(args: List[str]) -> None:
    args, quiet = _pop_quiet(args)
    if len(args) < 2:
        _emit_err("usage: sign <model_path> <output_file> [--quiet]", quiet)
        return

    model_path = Path(args[0])
    output_file = Path(args[1])
    if not model_path.exists():
        _emit_err(f"Model not found: {model_path}", quiet)
        return
    if not output_file.exists():
        _emit_err(f"Output file not found: {output_file}", quiet)
        return

    model_weight_root = compute_model_weight_root(model_path)
    output_hash = hash_output(output_file.read_text(encoding="utf-8"))

    # persistent app key + transparency log, same as the interactive wizard
    signer = load_or_create_signer()
    log = ReceiptLog()
    try:
        receipt, path = issue_receipt(
            signer, log,
            model_weight_root=model_weight_root,
            output_hash=output_hash,
        )
    except Exception as e:
        _emit_err(f"Signing failed: {e}", quiet)
        return

    if quiet:
        print(receipt.to_json())
        return
    _ok(f"Receipt signed → {path}  (logged at #{receipt.log_sequence:06d})")
    _receipt_panel(receipt, title="RECEIPT SIGNED")
    console.print(f"[dim]Verify with:[/dim] aetherproof verify {path}")


def cmd_verify(args: List[str]) -> bool:
    args, quiet = _pop_quiet(args)
    args, pubkey_opt = _extract_opt(args, "--pubkey")
    args, output_opt = _extract_opt(args, "--output")

    def verr(msg):
        if quiet:
            print(json.dumps({"valid": False, "error": msg}))
        else:
            _err(msg)

    if not args:
        verr("usage: verify <receipt_file> [--pubkey PATH] [--output FILE] [--quiet]")
        return False

    receipt_path = Path(args[0])
    if not receipt_path.exists():
        verr(f"Receipt not found: {receipt_path}")
        return False

    pubkey_path = Path(pubkey_opt) if pubkey_opt else receipt_path.with_suffix(".pub")
    if not pubkey_path.exists():
        verr(f"Public key not found: {pubkey_path}")
        return False

    try:
        receipt = Receipt.from_json(receipt_path.read_text(encoding="utf-8"))
        pub = Verifier.from_public_file(str(pubkey_path))
    except Exception as e:
        verr(str(e))
        return False

    sig_valid = verify_receipt(receipt, pub)  # signature over the receipt itself

    output_unmodified = None
    if output_opt is not None:
        out_file = Path(output_opt)
        if not out_file.exists():
            verr(f"Output file not found: {out_file}")
            return False
        # recompute the output's hash and compare to what the receipt bound
        output_unmodified = verify_output_unmodified(
            receipt, hash_output(out_file.read_text(encoding="utf-8"))
        )

    overall = sig_valid and (output_unmodified if output_unmodified is not None else True)

    if quiet:
        result = {"valid": overall, "signature_valid": sig_valid}
        if output_unmodified is not None:
            result["output_unmodified"] = output_unmodified
        print(json.dumps(result))
        return overall

    if not sig_valid:
        _err("INVALID — receipt failed verification (tampered).")
    elif output_unmodified is None:
        _ok("VALID — signature intact (receipt unmodified).")
    elif output_unmodified:
        _ok("VALID — signature intact AND output file matches the receipt.")
    else:
        _err("OUTPUT MODIFIED — the output file does not match this receipt.")
    return overall


def cmd_inspect(args: List[str]) -> None:
    if not args:
        _err("usage: inspect <receipt_file>")
        return
    receipt_path = Path(args[0])
    if not receipt_path.exists():
        _err(f"Receipt not found: {receipt_path}")
        return
    try:
        receipt = Receipt.from_json(receipt_path.read_text(encoding="utf-8"))
    except Exception as e:
        _err(f"Could not parse receipt: {e}")
        return
    _receipt_panel(receipt, title=f"Inspect {receipt.receipt_id}")


def cmd_log(args: List[str]) -> bool:
    if not args:
        _err("usage: log <list|verify|count>")
        return False

    log = ReceiptLog()
    sub = args[0]

    if sub == "list":
        rows = log.list_all(limit=20)
        if rows:
            _log_table(rows)
        else:
            console.print("[dim]No receipts in log yet.[/dim]")
        return True
    elif sub == "verify":
        # key-free: hash chain + per-receipt sequence binding (rotation-safe)
        if log.verify_integrity():
            _ok(f"Log integrity verified — {log.count()} receipts, hash chain intact, no gaps.")
            return True
        _err("Log integrity check FAILED — chain broken, a gap, or a renumbered entry.")
        return False
    elif sub == "count":
        console.print(f"{log.count()} receipts in log")
        return True
    else:
        _err(f"Unknown subcommand: log {sub}")
        return False


def cmd_keygen(args: List[str]) -> None:
    output_prefix = "aetherproof_key"
    if len(args) > 1 and args[0] == "--output":
        output_prefix = args[1]

    signer = Signer.generate()
    priv_path = Path(f"{output_prefix}.pem")
    pub_path = Path(f"{output_prefix}.pub")
    signer.export_private_file(str(priv_path))
    signer.export_public_file(str(pub_path))

    _ok(f"Keypair generated → {priv_path}, {pub_path}")
    console.print("[red]Keep the private key secret.[/red]")


def cmd_export(args: List[str]) -> None:
    if len(args) < 2 or args[1] != "--format":
        _err("usage: export <receipt_file> --format <json|hex|cbor>")
        return

    receipt_path = Path(args[0])
    fmt = args[2] if len(args) > 2 else "json"
    if not receipt_path.exists():
        _err(f"Receipt not found: {receipt_path}")
        return

    try:
        receipt = Receipt.from_json(receipt_path.read_text(encoding="utf-8"))
    except Exception as e:
        _err(f"Could not parse receipt: {e}")
        return

    if fmt == "json":
        print(receipt.to_json(pretty=True))
    elif fmt == "hex":
        console.print("[dim](hex format not yet implemented)[/dim]")
    elif fmt == "cbor":
        console.print("[dim](cbor format not yet implemented)[/dim]")
    else:
        _err(f"Unknown format: {fmt}")


def cmd_tamper(args: List[str]) -> bool:
    if not args:
        _err("usage: tamper <receipt_file>")
        return False
    receipt_path = Path(args[0])
    if not receipt_path.exists():
        _err(f"Receipt not found: {receipt_path}")
        return False
    try:
        receipt = Receipt.from_json(receipt_path.read_text(encoding="utf-8"))
        pubkey_path = receipt_path.with_suffix(".pub")
        if not pubkey_path.exists():
            _err(f"Public key not found: {pubkey_path}")
            return False
        public_key = Verifier.from_public_file(str(pubkey_path))
        if tamper_detect(receipt, public_key):
            _ok("Tamper detection works — a one-bit flip is caught.")
            return True
        _err("Tamper detection FAILED (unexpected).")
        return False
    except Exception as e:
        _err(f"Tamper test error: {e}")
        return False
