"""Expert mode subcommands for developers."""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import List

from rich.panel import Panel
from rich.table import Table

from .display import console, err_console, header
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer, Verifier
from aetherproof.core.log import ReceiptLog
from aetherproof.core.keystore import (load_or_create_signer, issue_receipt,
                                       default_log)
from aetherproof.core.verifier import (
    verify_receipt,
    verify_receipt_file,
    verify_output_unmodified,
    tamper_detect,
)
from aetherproof.core.hash import hash_output, sha256_file, compute_model_weight_root


def _ok(msg: str) -> None:
    console.print(f"[green][/green] {msg}")


def _err(msg: str) -> None:
    # Errors go to STDERR. stdout is the data channel - `--quiet` JSON results
    # and `export` payloads must be pipeable without error text mixed in.
    err_console.print(f"[red]Error:[/red] {msg}")


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
        table.add_row(str(r["sequence"]), r["receipt_id"], ts, r["model_weight_root"][:12] + "...")
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
            return cmd_sign(rest)
        elif command == "verify":
            return cmd_verify(rest)
        elif command == "inspect":
            return cmd_inspect(rest)
        elif command == "log":
            return cmd_log(rest)
        elif command == "keygen":
            return cmd_keygen(rest)
        elif command == "export":
            return cmd_export(rest)
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

[yellow]sign[/yellow] [<model_path>] <output_file> [--input FILE] [--quiet]
  Generate a signed receipt for an AI output.
  The model file is OPTIONAL - cloud AI users (ChatGPT, Claude, Gemini)
  cannot download weights, so it is left out and the receipt is tiered
  honestly as name_only instead of pretending the weights were checked.
  --input binds the prompt too, so the receipt proves what was ASKED as
  well as what was answered. Without it input_commitment stays empty.
  Example: aetherproof sign answer.txt --input prompt.txt
           aetherproof sign model.onnx answer.txt --input prompt.txt

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
  Export a receipt. Formats: json, hex
  hex is the receipt JSON as hex - for embedding where only an ASCII
  scalar fits (a DB column, a QR code, an HTTP header).
  Example: aetherproof export receipt.json --format hex

[yellow]tamper[/yellow] <receipt_file>
  Test tamper detection (should FAIL on tampered receipt)
  Example: aetherproof tamper receipt.json
"""
    )


def cmd_sign(args: List[str]) -> None:
    args, quiet = _pop_quiet(args)
    # --input binds the PROMPT as well as the answer. Without it the receipt
    # proves "this output was not altered" but says nothing about what was
    # asked, which is the half an auditor usually cares about.
    args, input_file = _extract_opt(args, "--input")
    args, model_opt = _extract_opt(args, "--model")

    # The model file is OPTIONAL. Anyone using a cloud AI (ChatGPT, Claude,
    # Gemini) cannot download the weights, so demanding a model path made the
    # tool unusable for the majority of its actual users. One positional arg =
    # just the output; two = model then output.
    if len(args) >= 2:
        model_arg, output_arg = args[0], args[1]
    elif len(args) == 1:
        model_arg, output_arg = model_opt, args[0]
    else:
        _emit_err("usage: sign [<model_path>] <output_file> [--input FILE] [--quiet]",
                  quiet)
        return False

    output_file = Path(output_arg)
    if not output_file.exists():
        _emit_err(f"Output file not found: {output_file}", quiet)
        return False

    model_path = Path(model_arg) if model_arg else None
    if model_path is not None and not model_path.exists():
        _emit_err(f"Model not found: {model_path}", quiet)
        return False

    input_commitment = ""
    if input_file:
        ip = Path(input_file)
        if not ip.exists():
            _emit_err(f"Input file not found: {ip}", quiet)
            return False
        input_commitment = sha256_file(ip)

    # Tier honestly: hashing real weights is artifact_hash, the strongest claim.
    # With no model file there is nothing to hash, so the root commits only to
    # the fact that no model was identified - and says so as name_only rather
    # than implying the weights were checked.
    if model_path is not None:
        model_weight_root = compute_model_weight_root(model_path)
        model_root_type = "artifact_hash"
    else:
        model_weight_root = hash_output("unspecified")
        model_root_type = "name_only"

    # raw-byte hash (streamed) - exact for any size / encoding / binary, and
    # symmetric with `verify --output`, which recomputes the same way.
    output_hash = sha256_file(output_file)

    # persistent app key + transparency log, same as the interactive wizard
    signer = load_or_create_signer()
    log = default_log()
    try:
        receipt, path = issue_receipt(
            signer, log,
            model_weight_root=model_weight_root,
            model_root_type=model_root_type,
            output_hash=output_hash,
            input_commitment=input_commitment,
        )
    except Exception as e:
        _emit_err(f"Signing failed: {e}", quiet)
        return False

    if quiet:
        print(receipt.to_json())
        return True
    _ok(f"Receipt signed -> {path}  (logged at #{receipt.log_sequence:06d})")
    _receipt_panel(receipt, title="RECEIPT SIGNED")
    console.print(f"[dim]Verify with:[/dim] aetherproof verify {path}")
    return True


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
        # recompute the output's hash and compare to what the receipt bound.
        # raw-byte hash (streamed) so it matches a file signed by easy-mode's
        # file path and works for any size / encoding / binary.
        output_unmodified = verify_output_unmodified(
            receipt, sha256_file(out_file)
        )

    overall = sig_valid and (output_unmodified if output_unmodified is not None else True)

    if quiet:
        result = {"valid": overall, "signature_valid": sig_valid}
        if output_unmodified is not None:
            result["output_unmodified"] = output_unmodified
        print(json.dumps(result))
        return overall

    if not sig_valid:
        _err("INVALID - receipt failed verification (tampered).")
    elif output_unmodified is None:
        _ok("VALID - signature intact (receipt unmodified).")
    elif output_unmodified:
        _ok("VALID - signature intact AND output file matches the receipt.")
    else:
        _err("OUTPUT MODIFIED - the output file does not match this receipt.")
    return overall


def cmd_inspect(args: List[str]) -> bool:
    """Show a receipt's fields.

    Returns False on failure so the exit code is non-zero - this returned None
    unconditionally, so `aetherproof inspect missing.json && deploy` deployed.
    """
    if not args:
        _err("usage: inspect <receipt_file>")
        return False
    receipt_path = Path(args[0])
    if not receipt_path.exists():
        _err(f"Receipt not found: {receipt_path}")
        return False
    try:
        receipt = Receipt.from_json(receipt_path.read_text(encoding="utf-8"))
    except Exception as e:
        _err(f"Could not parse receipt: {e}")
        return False
    _receipt_panel(receipt, title=f"Inspect {receipt.receipt_id}")
    return True


def cmd_log(args: List[str]) -> bool:
    if not args:
        _err("usage: log <list|verify|count>")
        return False

    log = default_log()
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
            _ok(f"Log integrity verified - {log.count()} receipts, hash chain intact, no gaps.")
            return True
        _err("Log integrity check FAILED - chain broken, a gap, or a renumbered entry.")
        return False
    elif sub == "count":
        console.print(f"{log.count()} receipts in log")
        return True
    else:
        _err(f"Unknown subcommand: log {sub}")
        return False


def cmd_keygen(args: List[str]) -> bool:
    output_prefix = "aetherproof_key"
    if len(args) > 1 and args[0] == "--output":
        output_prefix = args[1]

    signer = Signer.generate()
    priv_path = Path(f"{output_prefix}.pem")
    pub_path = Path(f"{output_prefix}.pub")
    try:
        signer.export_private_file(str(priv_path))
        signer.export_public_file(str(pub_path))
    except OSError as e:
        _err(f"Could not write keypair: {e}")
        return False

    _ok(f"Keypair generated -> {priv_path}, {pub_path}")
    console.print("[red]Keep the private key secret.[/red]")
    return True


EXPORT_FORMATS = ("json", "hex")


def cmd_export(args: List[str]) -> bool:
    """Export a receipt.

    Returns False on any failure so the process exits non-zero - these used to
    return None unconditionally, so `aetherproof export missing.json && deploy`
    happily ran the deploy.

    `hex` is the canonical receipt JSON encoded as hex, which is what you want
    when embedding a receipt somewhere that only accepts an ASCII scalar (a
    database column, a QR code, an HTTP header). `cbor` was previously
    advertised in the help but printed "not yet implemented" and exited 0 - it
    is no longer offered rather than pretending.
    """
    if len(args) < 2 or args[1] != "--format":
        _err(f"usage: export <receipt_file> --format <{'|'.join(EXPORT_FORMATS)}>")
        return False

    receipt_path = Path(args[0])
    fmt = args[2] if len(args) > 2 else "json"
    if not receipt_path.exists():
        _err(f"Receipt not found: {receipt_path}")
        return False

    try:
        receipt = Receipt.from_json(receipt_path.read_text(encoding="utf-8"))
    except Exception as e:
        _err(f"Could not parse receipt: {e}")
        return False

    if fmt == "json":
        print(receipt.to_json(pretty=True))
    elif fmt == "hex":
        print(receipt.to_json().encode("utf-8").hex())
    else:
        _err(f"Unknown format: {fmt}. Supported: {', '.join(EXPORT_FORMATS)}")
        return False
    return True


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
            _ok("Tamper detection works - a one-bit flip is caught.")
            return True
        _err("Tamper detection FAILED (unexpected).")
        return False
    except Exception as e:
        _err(f"Tamper test error: {e}")
        return False
