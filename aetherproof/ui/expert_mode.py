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


def _extract_all(args: List[str], flag: str):
    # every "<flag> VALUE" pair, for flags that may repeat
    values = []
    while flag in args:
        args, v = _extract_opt(args, flag)
        if v is None:
            raise ValueError(f"{flag} needs a value")
        values.append(v)
    return args, values


def _trusted_keys(paths: List[str]):
    """Keys to trust, from --pubkey files; default is this machine's own key.
    Never the .pub sitting next to a receipt: whoever forged the receipt wrote that too."""
    from aetherproof.core.keystore import home
    paths = paths or [str(home() / "signing_key.pub")]
    missing = [p for p in paths if not Path(p).exists()]
    if missing:
        raise FileNotFoundError(f"public key not found: {', '.join(missing)}")
    return [Verifier.from_public_file(p) for p in paths]


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
        elif command == "approve":
            return cmd_approve(rest)
        elif command == "reconcile":
            return cmd_reconcile(rest)
        elif command == "checkpoint":
            return cmd_checkpoint(rest)
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

[yellow]approve[/yellow] --action-id ID --actor ARN --operation OP --resource ARN
        [--params FILE] [--approved-by NAME] [--ref TICKET] [--window MIN] [--quiet]
  Sign an approval for one agent action. The agent should assume its role
  with SourceIdentity=ID so CloudTrail tags every call with it.
  Example: aetherproof approve --action-id chg-2041 --actor arn:aws:sts::1:assumed-role/agent/s
           --operation s3:DeleteObject --resource arn:aws:s3:::invoices/1042.pdf

[yellow]reconcile[/yellow] <cloudtrail_file> --receipts PATH [--receipts PATH ...]
        [--pubkey PATH ...] [--agent ARN_PREFIX ...] [--as-of ISO8601] [--quiet]
  Check each approval against what CloudTrail recorded: matched, conflict,
  missing or ambiguous. --agent flags that identity's unapproved changes.
  Exits 1 unless everything matched.

[yellow]checkpoint[/yellow] create [--out FILE] [--tsa URL]
[yellow]checkpoint[/yellow] verify <file> [--pubkey PATH] [--tsa-root PEM ...] [--quiet]
  Sign the log head (optionally RFC 3161 time stamped by --tsa). Keep the file
  outside this machine; verify later to detect deleted or rewritten receipts.
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


def cmd_approve(args: List[str]) -> bool:
    from aetherproof.core.reconcile import ApprovedAction, issue_action_receipt

    args, quiet = _pop_quiet(args)
    opts = {}
    for flag in ("--action-id", "--actor", "--operation", "--resource", "--params",
                 "--approved-by", "--ref", "--window"):
        args, opts[flag] = _extract_opt(args, flag)
    required = [f for f in ("--action-id", "--actor", "--operation", "--resource") if not opts[f]]
    if required:
        _emit_err(f"approve needs {', '.join(required)}", quiet)
        return False
    params = {}
    if opts["--params"]:
        try:
            params = json.loads(Path(opts["--params"]).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            _emit_err(f"Could not read --params: {e}", quiet)
            return False
        if not isinstance(params, dict):
            _emit_err("--params must hold a JSON object", quiet)
            return False
    try:
        window_ms = int(float(opts["--window"] or 15) * 60_000)
    except ValueError:
        _emit_err("--window must be a number of minutes", quiet)
        return False

    action = ApprovedAction(action_id=opts["--action-id"], actor=opts["--actor"],
                            operation=opts["--operation"], resource=opts["--resource"], params=params,
                            approved_by=opts["--approved-by"] or "", approval_ref=opts["--ref"] or "")
    receipt, path = issue_action_receipt(load_or_create_signer(), default_log(), action, window_ms=window_ms)
    if quiet:
        print(receipt.to_json())
        return True
    _ok(f"Approval signed -> {path}  (logged at #{receipt.log_sequence:06d})")
    console.print(f"[dim]Window:[/dim] {datetime.fromtimestamp(action.not_before_ms / 1000, timezone.utc).isoformat()}"
                  f" to {datetime.fromtimestamp(action.not_after_ms / 1000, timezone.utc).isoformat()}")
    return True


def cmd_reconcile(args: List[str]) -> bool:
    from aetherproof.core.reconcile import load_cloudtrail, reconcile

    args, quiet = _pop_quiet(args)
    args, receipt_paths = _extract_all(args, "--receipts")
    args, pubkeys = _extract_all(args, "--pubkey")
    args, agents = _extract_all(args, "--agent")
    args, as_of = _extract_opt(args, "--as-of")
    if not args or not receipt_paths:
        _emit_err("usage: reconcile <cloudtrail_file> --receipts PATH [--pubkey PATH] [--agent ARN] [--as-of ISO]", quiet)
        return False

    files = []
    for p in map(Path, receipt_paths):
        if p.is_dir():
            files.extend(sorted(p.glob("*.json")))
        elif p.exists():
            files.append(p)
        else:
            _emit_err(f"Receipts not found: {p}", quiet)
            return False
    try:
        receipts = [Receipt.from_json(f.read_text(encoding="utf-8")) for f in files]
        events = load_cloudtrail(args[0])
        keys = _trusted_keys(pubkeys)
        as_of_ms = int(datetime.fromisoformat(as_of.replace("Z", "+00:00")).timestamp() * 1000) if as_of else None
    except (OSError, ValueError, KeyError) as e:
        _emit_err(str(e), quiet)
        return False

    report = reconcile(receipts, events, keys, agent_actors=agents, as_of_ms=as_of_ms)
    if quiet:
        print(json.dumps(report.to_dict()))
        return report.ok

    colour = {"matched": "green", "conflict": "red", "missing": "red", "ambiguous": "yellow"}
    table = Table(show_header=True, header_style="cyan")
    for col in ("Verdict", "Action", "Events", "Why"):
        table.add_column(col)
    for r in report.results:
        label = r.verdict.upper() + (" (unapproved)" if r.kind == "unapproved_event" else "")
        table.add_row(f"[{colour[r.verdict]}]{label}[/{colour[r.verdict]}]", r.action_id or r.receipt_id,
                      ", ".join(r.event_ids) or "-", "; ".join(r.reasons) or f"basis: {r.basis}")
    console.print(table)
    c = report.counts()
    console.print(f"{len(receipts)} approvals, {len(events)} events: "
                  f"{c['matched']} matched, {c['conflict']} conflict, {c['missing']} missing, {c['ambiguous']} ambiguous")
    return report.ok


def cmd_checkpoint(args: List[str]) -> bool:
    from aetherproof.core.anchor import Checkpoint, create_checkpoint, verify_checkpoint

    args, quiet = _pop_quiet(args)
    if not args or args[0] not in ("create", "verify"):
        _emit_err("usage: checkpoint create [--out FILE] [--tsa URL] | checkpoint verify <file> [--tsa-root PEM]", quiet)
        return False
    sub, args = args[0], args[1:]
    log = default_log()

    if sub == "create":
        args, out = _extract_opt(args, "--out")
        args, tsa = _extract_opt(args, "--tsa")
        try:
            cp = create_checkpoint(log, load_or_create_signer(), tsa_url=tsa or "")
            out_path = Path(out or f"checkpoint_{cp.log_size:06d}.json")
            out_path.write_text(cp.to_json(), encoding="utf-8")
        except Exception as e:  # TimestampError, empty log, write failure
            _emit_err(f"Checkpoint failed: {e}", quiet)
            return False
        if quiet:
            print(cp.to_json())
        else:
            _ok(f"Checkpoint of {cp.log_size} receipts -> {out_path}"
                + ("  (time stamped)" if cp.timestamp_token else ""))
            console.print("[dim]Store it somewhere this machine cannot change: email it, give it to your auditor.[/dim]")
        return True

    args, pubkeys = _extract_all(args, "--pubkey")
    args, root_paths = _extract_all(args, "--tsa-root")
    if not args:
        _emit_err("usage: checkpoint verify <file> [--pubkey PATH] [--tsa-root PEM ...]", quiet)
        return False
    try:
        from cryptography import x509
        cp = Checkpoint.from_json(Path(args[0]).read_text(encoding="utf-8"))
        roots = [x509.load_pem_x509_certificate(Path(p).read_bytes()) for p in root_paths]
        report = verify_checkpoint(cp, log, _trusted_keys(pubkeys), tsa_roots=roots)
    except (OSError, ValueError, TypeError) as e:
        _emit_err(str(e), quiet)
        return False
    if quiet:
        print(json.dumps(report.to_dict()))
        return report.ok
    for p in report.problems:
        _err(p)
    for n in report.notes:
        console.print(f"[dim]{n}[/dim]")
    if report.tsa_time:
        console.print(f"Independent time: {report.tsa_time} from {report.tsa_subject}")
    if report.ok:
        _ok(f"Checkpoint holds - the first {cp.log_size} receipts are all still there, unchanged.")
    return report.ok


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
