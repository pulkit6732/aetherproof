"""Easy mode signing wizard."""

import json
import time
import secrets
from pathlib import Path
from datetime import datetime, timezone

import questionary
from questionary import Validator, ValidationError
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn

from .display import console
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Verifier
from aetherproof.core.verifier import verify_receipt
from aetherproof.core.hash import hash_output

RECEIPTS_DIR = Path("./receipts")
MODEL_CHOICES = ["GPT-4o", "Gemini", "Llama 3", "Mistral", "Custom…"]


def _ask(question):
    # uniform Ctrl+C / Esc -> None
    try:
        return question.ask()
    except KeyboardInterrupt:
        return None


def run_easy_mode(signer, log) -> None:
    model = _select_model()
    if model is None:
        console.print("Cancelled.")
        return

    output_text = _collect_output()
    if output_text is None:
        console.print("Cancelled.")
        return

    result = _sign_and_log(signer, log, model, output_text)
    if result is None:
        return  # failure panel already shown
    receipt, path = result

    _show_success(receipt, model, path)
    _post_action(receipt, path)


def _select_model():
    model = _ask(questionary.select(
        "Which AI model produced this output?",
        choices=MODEL_CHOICES,
    ))
    if model is None:
        return None
    if model == "Custom…":
        name = _ask(questionary.text(
            "Model name:",
            validate=lambda t: True if t.strip() else "Model name cannot be empty.",
        ))
        return name.strip() if name else None
    return model


def _collect_output():
    console.print("Paste the AI output below. Press Enter twice when done.")
    while True:
        lines = []
        try:
            while True:
                line = input()
                if line == "":  # blank line ends input
                    break
                lines.append(line)
        except EOFError:
            pass
        except KeyboardInterrupt:
            return None
        text = "\n".join(lines)
        if text.strip():
            return text
        console.print("[red]Output cannot be empty. Try again.[/red]")


def _sign_and_log(signer, log, model, output_text):
    steps = [
        "[1/4] Hashing output",
        "[2/4] Computing model root",
        "[3/4] Signing receipt",
        "[4/4] Writing to log",
    ]
    written = []        # files created this run, for rollback
    committed = False   # True once log.append succeeds — the commit point
    receipt = None
    path = None
    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            tasks = [progress.add_task(s, total=100, start=False) for s in steps]

            progress.start_task(tasks[0])
            output_hash = hash_output(output_text)
            _finish(progress, tasks[0])

            progress.start_task(tasks[1])
            model_weight_root = hash_output(model)
            _finish(progress, tasks[1])

            progress.start_task(tasks[2])
            seq = log.max_sequence() + 1  # single-writer; drift checked at append
            receipt = Receipt(
                receipt_version="1.0",
                model_weight_root=model_weight_root,
                input_commitment="",
                output_hash=output_hash,
                timestamp_ms=int(datetime.now(timezone.utc).timestamp() * 1000),
                log_sequence=seq,
                hw_evidence=[],
                signature="",
                log_anchor=f"local://log/{seq}",  # set BEFORE signing
                receipt_id=f"ap_{secrets.token_hex(4)}",
            )
            receipt.signature = signer.sign(receipt.signing_bytes())
            _finish(progress, tasks[2])

            progress.start_task(tasks[3])
            RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
            path = RECEIPTS_DIR / f"{receipt.receipt_id}.json"
            pub = path.with_suffix(".pub")
            # files first, append last: append is the commit. if append fails
            # the files are rolled back, so nothing is left orphaned.
            _atomic_write(path, receipt.to_json(pretty=True).encode("utf-8"))
            written.append(path)
            _atomic_write(pub, signer.get_public_key().export_public_pem())
            written.append(pub)
            assigned = log.append(receipt)
            if assigned != seq:
                raise RuntimeError(f"log sequence drift ({assigned} != {seq}); concurrent write")
            committed = True
            _finish(progress, tasks[3])
    except KeyboardInterrupt:
        if not committed:
            _cleanup(written)
            console.print("Cancelled. Nothing was written.")
            return None
    except Exception as e:
        if not committed:
            _cleanup(written)
            console.print(Panel(f"Signing failed: {e}", border_style="red"))
            console.print("Nothing was written.")
            return None

    return receipt, path


def _finish(progress, task):
    progress.update(task, completed=100)
    time.sleep(0.4)


def _atomic_write(path: Path, data: bytes):
    # write to a temp sibling then replace — target is never partially written
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_bytes(data)
        tmp.replace(path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _cleanup(paths):
    for p in paths:
        try:
            p.unlink()
        except OSError:
            pass


def _show_success(receipt, model, path):
    inner = Table.grid(padding=(0, 2))
    inner.add_column(style="dim", justify="right")
    inner.add_column()
    inner.add_row("Receipt ID", receipt.receipt_id)
    inner.add_row("Model", model)
    inner.add_row("Output hash", f"sha256:{receipt.output_hash[:16]}...")
    signed_at = datetime.fromtimestamp(receipt.timestamp_ms / 1000, timezone.utc).isoformat()
    inner.add_row("Signed at", signed_at)
    inner.add_row("Log entry", f"#{receipt.log_sequence:06d}")
    inner.add_row("Saved to", str(path))

    console.print(Panel(inner, title="RECEIPT SIGNED", border_style="green"))
    console.print("This output is now cryptographically proven.")
    console.print("Share the receipt file to prove it was never modified.")


def _post_action(receipt, path):
    choice = _ask(questionary.select(
        "Next:",
        choices=["Verify this receipt", "Inspect receipt", "Return to menu"],
    ))
    if choice in (None, "Return to menu"):
        return
    if choice == "Verify this receipt":
        _inline_verify(path)
    elif choice == "Inspect receipt":
        _inline_inspect(receipt)


def _inline_verify(path):
    pub = path.with_suffix(".pub")
    receipt = Receipt.from_json(path.read_text(encoding="utf-8"))
    ok = verify_receipt(receipt, Verifier.from_public_file(str(pub)))
    if ok:
        console.print(Panel("✓ VALID — signature intact, output unmodified.",
                            border_style="green"))
    else:
        console.print(Panel("✗ INVALID — receipt failed verification.",
                            border_style="red"))


def _inline_inspect(receipt):
    inner = Table.grid(padding=(0, 2))
    inner.add_column(style="dim", justify="right")
    inner.add_column()
    for field, value in receipt.to_dict().items():
        inner.add_row(field, str(value))
    console.print(Panel(inner, title=f"Receipt {receipt.receipt_id}", border_style="dim"))


class PathValidator(Validator):
    def __init__(self, is_file=False):
        self.is_file = is_file

    def validate(self, document):
        text = document.text.strip()
        p = Path(text).expanduser()
        ok = p.is_file() if self.is_file else p.exists()
        if not text or not ok:
            raise ValidationError(message="File not found.", cursor_position=len(document.text))


def _config_file() -> Path:
    return Path.home() / ".aetherproof" / "config.json"


def _last_pubkey() -> str:
    try:
        data = json.loads(_config_file().read_text(encoding="utf-8"))
        return str(data.get("last_pubkey", ""))
    except (OSError, ValueError):
        return ""


def _save_last_pubkey(path) -> None:
    cfg = _config_file()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"last_pubkey": str(path)}), encoding="utf-8")


def run_verify_wizard(verifier, log) -> None:
    # verifier: reserved for caller symmetry; verification uses the chosen key file
    receipt_path = _ask(questionary.path(
        "Receipt file path:", validate=PathValidator(is_file=True)))
    if receipt_path is None:
        console.print("Cancelled.")
        return

    pub_path = _ask(questionary.path(
        "Public key path:",
        default=_last_pubkey(),
        validate=PathValidator(is_file=True),
    ))
    if pub_path is None:
        console.print("Cancelled.")
        return

    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            tasks = [progress.add_task(s, total=100, start=False) for s in
                     ("[1/2] Loading receipt", "[2/2] Verifying signature and log")]

            progress.start_task(tasks[0])
            receipt = Receipt.from_json(Path(receipt_path).read_text(encoding="utf-8"))
            pub = Verifier.from_public_file(str(Path(pub_path)))
            _finish(progress, tasks[0])

            progress.start_task(tasks[1])
            result = _evaluate(receipt, pub, log)
            _finish(progress, tasks[1])
    except KeyboardInterrupt:
        console.print("Cancelled.")
        return
    except (ValueError, OSError) as e:
        console.print(Panel(f"Could not read receipt or key: {e}", border_style="red"))
        return

    status = result["status"]
    if status == "valid":
        _verify_valid_panel()
    elif status == "unlogged":
        _verify_unlogged_panel(result)
    elif status == "log_broken":
        _verify_logbroken_panel(result)
    else:  # tampered
        _verify_invalid_panel(result)


def _evaluate(receipt, pub, log):
    # 1. signature: does the receipt match what was signed?
    if not pub.verify(receipt.signing_bytes(), receipt.signature):
        return {"status": "tampered", "field": "receipt contents",
                "reason": "The receipt's contents were altered after signing, "
                          "so the signature no longer matches."}

    # 2. is this receipt recorded in THIS machine's log?
    entry = log.get_by_sequence(receipt.log_sequence) if receipt.log_sequence else None
    found = (
        entry is not None
        and entry.get("receipt_id") == receipt.receipt_id
        and entry.get("signature") == receipt.signature
    )
    if not found:
        # valid signature, simply not issued here — NOT tamper
        return {"status": "unlogged",
                "reason": "The signature is authentic, but this receipt is not in "
                          "this machine's transparency log. That is expected when "
                          "verifying a receipt that was issued on another machine."}

    # 3. receipt is logged here — is the local log itself intact?
    #    key-free: chain + sequence binding (rotation-safe, no false TAMPER)
    if not log.verify_integrity():
        return {"status": "log_broken", "field": "local transparency log",
                "reason": "The signature is authentic and the receipt is logged, but "
                          "this machine's log failed its integrity check — the local "
                          "log has been altered. The receipt itself is intact."}

    return {"status": "valid"}


def _verify_valid_panel():
    inner = Table.grid(padding=(0, 2))
    inner.add_column(style="dim", justify="right")
    inner.add_column()
    inner.add_row("Signature", "✓ VALID")
    inner.add_row("Log entry", "✓ FOUND, INTACT")
    inner.add_row("Chain", "✓ UNBROKEN")
    inner.add_row("Tamper", "✓ NONE DETECTED")
    console.print(Panel(inner, title="RECEIPT VALID", border_style="green"))


def _verify_unlogged_panel(result):
    inner = Table.grid(padding=(0, 2))
    inner.add_column(style="dim", justify="right")
    inner.add_column()
    inner.add_row("Signature", "✓ VALID")
    inner.add_row("Log entry", "— not in this machine's log")
    inner.add_row("Chain", "— not checked (not logged here)")
    inner.add_row("Tamper", "✓ NONE DETECTED")
    console.print(Panel(inner, title="SIGNATURE VALID — NOT IN THIS LOG", border_style="yellow"))
    console.print(result["reason"])


def _verify_logbroken_panel(result):
    inner = Table.grid(padding=(0, 2))
    inner.add_column(style="dim", justify="right")
    inner.add_column()
    inner.add_row("Signature", "✓ VALID (receipt intact)")
    inner.add_row("Log entry", "✓ FOUND")
    inner.add_row("Chain", "✗ BROKEN")
    inner.add_row("Tamper", "✗ LOCAL LOG ALTERED")
    console.print(Panel(inner, title="LOG INTEGRITY FAILURE", border_style="red"))
    console.print(result["reason"])


def _verify_invalid_panel(result):
    inner = Table.grid(padding=(0, 2))
    inner.add_column(style="dim", justify="right")
    inner.add_column()
    inner.add_row("Failed check", "Signature")
    inner.add_row("Field", result["field"])
    inner.add_row("Reason", result["reason"])
    console.print(Panel(inner, title="TAMPER DETECTED", border_style="red"))
    console.print("This receipt has been modified.")
