"""The interactive wizard - the path a non-technical user actually takes.

easy_mode.py was 284 statements at 0% coverage, and that mattered more than the
number suggests: it had its own copy of the receipt-building logic, and that
copy had drifted behind the hardened one. Wizard receipts were pinned to
receipt_version="1.1" (no signed receipt_id, no signing_key_id), written to a
RECEIPTS_DIR frozen at import (ignoring AETHERPROOF_HOME), with no retry when a
concurrent writer took the log sequence.

So the least-hardened code path in the project was the one aimed at the people
least able to notice. It now delegates to issue_receipt like everything else.

questionary needs a real terminal, so the prompts are stubbed; everything behind
them is exercised for real.
"""

import json
from pathlib import Path

import pytest

from aetherproof.core.hash import hash_output, sha256_file
from aetherproof.core.keystore import load_or_create_signer, default_log
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt
from aetherproof.ui import easy_mode as em


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)
    # the wizard sleeps 0.4s per step purely for feel; skip it in tests
    monkeypatch.setattr(em, "_finish",
                        lambda progress, task: progress.update(task, completed=100))
    yield


@pytest.fixture
def rig(tmp_path):
    signer = load_or_create_signer()
    log = default_log()
    yield signer, log, tmp_path
    log.close()


class Stub:
    """Stands in for a questionary prompt."""

    def __init__(self, answer=None, raises=None):
        self.answer = answer
        self.raises = raises

    def ask(self):
        if self.raises:
            raise self.raises
        return self.answer


def out(capsys):
    cap = capsys.readouterr()
    return cap.out + cap.err


# ══ _ask: cancellation is uniform ═══════════════════════════════════════════

def test_ask_returns_the_answer():
    assert em._ask(Stub("hello")) == "hello"


def test_ask_turns_ctrl_c_into_none():
    assert em._ask(Stub(raises=KeyboardInterrupt)) is None


# ══ model selection ═════════════════════════════════════════════════════════

@pytest.mark.parametrize("choice", ["GPT-4o", "Gemini", "Llama 3", "Mistral"])
def test_selecting_a_listed_model(monkeypatch, choice):
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub(choice))
    assert em._select_model() == choice


def test_custom_model_name_is_collected_and_trimmed(monkeypatch):
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub("Custom..."))
    monkeypatch.setattr(em.questionary, "text", lambda *a, **k: Stub("  MyModel  "))
    assert em._select_model() == "MyModel"


def test_cancelling_the_model_prompt(monkeypatch):
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub(None))
    assert em._select_model() is None


def test_cancelling_the_custom_name_prompt(monkeypatch):
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub("Custom..."))
    monkeypatch.setattr(em.questionary, "text", lambda *a, **k: Stub(None))
    assert em._select_model() is None


# ══ collecting the output ═══════════════════════════════════════════════════

def test_paste_path_hashes_the_typed_text(monkeypatch):
    lines = iter(["The capital of France", "is Paris.", ""])
    monkeypatch.setattr("builtins.input", lambda: next(lines))
    digest, source = em._paste_output()
    assert digest == hash_output("The capital of France\nis Paris.")
    assert source == "pasted text"


def test_paste_reprompts_on_empty_input(monkeypatch, capsys):
    lines = iter(["", "real content", ""])
    monkeypatch.setattr("builtins.input", lambda: next(lines))
    digest, _ = em._paste_output()
    assert digest == hash_output("real content")
    assert "cannot be empty" in out(capsys).lower()


def test_paste_handles_eof(monkeypatch):
    def eof():
        raise EOFError
    monkeypatch.setattr("builtins.input", eof)
    # EOF with nothing typed loops back; feed content on the second pass
    seq = iter([EOFError, "text", ""])

    def reader():
        v = next(seq)
        if v is EOFError:
            raise EOFError
        return v
    monkeypatch.setattr("builtins.input", reader)
    digest, _ = em._paste_output()
    assert digest == hash_output("text")


def test_paste_cancelled_returns_none(monkeypatch):
    def interrupt():
        raise KeyboardInterrupt
    monkeypatch.setattr("builtins.input", interrupt)
    assert em._paste_output() is None


def test_paste_strips_crlf(monkeypatch):
    """Windows / piped input must hash the same as unix input."""
    lines = iter(["line one\r", "line two\r", ""])
    monkeypatch.setattr("builtins.input", lambda: next(lines))
    digest, _ = em._paste_output()
    assert digest == hash_output("line one\nline two")


def test_file_path_hashes_raw_bytes(monkeypatch, tmp_path, capsys):
    f = tmp_path / "output.bin"
    f.write_bytes(b"\x00\x01binary\xff content")
    monkeypatch.setattr(em.questionary, "path", lambda *a, **k: Stub(str(f)))
    digest, source = em._hash_output_file()
    assert digest == sha256_file(f)
    assert "output.bin" in source
    assert "Hashed" in out(capsys)


def test_file_path_cancelled(monkeypatch):
    monkeypatch.setattr(em.questionary, "path", lambda *a, **k: Stub(None))
    assert em._hash_output_file() is None


def test_collect_routes_to_paste(monkeypatch):
    monkeypatch.setattr(em.questionary, "select",
                        lambda *a, **k: Stub("Paste it here (short text)"))
    lines = iter(["hi", ""])
    monkeypatch.setattr("builtins.input", lambda: next(lines))
    assert em._collect_output()[1] == "pasted text"


def test_collect_routes_to_file(monkeypatch, tmp_path):
    f = tmp_path / "o.txt"
    f.write_text("data")
    monkeypatch.setattr(em.questionary, "select",
                        lambda *a, **k: Stub("Point to a file (any size / code / binary)"))
    monkeypatch.setattr(em.questionary, "path", lambda *a, **k: Stub(str(f)))
    assert "file:" in em._collect_output()[1]


def test_collect_cancelled(monkeypatch):
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub(None))
    assert em._collect_output() is None


# ══ signing - the regression that mattered ══════════════════════════════════

def test_wizard_receipts_are_current_version(rig):
    """Was pinned to "1.1", so the wizard silently skipped the v1.3 binding."""
    signer, log, _ = rig
    receipt, _ = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    assert receipt.receipt_version == "1.3"


def test_wizard_receipts_name_their_signing_key(rig):
    signer, log, _ = rig
    receipt, _ = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    assert receipt.signing_key_id == Receipt.key_id(signer.get_public_key())


def test_wizard_receipt_id_is_bound_by_the_signature(rig):
    signer, log, _ = rig
    receipt, _ = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    assert receipt.receipt_id in receipt.canonical_message()


def test_wizard_receipt_verifies(rig):
    signer, log, _ = rig
    receipt, _ = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    assert verify_receipt(receipt, signer.get_public_key()) is True


def test_wizard_writes_under_the_configured_home(rig, tmp_path):
    """Used a RECEIPTS_DIR frozen at import, ignoring AETHERPROOF_HOME."""
    signer, log, _ = rig
    _, path = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    assert path.parent == tmp_path / "home" / "receipts"
    assert path.exists()
    assert path.with_suffix(".pub").exists()


def test_wizard_is_honest_about_the_model_tier(rig):
    """A typed model name proves the CLAIM, never the weights."""
    signer, log, _ = rig
    receipt, _ = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    assert receipt.model_root_type == "name_only"
    assert receipt.model_weight_root == hash_output("GPT-4o")


def test_wizard_appends_to_the_shared_log(rig):
    signer, log, _ = rig
    for i in range(3):
        em._sign_and_log(signer, log, "GPT-4o", hash_output(f"answer {i}"))
    assert log.count() == 3
    assert log.verify_integrity(signer.get_public_key()) is True


def test_wizard_sequences_are_continuous(rig):
    signer, log, _ = rig
    seqs = [em._sign_and_log(signer, log, "GPT-4o", hash_output(f"a{i}"))[0].log_sequence
            for i in range(3)]
    assert seqs == [1, 2, 3]


def test_wizard_receipts_are_unique(rig):
    signer, log, _ = rig
    ids = {em._sign_and_log(signer, log, "GPT-4o", hash_output(f"a{i}"))[0].receipt_id
           for i in range(5)}
    assert len(ids) == 5


def test_signing_failure_writes_nothing_and_reports(rig, monkeypatch, capsys, tmp_path):
    signer, log, _ = rig

    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(em, "issue_receipt", boom)

    assert em._sign_and_log(signer, log, "GPT-4o", hash_output("answer")) is None
    text = out(capsys)
    assert "Signing failed" in text
    assert "Nothing was written" in text
    receipts = tmp_path / "home" / "receipts"
    assert not receipts.exists() or list(receipts.glob("*.json")) == []


def test_cancelling_mid_sign_writes_nothing(rig, monkeypatch, capsys):
    signer, log, _ = rig

    def interrupt(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(em, "issue_receipt", interrupt)

    assert em._sign_and_log(signer, log, "GPT-4o", hash_output("answer")) is None
    assert "Nothing was written" in out(capsys)


# ══ the whole wizard, end to end ════════════════════════════════════════════

def test_full_wizard_run(rig, monkeypatch, capsys, tmp_path):
    signer, log, _ = rig
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub("GPT-4o"))
    lines = iter(["The capital of France is Paris.", ""])
    monkeypatch.setattr("builtins.input", lambda: next(lines))
    monkeypatch.setattr(em, "_collect_output",
                        lambda: (hash_output("The capital of France is Paris."), "pasted text"))
    monkeypatch.setattr(em, "_post_action", lambda receipt, path: None)

    em.run_easy_mode(signer, log)

    assert log.count() == 1
    receipts = list((tmp_path / "home" / "receipts").glob("*.json"))
    assert len(receipts) == 1
    r = Receipt.from_json(receipts[0].read_text(encoding="utf-8"))
    assert verify_receipt(r, signer.get_public_key()) is True


def test_wizard_cancelled_at_model_selection(rig, monkeypatch, capsys):
    signer, log, _ = rig
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub(None))
    em.run_easy_mode(signer, log)
    assert "Cancelled" in out(capsys)
    assert log.count() == 0


def test_wizard_cancelled_at_output_collection(rig, monkeypatch, capsys):
    signer, log, _ = rig
    monkeypatch.setattr(em, "_select_model", lambda: "GPT-4o")
    monkeypatch.setattr(em, "_collect_output", lambda: None)
    em.run_easy_mode(signer, log)
    assert "Cancelled" in out(capsys)
    assert log.count() == 0


def test_wizard_stops_cleanly_when_signing_fails(rig, monkeypatch, capsys):
    signer, log, _ = rig
    monkeypatch.setattr(em, "_select_model", lambda: "GPT-4o")
    monkeypatch.setattr(em, "_collect_output", lambda: (hash_output("x"), "pasted text"))
    monkeypatch.setattr(em, "_sign_and_log", lambda *a: None)
    em.run_easy_mode(signer, log)     # must return, not raise


# ══ success panel and follow-up ═════════════════════════════════════════════

def test_success_panel_shows_the_receipt(rig, capsys):
    signer, log, _ = rig
    receipt, path = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    capsys.readouterr()
    em._show_success(receipt, "GPT-4o", path)
    text = out(capsys)
    assert receipt.receipt_id in text


def test_inline_verify_confirms_a_good_receipt(rig, capsys):
    signer, log, _ = rig
    _, path = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    capsys.readouterr()
    em._inline_verify(path)
    assert "VALID" in out(capsys).upper()


def test_inline_inspect_lists_fields(rig, capsys):
    signer, log, _ = rig
    receipt, _ = em._sign_and_log(signer, log, "GPT-4o", hash_output("answer"))
    capsys.readouterr()
    em._inline_inspect(receipt)
    assert "output_hash" in out(capsys)


# ══ config: the remembered public key ═══════════════════════════════════════

def test_config_file_follows_the_configured_home(tmp_path):
    assert em._config_file() == tmp_path / "home" / "config.json"


def test_last_pubkey_is_empty_before_anything_is_saved():
    assert em._last_pubkey() == ""


def test_saving_and_reading_back_the_last_pubkey(tmp_path):
    p = tmp_path / "some.pub"
    p.write_bytes(Signer.generate().get_public_key().export_public_pem())
    em._save_last_pubkey(p)
    assert em._last_pubkey() == str(p)


def test_last_pubkey_survives_a_corrupt_config(tmp_path):
    cfg = em._config_file()
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text("{not json", encoding="utf-8")
    assert em._last_pubkey() == ""


# ══ the path validator ══════════════════════════════════════════════════════

def test_path_validator_accepts_an_existing_file(tmp_path):
    f = tmp_path / "f.txt"
    f.write_text("x")

    class Doc:
        text = str(f)

    em.PathValidator(is_file=True).validate(Doc())      # must not raise


def test_path_validator_rejects_a_missing_file(tmp_path):
    from questionary import ValidationError

    class Doc:
        text = str(tmp_path / "missing.txt")

    with pytest.raises(ValidationError):
        em.PathValidator(is_file=True).validate(Doc())


def test_path_validator_rejects_empty_input():
    from questionary import ValidationError

    class Doc:
        text = "   "

    with pytest.raises(ValidationError):
        em.PathValidator(is_file=True).validate(Doc())
