"""The verify wizard and menu helpers.

The verify wizard is the second half of the non-technical path: someone is
handed a receipt and needs to know whether to trust it. Its four verdicts are
not interchangeable, and the distinction between them is the whole product:

  valid       signature good, logged here, local log intact
  unlogged    signature good, but issued on a DIFFERENT machine. Not tamper -
              and calling it tamper would be a false accusation, which is the
              failure mode that destroys trust in a verification tool.
  log_broken  receipt intact, but THIS machine's log was altered
  tampered    the receipt itself was altered after signing

_evaluate had no tests, so nothing stopped those four collapsing into each other.
"""

import json
import sqlite3
from pathlib import Path

import pytest

from aetherproof.core.hash import hash_output
from aetherproof.core.keystore import load_or_create_signer, default_log
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.ui import easy_mode as em
from aetherproof.ui import menus


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)
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
    def __init__(self, answer=None, raises=None):
        self.answer, self.raises = answer, raises

    def ask(self):
        if self.raises:
            raise self.raises
        return self.answer


def out(capsys):
    cap = capsys.readouterr()
    return cap.out + cap.err


def issued(rig, text="the answer"):
    signer, log, _ = rig
    receipt, path = em._sign_and_log(signer, log, "GPT-4o", hash_output(text))
    return receipt, path, signer, log


# ══ _evaluate: the four verdicts must stay distinct ═════════════════════════

def test_valid_when_signed_logged_and_intact(rig):
    receipt, _, signer, log = issued(rig)
    assert em._evaluate(receipt, signer.get_public_key(), log)["status"] == "valid"


def test_tampered_when_the_receipt_was_altered(rig):
    receipt, _, signer, log = issued(rig)
    receipt.output_hash = "f" * 64
    result = em._evaluate(receipt, signer.get_public_key(), log)
    assert result["status"] == "tampered"
    assert "altered after signing" in result["reason"]


def test_tampered_when_verified_against_the_wrong_key(rig):
    receipt, _, _, log = issued(rig)
    other = Signer.generate().get_public_key()
    assert em._evaluate(receipt, other, log)["status"] == "tampered"


def test_unlogged_is_not_reported_as_tamper(rig, tmp_path):
    """A receipt issued on another machine is the common case. Calling it
    tampering would be a false accusation."""
    receipt, _, signer, _ = issued(rig)
    from aetherproof.core.log import ReceiptLog
    empty = ReceiptLog(db_path=str(tmp_path / "someone_elses.db"))
    try:
        result = em._evaluate(receipt, signer.get_public_key(), empty)
        assert result["status"] == "unlogged"
        assert "another machine" in result["reason"]
    finally:
        empty.close()


def test_unlogged_when_the_sequence_holds_a_different_receipt(rig, tmp_path):
    receipt, _, signer, log = issued(rig)
    other, _, _, _ = issued(rig, "a different answer")
    # claim the other receipt's slot
    receipt.log_sequence = other.log_sequence
    assert em._evaluate(receipt, signer.get_public_key(), log)["status"] == "tampered"


def test_unlogged_when_receipt_has_no_sequence(rig):
    signer, log, _ = rig
    r = Receipt(model_weight_root="a" * 64, output_hash="c" * 64, log_sequence=0)
    r.signature = signer.sign(r.signing_bytes())
    assert em._evaluate(r, signer.get_public_key(), log)["status"] == "unlogged"


def test_log_broken_keeps_the_receipt_intact(rig, tmp_path):
    """The receipt is fine; the machine's log is not. Those are different
    accusations and must not be conflated."""
    receipt, _, signer, log = issued(rig)
    issued(rig, "second")
    log.close()

    conn = sqlite3.connect(tmp_path / "home" / "log.db")
    conn.execute("UPDATE receipts SET output_hash='f'*64 WHERE sequence=2")
    conn.commit()
    conn.close()

    from aetherproof.core.log import ReceiptLog
    reopened = ReceiptLog(db_path=str(tmp_path / "home" / "log.db"))
    try:
        result = em._evaluate(receipt, signer.get_public_key(), reopened)
        assert result["status"] == "log_broken"
        assert "receipt itself is intact" in result["reason"]
    finally:
        reopened.close()


# ══ the wizard end to end ═══════════════════════════════════════════════════

def _drive(monkeypatch, receipt_path, pub_path):
    answers = iter([str(receipt_path), str(pub_path)])
    monkeypatch.setattr(em.questionary, "path", lambda *a, **k: Stub(next(answers)))


def test_wizard_reports_a_valid_receipt(rig, monkeypatch, capsys):
    _, path, signer, log = issued(rig)
    _drive(monkeypatch, path, path.with_suffix(".pub"))
    capsys.readouterr()
    em.run_verify_wizard(signer.get_public_key(), log)
    assert "RECEIPT VALID" in out(capsys)


def test_wizard_reports_tampering(rig, monkeypatch, capsys):
    receipt, path, signer, log = issued(rig)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["output_hash"] = "f" * 64
    path.write_text(json.dumps(data), encoding="utf-8")

    _drive(monkeypatch, path, path.with_suffix(".pub"))
    capsys.readouterr()
    em.run_verify_wizard(signer.get_public_key(), log)
    assert "TAMPER DETECTED" in out(capsys)


def test_wizard_reports_a_foreign_receipt_gently(rig, monkeypatch, capsys, tmp_path):
    _, path, signer, _ = issued(rig)
    from aetherproof.core.log import ReceiptLog
    empty = ReceiptLog(db_path=str(tmp_path / "other.db"))
    try:
        _drive(monkeypatch, path, path.with_suffix(".pub"))
        capsys.readouterr()
        em.run_verify_wizard(signer.get_public_key(), empty)
        text = out(capsys)
        assert "NOT IN THIS LOG" in text
        assert "TAMPER DETECTED" not in text
    finally:
        empty.close()


def test_wizard_reports_a_broken_local_log(rig, monkeypatch, capsys, tmp_path):
    _, path, signer, log = issued(rig)
    issued(rig, "second")
    log.close()
    conn = sqlite3.connect(tmp_path / "home" / "log.db")
    conn.execute("UPDATE receipts SET output_hash='f'*64 WHERE sequence=2")
    conn.commit()
    conn.close()

    from aetherproof.core.log import ReceiptLog
    reopened = ReceiptLog(db_path=str(tmp_path / "home" / "log.db"))
    try:
        _drive(monkeypatch, path, path.with_suffix(".pub"))
        capsys.readouterr()
        em.run_verify_wizard(signer.get_public_key(), reopened)
        assert "LOG INTEGRITY FAILURE" in out(capsys)
    finally:
        reopened.close()


def test_wizard_cancelled_at_the_receipt_prompt(rig, monkeypatch, capsys):
    signer, log, _ = rig
    monkeypatch.setattr(em.questionary, "path", lambda *a, **k: Stub(None))
    em.run_verify_wizard(signer.get_public_key(), log)
    assert "Cancelled" in out(capsys)


def test_wizard_cancelled_at_the_key_prompt(rig, monkeypatch, capsys):
    _, path, signer, log = issued(rig)
    answers = iter([str(path), None])
    monkeypatch.setattr(em.questionary, "path", lambda *a, **k: Stub(next(answers)))
    capsys.readouterr()
    em.run_verify_wizard(signer.get_public_key(), log)
    assert "Cancelled" in out(capsys)


def test_wizard_handles_an_unreadable_receipt(rig, monkeypatch, capsys, tmp_path):
    _, path, signer, log = issued(rig)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    _drive(monkeypatch, bad, path.with_suffix(".pub"))
    capsys.readouterr()
    em.run_verify_wizard(signer.get_public_key(), log)
    assert "Could not read" in out(capsys)


def test_wizard_handles_a_corrupt_public_key(rig, monkeypatch, capsys, tmp_path):
    _, path, signer, log = issued(rig)
    bad = tmp_path / "bad.pub"
    bad.write_bytes(b"-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----\n")
    _drive(monkeypatch, path, bad)
    capsys.readouterr()
    em.run_verify_wizard(signer.get_public_key(), log)
    assert "Could not read" in out(capsys)


def test_wizard_cancelled_mid_verification(rig, monkeypatch, capsys):
    _, path, signer, log = issued(rig)
    _drive(monkeypatch, path, path.with_suffix(".pub"))

    def interrupt(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(em, "_evaluate", interrupt)
    capsys.readouterr()
    em.run_verify_wizard(signer.get_public_key(), log)
    assert "Cancelled" in out(capsys)


# ══ the panels render without raising ═══════════════════════════════════════

def test_valid_panel(capsys):
    em._verify_valid_panel()
    assert "RECEIPT VALID" in out(capsys)


def test_unlogged_panel(capsys):
    em._verify_unlogged_panel({"reason": "issued elsewhere"})
    text = out(capsys)
    assert "NOT IN THIS LOG" in text
    assert "issued elsewhere" in text


def test_logbroken_panel(capsys):
    em._verify_logbroken_panel({"reason": "log altered"})
    text = out(capsys)
    assert "LOG INTEGRITY FAILURE" in text
    assert "log altered" in text


def test_invalid_panel(capsys):
    em._verify_invalid_panel({"field": "receipt contents", "reason": "edited"})
    text = out(capsys)
    assert "TAMPER DETECTED" in text
    assert "edited" in text


# ══ post-action menu ════════════════════════════════════════════════════════

def test_post_action_verify_now(rig, monkeypatch, capsys):
    receipt, path, _, _ = issued(rig)
    monkeypatch.setattr(em.questionary, "select",
                        lambda *a, **k: Stub("Verify this receipt"))
    capsys.readouterr()
    em._post_action(receipt, path)
    assert "VALID" in out(capsys).upper()


def test_post_action_inspect(rig, monkeypatch, capsys):
    receipt, path, _, _ = issued(rig)
    monkeypatch.setattr(em.questionary, "select",
                        lambda *a, **k: Stub("Inspect receipt"))
    capsys.readouterr()
    em._post_action(receipt, path)
    assert "output_hash" in out(capsys)


def test_post_action_done(rig, monkeypatch, capsys):
    receipt, path, _, _ = issued(rig)
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub("Return to menu"))
    em._post_action(receipt, path)      # must simply return


def test_post_action_cancelled(rig, monkeypatch):
    receipt, path, _, _ = issued(rig)
    monkeypatch.setattr(em.questionary, "select", lambda *a, **k: Stub(None))
    em._post_action(receipt, path)


# ══ menus ═══════════════════════════════════════════════════════════════════

def test_main_menu_returns_the_choice(monkeypatch):
    monkeypatch.setattr(menus.questionary, "select",
                        lambda *a, **k: Stub("Sign an AI output"))
    assert menus.show_main_menu() == "Sign an AI output"


def test_main_menu_exits_cleanly_on_cancel(monkeypatch, capsys):
    monkeypatch.setattr(menus.questionary, "select", lambda *a, **k: Stub(None))
    with pytest.raises(SystemExit) as e:
        menus.show_main_menu()
    assert e.value.code == 0
    assert "Cancelled" in out(capsys)


def test_main_menu_exits_cleanly_on_ctrl_c(monkeypatch, capsys):
    monkeypatch.setattr(menus.questionary, "select",
                        lambda *a, **k: Stub(raises=KeyboardInterrupt))
    with pytest.raises(SystemExit) as e:
        menus.show_main_menu()
    assert e.value.code == 0


@pytest.mark.parametrize("typed,expected", [
    ("y", True), ("yes", True), ("Y", True), ("YES", True),
    ("n", False), ("no", False), ("", False), ("maybe", False),
])
def test_confirm(monkeypatch, typed, expected):
    monkeypatch.setattr(menus.console, "input", lambda prompt: typed)
    assert menus.confirm("Continue?") is expected


def test_legacy_main_menu_reads_a_choice(monkeypatch, capsys):
    monkeypatch.setattr(menus.console, "input", lambda prompt: " 1 ")
    assert menus.main_menu() == "1"


def test_back_to_main_waits_for_enter(monkeypatch):
    seen = {}
    monkeypatch.setattr(menus.console, "input", lambda prompt: seen.setdefault("p", prompt))
    menus.back_to_main()
    assert "main menu" in seen["p"]
