"""The expert-mode command surface, driven in-process.

`test_cli_paths.py` drives the same commands through a real subprocess, which is
the honest integration check but is invisible to coverage and slow. These call
the command functions directly, so every branch - usage errors, missing files,
bad formats, unknown subcommands - is actually exercised and measured.

Between them: inspect, log list/verify/count, keygen, export json/hex/cbor, and
tamper had NO tests of any kind before this file.
"""

import json
from pathlib import Path

import pytest

from aetherproof.core.log import ReceiptLog
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.ui import expert_mode as em


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Point the whole keystore at a temp dir so nothing touches the real home."""
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)
    yield


@pytest.fixture
def files(tmp_path):
    (tmp_path / "model.bin").write_text("fake weights")
    (tmp_path / "answer.txt").write_text("The capital of France is Paris.")
    (tmp_path / "prompt.txt").write_text("What is the capital of France?")
    return tmp_path


def out(capsys):
    """stdout only - the data channel."""
    return capsys.readouterr().out


def both(capsys):
    """stdout + stderr. Human-readable errors and the banner go to stderr."""
    cap = capsys.readouterr()
    return cap.out + cap.err


def sign(files, *extra):
    assert em.cmd_sign([str(files / "model.bin"), str(files / "answer.txt"),
                        *extra, "--quiet"]) is True


def latest_receipt(tmp_path):
    return max((tmp_path / "home" / "receipts").glob("*.json"),
               key=lambda p: p.stat().st_mtime)


# ══ dispatch ════════════════════════════════════════════════════════════════

def test_no_args_shows_help(capsys):
    assert em.run_expert_mode([]) is True
    assert "EXPERT MODE COMMANDS" in out(capsys)


@pytest.mark.parametrize("flag", ["-h", "--help", "help"])
def test_help_flags(capsys, flag):
    assert em.run_expert_mode([flag]) is True
    assert "EXPERT MODE COMMANDS" in out(capsys)


def test_unknown_command_fails_and_shows_help(capsys):
    assert em.run_expert_mode(["frobnicate"]) is False
    text = both(capsys)
    assert "Unknown command" in text
    assert "EXPERT MODE COMMANDS" in text


def test_an_exception_inside_a_command_is_reported_not_raised(capsys, monkeypatch):
    def boom(_args):
        raise RuntimeError("internal explosion")
    monkeypatch.setattr(em, "cmd_sign", boom)
    assert em.run_expert_mode(["sign", "x", "y"]) is False
    assert "internal explosion" in both(capsys)


def test_help_documents_the_optional_model(capsys):
    em.run_expert_mode(["--help"])
    text = out(capsys)
    assert "OPTIONAL" in text
    assert "--input" in text


# ══ sign ════════════════════════════════════════════════════════════════════

def test_sign_with_no_args_reports_usage(capsys):
    assert em.cmd_sign(["--quiet"]) is False
    assert "usage" in json.loads(out(capsys))["error"]


def test_sign_missing_output_file(capsys, files):
    assert em.cmd_sign([str(files / "nope.txt"), "--quiet"]) is False
    assert "Output file not found" in json.loads(out(capsys))["error"]


def test_sign_missing_model_file(capsys, files):
    assert em.cmd_sign([str(files / "nomodel.bin"), str(files / "answer.txt"),
                        "--quiet"]) is False
    assert "Model not found" in json.loads(out(capsys))["error"]


def test_sign_missing_input_file(capsys, files):
    assert em.cmd_sign([str(files / "answer.txt"), "--input",
                        str(files / "nope.txt"), "--quiet"]) is False
    assert "Input file not found" in json.loads(out(capsys))["error"]


def test_sign_quiet_emits_parseable_json(capsys, files):
    sign(files)
    r = json.loads(out(capsys))
    assert r["receipt_version"] == "1.3"
    assert r["model_root_type"] == "artifact_hash"


def test_sign_verbose_prints_a_panel_and_next_step(capsys, files):
    assert em.cmd_sign([str(files / "model.bin"), str(files / "answer.txt")]) is True
    text = out(capsys)
    assert "RECEIPT SIGNED" in text
    assert "Verify with" in text


def test_sign_reports_a_signing_failure(capsys, files, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(em, "issue_receipt", boom)
    assert em.cmd_sign([str(files / "answer.txt"), "--quiet"]) is False
    assert "Signing failed" in json.loads(out(capsys))["error"]


# ══ verify ══════════════════════════════════════════════════════════════════

def test_verify_with_no_args_reports_usage(capsys):
    assert em.cmd_verify(["--quiet"]) is False
    assert json.loads(out(capsys))["valid"] is False


def test_verify_missing_receipt(capsys, tmp_path):
    assert em.cmd_verify([str(tmp_path / "nope.json"), "--quiet"]) is False
    assert "not found" in json.loads(out(capsys))["error"].lower()


def test_verify_valid_receipt(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    assert em.cmd_verify([str(latest_receipt(tmp_path)), "--quiet"]) is True
    assert json.loads(out(capsys))["valid"] is True


def test_verify_with_matching_output_file(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    assert em.cmd_verify([str(latest_receipt(tmp_path)), "--output",
                          str(files / "answer.txt"), "--quiet"]) is True
    res = json.loads(out(capsys))
    assert res["valid"] is True and res["output_unmodified"] is True


def test_verify_detects_a_modified_output_file(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    (files / "answer.txt").write_text("The capital of France is Berlin.")
    assert em.cmd_verify([str(latest_receipt(tmp_path)), "--output",
                          str(files / "answer.txt"), "--quiet"]) is False
    assert json.loads(out(capsys))["valid"] is False


def test_verify_verbose_prints_a_human_verdict(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    em.cmd_verify([str(latest_receipt(tmp_path))])
    assert "VALID" in out(capsys)


def test_verify_with_an_explicit_wrong_pubkey(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    other = tmp_path / "other.pub"
    other.write_bytes(Signer.generate().get_public_key().export_public_pem())
    assert em.cmd_verify([str(latest_receipt(tmp_path)), "--pubkey", str(other),
                          "--quiet"]) is False


def test_verify_with_a_missing_output_file(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    assert em.cmd_verify([str(latest_receipt(tmp_path)), "--output",
                          str(files / "gone.txt"), "--quiet"]) is False


# ══ inspect (previously untested) ═══════════════════════════════════════════

def test_inspect_shows_every_field(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    assert em.cmd_inspect([str(latest_receipt(tmp_path))]) is True
    text = out(capsys)
    for field in ("receipt_version", "output_hash", "signing_key_id", "log_anchor"):
        assert field in text


def test_inspect_with_no_args(capsys):
    assert em.cmd_inspect([]) is False
    assert "usage" in both(capsys).lower()


def test_inspect_missing_file(capsys, tmp_path):
    """Returned None unconditionally, so `inspect missing.json && deploy` ran."""
    assert em.cmd_inspect([str(tmp_path / "nope.json")]) is False
    assert "not found" in both(capsys).lower()


def test_inspect_unparseable_receipt(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert em.cmd_inspect([str(bad)]) is False
    assert "parse" in both(capsys).lower()


# ══ log (previously untested) ═══════════════════════════════════════════════

def test_log_count_reflects_signings(capsys, files):
    sign(files)
    sign(files)
    capsys.readouterr()
    assert em.cmd_log(["count"]) is True
    assert "2" in out(capsys)


def test_log_list_shows_the_entries(capsys, files):
    sign(files)
    capsys.readouterr()
    assert em.cmd_log(["list"]) is True
    assert "Sequence" in out(capsys)


def test_log_list_when_empty(capsys):
    em.cmd_log(["list"])
    assert out(capsys).strip() != ""


def test_log_verify_passes_on_an_untouched_log(capsys, files):
    sign(files)
    capsys.readouterr()
    assert em.cmd_log(["verify"]) is True


def test_log_verify_fails_on_a_tampered_log(capsys, files, tmp_path):
    import sqlite3
    sign(files)
    sign(files)
    capsys.readouterr()
    db = tmp_path / "home" / "log.db"
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM receipts WHERE sequence = 1")
    conn.commit()
    conn.close()
    assert em.cmd_log(["verify"]) is False


def test_log_with_no_subcommand(capsys):
    assert em.cmd_log([]) is False
    assert "usage" in both(capsys).lower()


def test_log_with_an_unknown_subcommand(capsys):
    assert em.cmd_log(["frobnicate"]) is False


# ══ keygen (previously untested) ════════════════════════════════════════════

def test_keygen_writes_a_usable_pair(capsys, tmp_path):
    assert em.cmd_keygen(["--output", str(tmp_path / "mykey")]) is True
    priv = tmp_path / "mykey.pem"
    pub = tmp_path / "mykey.pub"
    assert priv.exists() and pub.exists()

    from aetherproof.core.signer import Signer as S, Verifier as V
    s = S.from_private_file(str(priv))
    v = V.from_public_file(str(pub))
    assert v.verify(b"msg", s.sign(b"msg")) is True


def test_keygen_default_name(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert em.cmd_keygen([]) is True
    assert list(tmp_path.glob("*.pem"))


def test_keygen_reports_an_unwritable_destination(capsys, tmp_path):
    assert em.cmd_keygen(["--output", str(tmp_path / "no" / "such" / "dir" / "k")]) is False
    assert "could not write" in both(capsys).lower()


def test_keygen_reports_where_it_wrote(capsys, tmp_path):
    em.cmd_keygen(["--output", str(tmp_path / "k")])
    assert "k" in out(capsys)


# ══ export (previously untested) ════════════════════════════════════════════

def test_export_json(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    em.cmd_export([str(latest_receipt(tmp_path)), "--format", "json"])
    assert json.loads(out(capsys).strip())["receipt_version"] == "1.3"


def test_export_hex_round_trips_to_the_original_receipt(capsys, files, tmp_path):
    """hex used to print "(not yet implemented)" and exit 0 while the help
    advertised it as a working format."""
    sign(files)
    capsys.readouterr()
    assert em.cmd_export([str(latest_receipt(tmp_path)), "--format", "hex"]) is True
    blob = "".join(out(capsys).split())
    decoded = bytes.fromhex(blob).decode("utf-8")
    assert json.loads(decoded)["receipt_version"] == "1.3"


def test_export_hex_reconstructs_a_verifiable_receipt(capsys, files, tmp_path):
    from aetherproof.core.signer import Verifier
    from aetherproof.core.verifier import verify_receipt
    sign(files)
    capsys.readouterr()
    em.cmd_export([str(latest_receipt(tmp_path)), "--format", "hex"])
    blob = "".join(out(capsys).split())
    r = Receipt.from_json(bytes.fromhex(blob).decode("utf-8"))
    pub = Verifier.from_public_file(
        str(latest_receipt(tmp_path).with_suffix(".pub")))
    assert verify_receipt(r, pub) is True


def test_cbor_is_no_longer_advertised(capsys):
    """It printed a dim note and exited 0 - worse than not offering it."""
    em.show_help()
    assert "cbor" not in out(capsys).lower()


def test_export_unknown_format_is_rejected(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    assert em.cmd_export([str(latest_receipt(tmp_path)), "--format", "cbor"]) is False
    assert "format" in both(capsys).lower()


def test_export_with_no_args(capsys):
    assert em.cmd_export([]) is False
    assert "usage" in both(capsys).lower()


def test_export_missing_file(capsys, tmp_path):
    assert em.cmd_export([str(tmp_path / "nope.json"), "--format", "json"]) is False
    assert "not found" in both(capsys).lower()


def test_export_unparseable_receipt(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert em.cmd_export([str(bad), "--format", "json"]) is False
    assert "parse" in both(capsys).lower()


# ══ tamper (previously untested) ════════════════════════════════════════════

def test_tamper_probe_passes_on_a_real_receipt(capsys, files, tmp_path):
    sign(files)
    capsys.readouterr()
    assert em.cmd_tamper([str(latest_receipt(tmp_path))]) is True


def test_tamper_with_no_args(capsys):
    assert em.cmd_tamper([]) is False
    assert "usage" in both(capsys).lower()


def test_tamper_missing_file(capsys, tmp_path):
    assert em.cmd_tamper([str(tmp_path / "nope.json")]) is False


# ══ option parsing ══════════════════════════════════════════════════════════

def test_pop_quiet_removes_every_occurrence():
    args, quiet = em._pop_quiet(["a", "--quiet", "b"])
    assert args == ["a", "b"] and quiet is True
    args, quiet = em._pop_quiet(["a"])
    assert args == ["a"] and quiet is False


def test_extract_opt_pulls_flag_and_value():
    args, val = em._extract_opt(["x", "--input", "f.txt", "y"], "--input")
    assert args == ["x", "y"] and val == "f.txt"


def test_extract_opt_absent_flag():
    args, val = em._extract_opt(["x"], "--input")
    assert args == ["x"] and val is None


def test_extract_opt_flag_with_no_value():
    args, val = em._extract_opt(["x", "--input"], "--input")
    assert val is None
