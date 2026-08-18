"""The central claim, demonstrated end to end: no AetherProof code required.

`test_readme_verifier.py` checks the documented procedure against in-memory
receipts. That is necessary but not the whole claim. The claim is stronger:

    a receipt produced by the REAL CLI can be verified by a party who does not
    have AetherProof at all - only a standard crypto library.

So these tests do both halves for real:
  * the receipt is produced by running `python -m aetherproof sign` as a
    subprocess, not by calling the library;
  * the verifier runs in a subprocess where importing `aetherproof` is BLOCKED,
    so it cannot accidentally lean on the implementation it is meant to be
    independent of.

Marked `slow` because each test spawns two subprocesses. A stronger variant that
builds a clean virtualenv with only `cryptography` is gated behind
AETHERPROOF_TEST_VENV=1 - it needs network access, so it is opt-in rather than a
default CI dependency.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# Verifier source. Imports ONLY stdlib + cryptography, and asserts up front that
# aetherproof cannot be imported - so a passing run is proof of independence,
# not just of correctness.
VERIFIER = textwrap.dedent(r'''
    import sys, importlib.abc, importlib.machinery

    class Blocker(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if fullname == "aetherproof" or fullname.startswith("aetherproof."):
                raise ImportError(f"BLOCKED: {fullname}")
            return None

    sys.meta_path.insert(0, Blocker())
    try:
        import aetherproof
        sys.exit("FAIL: aetherproof was importable")
    except ImportError:
        pass

    import json, hashlib
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    r = json.load(open(sys.argv[1], encoding="utf-8"))
    pub = load_pem_public_key(open(sys.argv[2], "rb").read())

    fields = [
        r["receipt_version"], r["model_weight_root"], r["model_root_type"],
        r["input_commitment"], r["output_hash"], str(r["timestamp_ms"]),
        str(r["log_sequence"]),
        json.dumps(r["hw_evidence"], sort_keys=True, separators=(",", ":")),
        r["log_anchor"],
    ]
    if r["receipt_version"] not in ("1.0", "1.1", "1.2"):
        fields += [r["receipt_id"], r["signing_key_id"]]
    if r.get("signed_extensions"):
        def canon(o):
            return json.dumps(o, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        leaves = sorted(hashlib.sha256(canon(ns) + canon(b)).hexdigest()
                        for ns, b in r["signed_extensions"].items())
        fields.append("sha256:" + hashlib.sha256("".join(leaves).encode()).hexdigest())

    pub.verify(bytes.fromhex(r["signature"]),
               "".join(f"{len(f)}:{f}" for f in fields).encode("utf-8"))
    print("SIGNATURE_VALID")

    if len(sys.argv) > 3:
        digest = hashlib.sha256(open(sys.argv[3], "rb").read()).hexdigest()
        print("OUTPUT_UNMODIFIED" if digest == r["output_hash"] else "OUTPUT_CHANGED")
''')

pytestmark = pytest.mark.slow


@pytest.fixture
def rig(tmp_path):
    """A receipt produced by the real CLI, plus an independent verifier script."""
    home = tmp_path / "home"
    (tmp_path / "question.txt").write_text("What was our Q3 refund policy?\n",
                                           encoding="utf-8")
    (tmp_path / "answer.txt").write_text(
        "Refunds were accepted within 30 days with a receipt.\n", encoding="utf-8")

    env = dict(os.environ)
    env.update(AETHERPROOF_HOME=str(home), PYTHONPATH=str(REPO),
               PYTHONIOENCODING="utf-8")
    env.pop("AETHERPROOF_KEY_PASSPHRASE", None)

    r = subprocess.run(
        [sys.executable, "-m", "aetherproof", "sign", str(tmp_path / "answer.txt"),
         "--input", str(tmp_path / "question.txt"), "--quiet"],
        capture_output=True, text=True, encoding="utf-8", env=env,
        cwd=str(tmp_path), timeout=120)
    assert r.returncode == 0, f"CLI sign failed: {r.stderr}"

    receipt = next((home / "receipts").glob("*.json"))
    verifier = tmp_path / "independent_verify.py"
    verifier.write_text(VERIFIER, encoding="utf-8")
    return tmp_path, receipt, receipt.with_suffix(".pub"), verifier


def verify(rig, receipt=None, output=None):
    tmp_path, default_receipt, pub, verifier = rig
    args = [sys.executable, str(verifier), str(receipt or default_receipt), str(pub)]
    if output:
        args.append(str(output))
    # No PYTHONPATH: the verifier must not reach the repo, and the import
    # blocker stops it reaching a pip-installed copy either.
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=str(tmp_path.parent),
                          timeout=120)


# ══ the claim ═══════════════════════════════════════════════════════════════

def test_a_real_cli_receipt_verifies_without_aetherproof(rig):
    p = verify(rig)
    assert p.returncode == 0, p.stderr
    assert "SIGNATURE_VALID" in p.stdout


def test_the_output_file_is_confirmed_unmodified(rig):
    tmp_path, _, _, _ = rig
    p = verify(rig, output=tmp_path / "answer.txt")
    assert "SIGNATURE_VALID" in p.stdout
    assert "OUTPUT_UNMODIFIED" in p.stdout


def test_an_edited_output_is_detected_but_the_receipt_still_verifies(rig):
    """These are different facts and must not be conflated: the receipt is
    authentic, the file no longer matches it."""
    tmp_path, _, _, _ = rig
    (tmp_path / "answer.txt").write_text(
        "Refunds were accepted within 60 days with a receipt.\n", encoding="utf-8")
    p = verify(rig, output=tmp_path / "answer.txt")
    assert p.returncode == 0
    assert "SIGNATURE_VALID" in p.stdout
    assert "OUTPUT_CHANGED" in p.stdout


def test_an_edited_receipt_is_rejected(rig):
    tmp_path, receipt, _, _ = rig
    d = json.loads(receipt.read_text(encoding="utf-8"))
    d["output_hash"] = "f" * 64
    bad = tmp_path / "tampered.json"
    bad.write_text(json.dumps(d), encoding="utf-8")
    p = verify(rig, receipt=bad)
    assert p.returncode != 0
    assert "InvalidSignature" in p.stderr


@pytest.mark.parametrize("field,value", [
    ("receipt_id", "ap_00000000"),
    ("signing_key_id", "dead" * 4),
    ("model_weight_root", "f" * 64),
    ("input_commitment", "e" * 64),
    ("timestamp_ms", 1),
    ("log_sequence", 999),
    ("log_anchor", "local://log/999"),
])
def test_every_signed_field_is_rejected_when_rewritten(rig, field, value):
    """receipt_id and signing_key_id are the v1.3 additions - proving they are
    bound end to end, through the real CLI and an outside verifier."""
    tmp_path, receipt, _, _ = rig
    d = json.loads(receipt.read_text(encoding="utf-8"))
    d[field] = value
    bad = tmp_path / f"bad_{field}.json"
    bad.write_text(json.dumps(d), encoding="utf-8")
    p = verify(rig, receipt=bad)
    assert p.returncode != 0, f"{field} was not bound"
    assert "InvalidSignature" in p.stderr


def test_a_different_public_key_is_rejected(rig, tmp_path):
    from aetherproof.core.signer import Signer
    work, receipt, _, verifier = rig
    other = work / "other.pub"
    other.write_bytes(Signer.generate().get_public_key().export_public_pem())
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONIOENCODING"] = "utf-8"
    p = subprocess.run([sys.executable, str(verifier), str(receipt), str(other)],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, timeout=120)
    assert p.returncode != 0


def test_the_verifier_really_cannot_import_aetherproof(rig):
    """If the blocker ever stopped working these tests would silently become
    a check of the implementation against itself."""
    tmp_path, _, _, verifier = rig
    probe = tmp_path / "probe.py"
    probe.write_text(VERIFIER.split("import json, hashlib")[0] +
                     '\nprint("BLOCKED_OK")\n', encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    p = subprocess.run([sys.executable, str(probe)], capture_output=True,
                       text=True, encoding="utf-8", env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    assert "BLOCKED_OK" in p.stdout


# ══ the CLI must never hang without a terminal ══════════════════════════════

@pytest.mark.parametrize("argv,expected", [
    (["--help"], 0),
    ([], 2),                                    # menu guard, no TTY
    (["sign", "--quiet"], 1),                   # usage error
    (["verify", "nope.json", "--quiet"], 1),    # missing file
    (["log", "count"], 0),
])
def test_cli_completes_without_a_terminal(tmp_path, argv, expected):
    """Piped / redirected / CI contexts have no TTY. A hang here would look
    like a lockup with no explanation."""
    env = dict(os.environ)
    env.update(AETHERPROOF_HOME=str(tmp_path / "home"), PYTHONPATH=str(REPO),
               PYTHONIOENCODING="utf-8")
    env.pop("AETHERPROOF_KEY_PASSPHRASE", None)
    p = subprocess.run([sys.executable, "-m", "aetherproof", *argv],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, cwd=str(tmp_path),
                       stdin=subprocess.DEVNULL, timeout=60)
    assert p.returncode == expected, f"{argv} -> {p.returncode}\n{p.stderr}"


def test_bare_command_without_a_tty_explains_itself(tmp_path):
    env = dict(os.environ)
    env.update(AETHERPROOF_HOME=str(tmp_path / "home"), PYTHONPATH=str(REPO),
               PYTHONIOENCODING="utf-8")
    p = subprocess.run([sys.executable, "-m", "aetherproof"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, cwd=str(tmp_path),
                       stdin=subprocess.DEVNULL, timeout=60)
    assert p.returncode == 2
    text = p.stdout + p.stderr
    assert "interactive terminal" in text
    assert "--help" in text


# ══ opt-in: a real clean virtualenv (needs network) ═════════════════════════

@pytest.mark.skipif(os.environ.get("AETHERPROOF_TEST_VENV") != "1",
                    reason="set AETHERPROOF_TEST_VENV=1 (installs cryptography)")
def test_verifies_in_a_clean_virtualenv(rig, tmp_path):
    """The strongest form: a separate interpreter that has never seen
    aetherproof, with only `cryptography` installed."""
    work, receipt, pub, verifier = rig
    venv = tmp_path / "cleanenv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                   capture_output=True, timeout=300)
    vpy = venv / ("Scripts" if os.name == "nt" else "bin") / (
        "python.exe" if os.name == "nt" else "python")
    subprocess.run([str(vpy), "-m", "pip", "install", "-q",
                    "--disable-pip-version-check", "cryptography"],
                   check=True, capture_output=True, timeout=600)

    # cwd MUST be outside the repo: python puts the working directory on
    # sys.path, so running this from the repo root would find aetherproof/
    # there and the "clean" venv would not be clean at all.
    outside = tmp_path
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}

    probe = subprocess.run(
        [str(vpy), "-c",
         "import importlib.util as u; print(u.find_spec('aetherproof') is None)"],
        capture_output=True, text=True, cwd=str(outside), env=env, timeout=60)
    assert probe.stdout.strip() == "True", f"venv is not clean: {probe.stdout!r}"

    p = subprocess.run([str(vpy), str(verifier), str(receipt), str(pub),
                        str(work / "answer.txt")],
                       capture_output=True, text=True, encoding="utf-8",
                       cwd=str(outside), env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    assert "SIGNATURE_VALID" in p.stdout
    assert "OUTPUT_UNMODIFIED" in p.stdout
