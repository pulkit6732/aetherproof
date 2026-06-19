"""Security/CI regression tests — CLI exit-code contract.

A verification or signing FAILURE must exit non-zero so shell pipelines and CI
gates catch it. Bug D: `sign` with missing args exited 0, so
`aetherproof sign && echo ok` falsely reported success.

These run the CLI as a subprocess — the real contract a CI script sees.
"""

import subprocess
import sys

import pytest


def _run(*args):
    # force UTF-8 decode: the banner contains box-drawing chars that the Windows
    # default (cp1252) can't decode, which would otherwise crash the reader thread.
    return subprocess.run(
        [sys.executable, "-m", "aetherproof", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    ).returncode


@pytest.mark.parametrize("args,expected", [
    (("sign", "--quiet"), 1),                 # Bug D: missing args
    (("sign", "/no/model", "/no/out"), 1),    # missing files
    (("verify", "--quiet"), 1),               # missing receipt
    (("verify", "/nope.json", "--quiet"), 1), # nonexistent receipt
    (("frobnicate",), 1),                     # unknown command
    (("log", "wat"), 1),                      # unknown subcommand
    (("tamper", "/nope.json"), 1),            # missing receipt
])
def test_failures_exit_nonzero(args, expected):
    assert _run(*args) == expected


def test_help_exits_zero():
    # --help is the scriptable help path and must succeed.
    # (Bare `aetherproof` launches the interactive menu, which needs a real TTY;
    # it is intentionally not exercised here.)
    assert _run("--help") == 0
    assert _run("help") == 0
    assert _run("-h") == 0


def test_sign_then_verify_roundtrip_exit_codes(tmp_path):
    """Happy path: sign exits 0, verify of the result exits 0, verify of a
    mutated output exits 1."""
    model = tmp_path / "m.bin"; model.write_bytes(b"weights")
    out = tmp_path / "o.txt"; out.write_text("the output")

    sign = subprocess.run(
        [sys.executable, "-m", "aetherproof", "sign", str(model), str(out), "--quiet"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert sign.returncode == 0
    import json
    receipt_id = json.loads(sign.stdout)["receipt_id"]

    from pathlib import Path
    rcpt = Path.home() / ".aetherproof" / "receipts" / f"{receipt_id}.json"
    assert _run("verify", str(rcpt), "--output", str(out), "--quiet") == 0

    out.write_text("the output TAMPERED")
    assert _run("verify", str(rcpt), "--output", str(out), "--quiet") == 1
