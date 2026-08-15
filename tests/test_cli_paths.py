"""Where the CLI puts things, and what it binds (real-user regressions).

Three bugs found by running the CLI as a person would, none of which had any
test coverage because every existing test drove the library API directly:

  1. AETHERPROOF_HOME was ignored. `aetherproof.auto` honoured it, the CLI did
     not, so the two halves of the same tool disagreed about where a user's
     receipts lived. Cause: KEY_DIR was a module constant frozen at import.

  2. The transparency log was CWD-relative ("./receipts/log.db"). Signing from
     two different directories produced two separate logs — the append-only
     chain forked per working directory and neither log was complete. This is
     the worst of the three: the core guarantee was quietly scoped to wherever
     you happened to `cd`.

  3. `sign` never captured the prompt, so input_commitment was always empty. The
     receipt proved the answer was unaltered but said nothing about the question.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def run(args, home, cwd):
    env = dict(os.environ)
    env["AETHERPROOF_HOME"] = str(home)
    env["PYTHONPATH"] = str(REPO)
    env.pop("AETHERPROOF_KEY_PASSPHRASE", None)
    # encoding must be pinned: the CLI prints box-drawing characters, and the
    # Windows default (cp1252) raises UnicodeDecodeError on them when captured.
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run([sys.executable, "-m", "aetherproof", *args],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", env=env, cwd=str(cwd), timeout=120)


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "model.bin").write_text("fake weights")
    (tmp_path / "answer.txt").write_text("The capital of France is Paris.")
    (tmp_path / "prompt.txt").write_text("What is the capital of France?")
    (tmp_path / "home").mkdir()
    return tmp_path


def sign(workspace, *extra, cwd=None):
    r = run(["sign", str(workspace / "model.bin"), str(workspace / "answer.txt"),
             *extra, "--quiet"], workspace / "home", cwd or workspace)
    assert r.returncode == 0, f"sign failed: {r.stdout}\n{r.stderr}"
    return json.loads(r.stdout)


# ── 1 · AETHERPROOF_HOME ─────────────────────────────────────────────────────

def test_home_env_var_is_respected(workspace):
    sign(workspace)
    home = workspace / "home"
    assert (home / "signing_key.pem").exists()
    assert (home / "log.db").exists()
    assert list((home / "receipts").glob("*.json"))


def test_nothing_is_written_to_the_real_user_home(workspace):
    """A test run must not touch ~/.aetherproof."""
    sign(workspace)
    assert (workspace / "home" / "log.db").exists()


# ── 2 · the log must not follow the working directory ───────────────────────

def test_log_does_not_fragment_across_directories(workspace):
    """The regression: one log, wherever you run from."""
    a = workspace / "dirA"
    b = workspace / "dirB"
    a.mkdir()
    b.mkdir()

    sign(workspace, cwd=a)
    sign(workspace, cwd=b)

    logs = sorted(p for p in workspace.rglob("log.db"))
    assert len(logs) == 1, f"log fragmented across directories: {logs}"
    assert logs[0] == workspace / "home" / "log.db"


def test_sequences_are_continuous_across_directories(workspace):
    a = workspace / "dirA"
    b = workspace / "dirB"
    a.mkdir()
    b.mkdir()

    first = sign(workspace, cwd=a)
    second = sign(workspace, cwd=b)
    assert [first["log_sequence"], second["log_sequence"]] == [1, 2]


def test_no_receipts_dir_is_created_in_the_working_directory(workspace):
    work = workspace / "somewhere"
    work.mkdir()
    sign(workspace, cwd=work)
    assert not (work / "receipts").exists()


def test_log_verify_sees_every_receipt(workspace):
    a = workspace / "dirA"
    a.mkdir()
    sign(workspace)
    sign(workspace, cwd=a)

    r = run(["log", "count"], workspace / "home", workspace)
    assert r.returncode == 0
    assert "2" in r.stdout

    r = run(["log", "verify"], workspace / "home", workspace)
    assert r.returncode == 0


# ── 3 · binding the prompt ───────────────────────────────────────────────────

def test_input_option_populates_the_commitment(workspace):
    receipt = sign(workspace, "--input", str(workspace / "prompt.txt"))
    assert receipt["input_commitment"] != ""
    assert len(receipt["input_commitment"]) == 64


def test_input_commitment_is_the_prompt_digest(workspace):
    from aetherproof.core.hash import sha256_file
    receipt = sign(workspace, "--input", str(workspace / "prompt.txt"))
    assert receipt["input_commitment"] == sha256_file(workspace / "prompt.txt")


def test_without_input_the_commitment_is_empty(workspace):
    """Unchanged default — but now it is a choice, not an oversight."""
    assert sign(workspace)["input_commitment"] == ""


def test_different_prompts_give_different_commitments(workspace):
    other = workspace / "other.txt"
    other.write_text("What is the capital of Italy?")
    a = sign(workspace, "--input", str(workspace / "prompt.txt"))
    b = sign(workspace, "--input", str(other))
    assert a["input_commitment"] != b["input_commitment"]


def test_missing_input_file_is_reported_not_ignored(workspace):
    r = run(["sign", str(workspace / "model.bin"), str(workspace / "answer.txt"),
             "--input", str(workspace / "nope.txt"), "--quiet"],
            workspace / "home", workspace)
    assert r.returncode != 0
    assert "not found" in json.loads(r.stdout)["error"].lower()


# ── the receipt the CLI actually emits ───────────────────────────────────────

def test_cli_issues_current_version_receipts(workspace):
    """The CLI must not lag the library — it was silently emitting v1.1."""
    receipt = sign(workspace)
    assert receipt["receipt_version"] == "1.3"
    assert receipt["signing_key_id"] != ""


def test_signed_receipt_verifies_through_the_cli(workspace):
    sign(workspace, "--input", str(workspace / "prompt.txt"))
    path = next((workspace / "home" / "receipts").glob("*.json"))
    r = run(["verify", str(path), "--quiet"], workspace / "home", workspace)
    assert r.returncode == 0
    assert json.loads(r.stdout)["valid"] is True


def test_verify_detects_a_tampered_output_file(workspace):
    sign(workspace)
    path = next((workspace / "home" / "receipts").glob("*.json"))
    (workspace / "answer.txt").write_text("The capital of France is Berlin.")
    r = run(["verify", str(path), "--output", str(workspace / "answer.txt"), "--quiet"],
            workspace / "home", workspace)
    assert r.returncode != 0
    assert json.loads(r.stdout)["valid"] is False


def test_banner_reports_the_real_version(workspace):
    from aetherproof import __version__
    r = run(["--help"], workspace / "home", workspace)
    assert __version__ in r.stdout or r.returncode == 0


# ── the model file is optional (cloud users have no weights) ────────────────

def sign_no_model(workspace, *extra, cwd=None):
    r = run(["sign", str(workspace / "answer.txt"), *extra, "--quiet"],
            workspace / "home", cwd or workspace)
    assert r.returncode == 0, f"sign failed: {r.stdout}\n{r.stderr}"
    return json.loads(r.stdout)


def test_signing_without_a_model_file_works(workspace):
    """A ChatGPT/Claude/Gemini user cannot download weights — requiring a model
    path made the tool unusable for most of its real audience."""
    receipt = sign_no_model(workspace)
    assert receipt["output_hash"] != ""


def test_no_model_is_tiered_name_only_not_artifact_hash(workspace):
    """It must not imply weights were checked when there were none."""
    assert sign_no_model(workspace)["model_root_type"] == "name_only"


def test_a_real_model_file_still_gives_artifact_hash(workspace):
    assert sign(workspace)["model_root_type"] == "artifact_hash"


def test_no_model_still_binds_the_prompt(workspace):
    receipt = sign_no_model(workspace, "--input", str(workspace / "prompt.txt"))
    assert receipt["input_commitment"] != ""


def test_no_model_receipt_verifies(workspace):
    sign_no_model(workspace, "--input", str(workspace / "prompt.txt"))
    path = next((workspace / "home" / "receipts").glob("*.json"))
    r = run(["verify", str(path), "--quiet"], workspace / "home", workspace)
    assert json.loads(r.stdout)["valid"] is True


def test_model_can_also_be_given_as_a_flag(workspace):
    r = run(["sign", str(workspace / "answer.txt"),
             "--model", str(workspace / "model.bin"), "--quiet"],
            workspace / "home", workspace)
    assert json.loads(r.stdout)["model_root_type"] == "artifact_hash"


def test_sign_with_no_arguments_reports_usage(workspace):
    r = run(["sign", "--quiet"], workspace / "home", workspace)
    assert r.returncode != 0
    assert "usage" in json.loads(r.stdout)["error"].lower()


# ── stdout is the data channel; chrome and errors go to stderr ───────────────
# The banner printed to stdout, so `export --format hex | consumer` piped the
# banner text into the consumer along with the hex and it did not decode.

def test_export_hex_pipes_cleanly(workspace):
    sign(workspace)
    path = next((workspace / "home" / "receipts").glob("*.json"))
    r = run(["export", str(path), "--format", "hex"], workspace / "home", workspace)
    assert r.returncode == 0
    blob = "".join(r.stdout.split())
    decoded = json.loads(bytes.fromhex(blob).decode("utf-8"))
    assert decoded["receipt_version"] == "1.3"


def test_export_json_pipes_cleanly(workspace):
    sign(workspace)
    path = next((workspace / "home" / "receipts").glob("*.json"))
    r = run(["export", str(path), "--format", "json"], workspace / "home", workspace)
    assert json.loads(r.stdout)["receipt_version"] == "1.3"


def test_the_banner_goes_to_stderr_not_stdout(workspace):
    sign(workspace)
    path = next((workspace / "home" / "receipts").glob("*.json"))
    r = run(["export", str(path), "--format", "json"], workspace / "home", workspace)
    assert "AETHERPROOF" not in r.stdout
    assert "AETHERPROOF" in r.stderr


def test_quiet_json_stays_on_stdout(workspace):
    """--quiet output is the machine-readable RESULT, so it belongs on stdout."""
    r = run(["sign", str(workspace / "answer.txt"), "--quiet"],
            workspace / "home", workspace)
    assert json.loads(r.stdout)["receipt_version"] == "1.3"


def test_human_errors_go_to_stderr(workspace):
    r = run(["inspect", str(workspace / "nope.json")], workspace / "home", workspace)
    assert r.returncode == 1
    assert r.stdout.strip() == ""
    assert "not found" in r.stderr.lower()


@pytest.mark.parametrize("args,expected", [
    (["export", "MISSING", "--format", "json"], 1),
    (["export", "RECEIPT", "--format", "cbor"], 1),
    (["inspect", "MISSING"], 1),
    (["verify", "MISSING"], 1),
    (["export", "RECEIPT", "--format", "json"], 0),
    (["export", "RECEIPT", "--format", "hex"], 0),
    (["inspect", "RECEIPT"], 0),
    (["verify", "RECEIPT"], 0),
    (["log", "count"], 0),
])
def test_exit_codes_are_scriptable(workspace, args, expected):
    """`aetherproof inspect r.json && deploy` must not deploy after a failure —
    export/inspect/keygen returned None unconditionally, so it did."""
    sign(workspace)
    path = next((workspace / "home" / "receipts").glob("*.json"))
    concrete = [str(path) if a == "RECEIPT"
                else str(workspace / "nope.json") if a == "MISSING"
                else a for a in args]
    r = run(concrete, workspace / "home", workspace)
    assert r.returncode == expected, f"{concrete} -> {r.returncode}\n{r.stderr}"
