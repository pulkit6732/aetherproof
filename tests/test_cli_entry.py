"""The cli.py entry point: main(), exit codes, error handling, TTY guard.

cli.py was at 0% coverage. It owns the process exit code, the top-level
exception handlers that decide whether a user sees a traceback or a sentence,
and the guard that stops the interactive menu from being launched into a pipe.
Those are the paths that decide what a person actually experiences when
something goes wrong.
"""

import json
import sys
from pathlib import Path

import pytest

from aetherproof import cli


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AETHERPROOF_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AETHERPROOF_KEY_PASSPHRASE", raising=False)
    yield


@pytest.fixture
def files(tmp_path):
    (tmp_path / "answer.txt").write_text("The capital of France is Paris.")
    (tmp_path / "model.bin").write_text("fake weights")
    return tmp_path


def captured(capsys):
    cap = capsys.readouterr()
    return cap.out + cap.err


# ══ exit codes ══════════════════════════════════════════════════════════════

def test_successful_command_returns_zero(files, capsys):
    assert cli.main(["sign", str(files / "answer.txt"), "--quiet"]) == 0


def test_failed_command_exits_one(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["verify", str(tmp_path / "nope.json"), "--quiet"])
    assert e.value.code == 1


def test_unknown_command_exits_one(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["frobnicate"])
    assert e.value.code == 1


def test_help_returns_zero_and_lists_commands(capsys):
    assert cli.main(["--help"]) == 0
    text = captured(capsys)
    for command in ("sign", "verify", "inspect", "log", "keygen", "export", "tamper"):
        assert command in text


@pytest.mark.parametrize("flag", ["-h", "--help", "help"])
def test_all_help_aliases(capsys, flag):
    assert cli.main([flag]) == 0
    assert "Command" in captured(capsys)


def test_help_table_no_longer_advertises_cbor(capsys):
    cli.main(["--help"])
    assert "cbor" not in captured(capsys).lower()


# ══ top-level error handling ════════════════════════════════════════════════

def test_keyboard_interrupt_exits_zero_with_a_sentence(monkeypatch, capsys):
    """Ctrl-C is a user choice, not a crash - and nothing was written."""
    monkeypatch.setattr(cli, "_run", lambda argv: (_ for _ in ()).throw(KeyboardInterrupt))
    with pytest.raises(SystemExit) as e:
        cli.main(["sign", "x"])
    assert e.value.code == 0
    assert "Cancelled" in captured(capsys)


def test_keyboard_interrupt_reraises_under_debug(monkeypatch):
    monkeypatch.setattr(cli, "_run", lambda argv: (_ for _ in ()).throw(KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        cli.main(["--debug", "sign", "x"])


def test_missing_file_is_reported_plainly(monkeypatch, capsys):
    def boom(argv):
        raise FileNotFoundError(2, "No such file", "ghost.json")
    monkeypatch.setattr(cli, "_run", boom)
    with pytest.raises(SystemExit) as e:
        cli.main(["inspect", "ghost.json"])
    assert e.value.code == 1
    assert "ghost.json" in captured(capsys)


def test_missing_file_reraises_under_debug(monkeypatch):
    def boom(argv):
        raise FileNotFoundError(2, "No such file", "ghost.json")
    monkeypatch.setattr(cli, "_run", boom)
    with pytest.raises(FileNotFoundError):
        cli.main(["--debug", "inspect", "ghost.json"])


def test_corrupt_json_is_reported_plainly(monkeypatch, capsys):
    def boom(argv):
        raise json.JSONDecodeError("bad", "doc", 0)
    monkeypatch.setattr(cli, "_run", boom)
    with pytest.raises(SystemExit) as e:
        cli.main(["inspect", "bad.json"])
    assert e.value.code == 1
    assert "corrupted" in captured(capsys).lower()


def test_corrupt_json_reraises_under_debug(monkeypatch):
    def boom(argv):
        raise json.JSONDecodeError("bad", "doc", 0)
    monkeypatch.setattr(cli, "_run", boom)
    with pytest.raises(json.JSONDecodeError):
        cli.main(["--debug", "inspect", "bad.json"])


def test_unexpected_error_suggests_debug(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_run",
                        lambda argv: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(SystemExit) as e:
        cli.main(["sign", "x"])
    assert e.value.code == 1
    text = captured(capsys)
    assert "boom" in text
    assert "--debug" in text


def test_unexpected_error_reraises_under_debug(monkeypatch):
    monkeypatch.setattr(cli, "_run",
                        lambda argv: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        cli.main(["--debug", "sign", "x"])


def test_debug_flag_is_stripped_before_dispatch(monkeypatch, files):
    seen = {}
    monkeypatch.setattr(cli, "_run", lambda argv: seen.update(argv=argv))
    cli.main(["--debug", "sign", "answer.txt"])
    assert "--debug" not in seen["argv"]


def test_main_reads_sys_argv_when_given_nothing(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["aetherproof", "--help"])
    assert cli.main() == 0
    assert "Command" in captured(capsys)


# ══ the interactive menu must not launch into a pipe ════════════════════════

def test_non_tty_refuses_the_menu_with_guidance(monkeypatch, capsys):
    """A confusing prompt_toolkit traceback is the wrong failure for a user who
    piped the bare command."""
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as e:
        cli.main([])
    assert e.value.code == 2
    text = captured(capsys)
    assert "interactive terminal" in text
    assert "--help" in text


def test_non_tty_stdout_also_refuses(monkeypatch, capsys):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as e:
        cli.main([])
    assert e.value.code == 2


# ══ app state wiring ════════════════════════════════════════════════════════

def test_app_state_uses_the_configured_home(tmp_path, monkeypatch):
    home = tmp_path / "custom"
    monkeypatch.setenv("AETHERPROOF_HOME", str(home))
    signer, log = cli._app_state()
    try:
        assert (home / "signing_key.pem").exists()
        assert Path(log.db_path) == home / "log.db"
        assert signer is not None
    finally:
        log.close()


def test_app_state_saves_the_pubkey_for_the_verify_wizard(tmp_path, monkeypatch):
    home = tmp_path / "custom"
    monkeypatch.setenv("AETHERPROOF_HOME", str(home))
    _, log = cli._app_state()
    try:
        from aetherproof.ui.easy_mode import _last_pubkey
        assert str(home / "signing_key.pub") == str(_last_pubkey())
    finally:
        log.close()


# ══ interactive prompt wrappers ═════════════════════════════════════════════

def test_ask_path_returns_none_on_interrupt(monkeypatch):
    import questionary

    class Cancels:
        def ask(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(questionary, "path", lambda *a, **k: Cancels())
    assert cli._ask_path("file?") is None


def test_ask_text_returns_none_on_interrupt(monkeypatch):
    import questionary

    class Cancels:
        def ask(self):
            raise KeyboardInterrupt

    monkeypatch.setattr(questionary, "text", lambda *a, **k: Cancels())
    assert cli._ask_text("name?") is None


def test_ask_path_returns_the_answer(monkeypatch):
    import questionary

    class Answers:
        def ask(self):
            return "/some/path"

    monkeypatch.setattr(questionary, "path", lambda *a, **k: Answers())
    assert cli._ask_path("file?") == "/some/path"


# ══ menu route helpers ══════════════════════════════════════════════════════

def test_inspect_wizard_runs_inspect_on_the_given_path(monkeypatch, files, capsys):
    cli.main(["sign", str(files / "answer.txt"), "--quiet"])
    receipt = next((files / "home" / "receipts").glob("*.json"))
    monkeypatch.setattr(cli, "_ask_path", lambda msg: str(receipt))
    capsys.readouterr()
    cli.run_inspect_wizard()
    assert "receipt_version" in captured(capsys)


def test_inspect_wizard_does_nothing_when_cancelled(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_ask_path", lambda msg: None)
    cli.run_inspect_wizard()
    assert "receipt_version" not in captured(capsys)


def test_log_viewer_lists_and_verifies(files, capsys):
    cli.main(["sign", str(files / "answer.txt"), "--quiet"])
    capsys.readouterr()
    cli.run_log_viewer()
    assert "Sequence" in captured(capsys)


def test_keygen_wizard_writes_a_pair(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_ask_text", lambda msg, default="": "wizkey")
    cli.run_keygen_wizard()
    assert (tmp_path / "wizkey.pem").exists()
    assert (tmp_path / "wizkey.pub").exists()


def test_keygen_wizard_does_nothing_when_cancelled(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_ask_text", lambda msg, default="": None)
    cli.run_keygen_wizard()
    assert list(tmp_path.glob("*.pem")) == []


# ══ expert shell loop ═══════════════════════════════════════════════════════

def test_expert_shell_exits_on_exit(monkeypatch, capsys):
    lines = iter(["exit"])
    monkeypatch.setattr(cli.console, "input", lambda prompt: next(lines))
    cli.run_expert_shell()          # must return, not hang


def test_expert_shell_exits_on_eof(monkeypatch):
    def eof(prompt):
        raise EOFError
    monkeypatch.setattr(cli.console, "input", eof)
    cli.run_expert_shell()


def test_expert_shell_exits_on_interrupt(monkeypatch):
    def interrupt(prompt):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli.console, "input", interrupt)
    cli.run_expert_shell()


def test_expert_shell_skips_blank_lines_and_runs_commands(monkeypatch, capsys):
    lines = iter(["", "   ", "log count", "quit"])
    monkeypatch.setattr(cli.console, "input", lambda prompt: next(lines))
    cli.run_expert_shell()
    assert "0" in captured(capsys)
