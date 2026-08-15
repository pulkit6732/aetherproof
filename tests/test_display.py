"""Presentation helpers.

display.py was 33% covered. It is "just" presentation, but every command routes
its output through here — an exception in a formatting helper takes the whole
tool down, and the failure would look to a user like the cryptography broke.

These also pin the stdout/stderr split: the banner is chrome and belongs on
stderr so that machine-readable output stays pipeable.
"""

import io

import pytest
from rich.progress import Progress
from rich.table import Table

from aetherproof import __version__
from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.ui import display as d


@pytest.fixture
def receipt():
    s = Signer.generate()
    r = Receipt(model_weight_root="a" * 64, model_root_type="artifact_hash",
                input_commitment="b" * 64, output_hash="c" * 64,
                log_sequence=1, log_anchor="local://log/1",
                signing_key_id=Receipt.key_id(s.get_public_key()))
    r.signature = s.sign(r.signing_bytes())
    return r


def stdout(capsys):
    return capsys.readouterr().out


def both(capsys):
    cap = capsys.readouterr()
    return cap.out + cap.err


# ══ the stdout / stderr split ═══════════════════════════════════════════════

def test_header_goes_to_stderr_not_stdout(capsys):
    """Chrome on stdout corrupted every pipeable command."""
    d.header()
    cap = capsys.readouterr()
    assert "AETHERPROOF" in cap.err
    assert "AETHERPROOF" not in cap.out


def test_header_reports_the_real_version(capsys):
    d.header()
    assert __version__ in capsys.readouterr().err


def test_version_string_is_derived_not_hardcoded():
    assert d._V == f"v{__version__}"


def test_err_console_is_distinct_from_console():
    assert d.err_console is not d.console
    assert d.err_console.stderr is True


# ══ logo and about ══════════════════════════════════════════════════════════

def test_print_logo_renders(capsys):
    d.print_logo()
    assert "AETHERPROOF" in both(capsys)


def test_run_about_renders(capsys):
    d.run_about()
    text = both(capsys)
    assert __version__ in text


# ══ receipt rendering ═══════════════════════════════════════════════════════

def test_receipt_table_shows_every_field(receipt, capsys):
    d.receipt_table(receipt)
    text = both(capsys)
    for label in ("Receipt ID", "Model Weight Root", "Output Hash", "Log Sequence"):
        assert label in text


def test_receipt_table_handles_empty_optional_fields(capsys):
    """An unsigned receipt with no input commitment must still render."""
    r = Receipt(model_weight_root="a" * 64, output_hash="c" * 64)
    d.receipt_table(r)
    text = both(capsys)
    assert "(hidden)" in text        # empty input_commitment
    assert "NO" in text              # no signature yet


# ══ message boxes ═══════════════════════════════════════════════════════════

@pytest.mark.parametrize("fn", ["success_box", "error_box", "warning_box", "info_box"])
def test_message_boxes_render_title_and_message(capsys, fn):
    getattr(d, fn)("A Title", "the message body")
    text = both(capsys)
    assert "A Title" in text
    assert "the message body" in text


@pytest.mark.parametrize("fn", ["success_box", "error_box", "warning_box", "info_box"])
def test_message_boxes_survive_markup_in_user_text(capsys, fn):
    """A receipt id or path containing [brackets] must not be eaten as markup."""
    getattr(d, fn)("Title", "value [not-a-tag] here")
    assert "not-a-tag" in both(capsys)


# ══ verification verdict ════════════════════════════════════════════════════

def test_verification_result_valid(capsys):
    d.verification_result("ap_123", True)
    text = both(capsys).upper()
    assert "VALID" in text
    assert "INVALID" not in text


def test_verification_result_invalid(capsys):
    d.verification_result("ap_123", False)
    assert "INVALID" in both(capsys).upper()


def test_verification_result_names_the_receipt(capsys):
    d.verification_result("ap_deadbeef", True)
    assert "ap_deadbeef" in both(capsys)


# ══ progress ════════════════════════════════════════════════════════════════

def test_spinner_progress_returns_a_usable_progress():
    p = d.spinner_progress("Working...")
    assert isinstance(p, Progress)
    with p as active:
        task = active.add_task("Working...", total=1)
        active.update(task, completed=1)


# ══ input helpers ═══════════════════════════════════════════════════════════

def test_get_input_returns_what_was_typed(monkeypatch):
    monkeypatch.setattr(d.console, "input", lambda prompt: "  typed  ")
    assert d.get_input("Name?") == "typed"


def test_get_input_falls_back_to_the_default(monkeypatch):
    monkeypatch.setattr(d.console, "input", lambda prompt: "")
    assert d.get_input("Name?", default="fallback") == "fallback"


def test_multiline_input_ends_on_a_blank_line(monkeypatch):
    lines = iter(["first", "second", ""])
    monkeypatch.setattr("builtins.input", lambda: next(lines))
    assert d.multiline_input() == "first\nsecond"


def test_multiline_input_ends_on_eof(monkeypatch):
    lines = iter(["only line"])

    def reader():
        try:
            return next(lines)
        except StopIteration:
            raise EOFError
    monkeypatch.setattr("builtins.input", reader)
    assert d.multiline_input() == "only line"


def test_main_menu_reads_and_normalises(monkeypatch, capsys):
    monkeypatch.setattr(d.console, "input", lambda prompt: " Q ")
    assert d.main_menu() == "q"


# ══ generic table ═══════════════════════════════════════════════════════════

def test_table_from_list_with_explicit_headers():
    t = d.table_from_list([{"One": "a", "Two": "b"}], headers=["One", "Two"])
    assert isinstance(t, Table)
    assert t.columns[0].header == "One"


def test_table_from_list_infers_headers_from_the_first_item():
    t = d.table_from_list([{"seq": 1, "id": "ap_1"}])
    assert [c.header for c in t.columns] == ["seq", "id"]


def test_table_from_list_fills_missing_keys_blank():
    t = d.table_from_list([{"a": 1, "b": 2}, {"a": 3}], headers=["a", "b"])
    assert t.row_count == 2


def test_table_from_list_empty():
    assert isinstance(d.table_from_list([]), Table)


def test_table_from_list_renders(capsys):
    d.console.print(d.table_from_list([{"A": "x", "B": "y"}]))
    text = both(capsys)
    assert "x" in text and "A" in text
