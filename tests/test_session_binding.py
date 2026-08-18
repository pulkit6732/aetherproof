"""Binding a receipt to its conversation (issue #1's gap, finally populated).

`session.py` proves a turn belongs to a sealed session. This is the other
direction: a standalone receipt file saying which session and turn it came from,
committed inside the signature via the v1.2 signed-extensions mechanism.

Without it a receipt is an orphan - nothing connects turn N to turn N-1, which
is exactly what the causal-context extension was proposed for and what
issue_receipt never actually filled in.
"""

import json

import pytest

from aetherproof.core.keystore import issue_receipt, SESSION_NS
from aetherproof.core.log import ReceiptLog
from aetherproof.core.session import Session
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt


@pytest.fixture
def rig(tmp_path):
    log = ReceiptLog(db_path=str(tmp_path / "log.db"))
    signer = Signer.generate()
    return log, signer, signer.get_public_key(), tmp_path


def issue(log, signer, tmp_path, **kw):
    return issue_receipt(signer, log, model_weight_root="a" * 64,
                         output_hash="c" * 64, receipts_dir=tmp_path / "r", **kw)[0]


def test_unbound_receipt_has_no_extensions(rig):
    log, signer, pub, tmp = rig
    r = issue(log, signer, tmp)
    assert r.signed_extensions == {}
    assert r.receipt_version == "1.3"
    assert verify_receipt(r, pub) is True


def test_bound_receipt_names_its_session_and_turn(rig):
    log, signer, pub, tmp = rig
    r = issue(log, signer, tmp, session_id="s_abc", turn_index=2)
    ctx = r.signed_extensions[SESSION_NS]
    assert ctx["session_id"] == "s_abc"
    assert ctx["turn_index"] == "2"
    assert verify_receipt(r, pub) is True


def test_turn_zero_is_recorded_not_dropped(rig):
    """turn_index=0 is falsy - it must still be bound."""
    log, signer, pub, tmp = rig
    r = issue(log, signer, tmp, session_id="s_abc", turn_index=0)
    assert r.signed_extensions[SESSION_NS]["turn_index"] == "0"


def test_binding_is_inside_the_signature(rig):
    log, signer, pub, tmp = rig
    r = issue(log, signer, tmp, session_id="s_abc", turn_index=2)
    assert r.signed_extensions_hash() in r.canonical_message()


@pytest.mark.parametrize("field,value", [
    ("session_id", "s_forged"), ("turn_index", "9"), ("session_root", "f" * 64),
])
def test_editing_any_bound_field_breaks_the_signature(rig, field, value):
    log, signer, pub, tmp = rig
    r = issue(log, signer, tmp, session_id="s_abc", turn_index=2,
              session_root="d" * 64)
    assert verify_receipt(r, pub) is True
    r.signed_extensions[SESSION_NS][field] = value
    assert verify_receipt(r, pub) is False


def test_removing_the_binding_breaks_the_signature(rig):
    log, signer, pub, tmp = rig
    r = issue(log, signer, tmp, session_id="s_abc", turn_index=2)
    del r.signed_extensions[SESSION_NS]
    assert verify_receipt(r, pub) is False


def test_receipt_carries_the_session_root_it_was_sealed_under(rig):
    """The join between a receipt and the session tree."""
    log, signer, pub, tmp = rig
    sess = Session(signer)
    for i in range(8):
        sess.record(prompt=f"q{i}", output=f"a{i}")
    seal = sess.seal()

    r = issue(log, signer, tmp, session_id=sess.session_id, turn_index=3,
              session_root=seal.merkle_root)

    ctx = r.signed_extensions[SESSION_NS]
    assert ctx["session_root"] == seal.merkle_root
    assert ctx["session_id"] == seal.session_id
    # and the turn it names really is in that tree
    assert Session.verify_turn(sess.prove(3), seal, pub) is True


def test_caller_extensions_are_preserved_alongside(rig):
    log, signer, pub, tmp = rig
    other = {"org.liminal.agent_chain/v0.1": {"actor_id": "agent:planner"}}
    r = issue(log, signer, tmp, session_id="s_abc", turn_index=1, extensions=other)
    assert "org.liminal.agent_chain/v0.1" in r.signed_extensions
    assert SESSION_NS in r.signed_extensions
    assert verify_receipt(r, pub) is True


def test_caller_extensions_are_not_mutated(rig):
    """issue_receipt must not write into the dict the caller handed it."""
    log, signer, pub, tmp = rig
    other = {"ns/v1": {"a": "b"}}
    issue(log, signer, tmp, session_id="s_abc", turn_index=1, extensions=other)
    assert other == {"ns/v1": {"a": "b"}}


def test_bound_receipts_round_trip_and_log_verifies(rig):
    log, signer, pub, tmp = rig
    sess = Session(signer)
    for i in range(4):
        sess.record(prompt=f"q{i}", output=f"a{i}")
    seal = sess.seal()
    for i in range(4):
        issue(log, signer, tmp, session_id=sess.session_id, turn_index=i,
              session_root=seal.merkle_root)

    assert log.count() == 4
    report = log.verify_integrity_report(pub)
    assert report.ok is True
    assert report.verified == 4

    from aetherproof.core.receipt import Receipt
    stored = Receipt.from_json(log.get_by_sequence(2)["receipt_json"])
    assert stored.signed_extensions[SESSION_NS]["turn_index"] == "1"
    assert verify_receipt(stored, pub) is True


def test_receipts_from_one_session_share_a_session_id(rig):
    log, signer, pub, tmp = rig
    ids = {issue(log, signer, tmp, session_id="s_same", turn_index=i)
           .signed_extensions[SESSION_NS]["session_id"] for i in range(5)}
    assert ids == {"s_same"}
