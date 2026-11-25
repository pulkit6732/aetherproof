"""Destination authorization: the payout approver alone cannot add a destination, k of n
policy keys can, revocation sticks, old records cannot be replayed, direct database writes
do not count, domain rules hold, and the CLI and API enforce the same gate."""
import json
import sqlite3
import threading

import pytest

from aetherproof.core.destinations import DestinationRegistry, bank_destination, make_record, sign_record
from aetherproof.core.gate import GatePolicyError, decide, load_policy
from aetherproof.core.instruction import PayoutRequest, ReplayStore, sign_instruction, token_beneficiary
from aetherproof.core.signer import Signer

NOW = 1_780_000_000_000


@pytest.fixture
def keys():
    return Signer.generate(), Signer.generate(), Signer.generate()   # policy A, policy B, payout approver


def _reg(tmp_path, a, b, k=2):
    return DestinationRegistry(str(tmp_path / "d.db"), [a.get_public_key(), b.get_public_key()], k)


def _apply(reg, rec, *signers):
    return reg.apply(rec, [sign_record(rec, s) for s in signers])


def test_approver_key_or_one_policy_key_cannot_add(tmp_path, keys):
    a, b, approver = keys
    reg = _reg(tmp_path, a, b)
    rec = make_record(account="nbfc", destination="fa_mule", domain="bank", action="add", version=1)
    assert not _apply(reg, rec, approver)[0]          # stolen or tricked approver key
    assert not _apply(reg, rec, a)[0]                 # one compromised policy key
    assert not _apply(reg, rec, a, a)[0]              # the same key twice is one signer
    assert _apply(reg, rec, a, b)[0]
    assert reg.check("nbfc", "fa_mule") == (True, "")
    assert reg.check("other-account", "fa_mule")[0] is False


def test_revoke_sticks_and_old_records_cannot_be_replayed(tmp_path, keys):
    a, b, _ = keys
    reg = _reg(tmp_path, a, b)
    add = make_record(account="nbfc", destination="fa_1", domain="bank", action="add", version=1)
    assert _apply(reg, add, a, b)[0]
    rev = make_record(account="nbfc", destination="fa_1", domain="bank", action="revoke", version=2)
    assert _apply(reg, rev, a, b)[0]
    assert reg.check("nbfc", "fa_1") == (False, "destination revoked")
    ok, why = _apply(reg, add, a, b)                  # replay the old add
    assert not ok and "not the next version" in why
    assert reg.check("nbfc", "fa_1")[0] is False
    assert reg.verify_history() == (True, "")


def test_rows_written_straight_into_the_database_do_not_count(tmp_path, keys):
    a, b, approver = keys
    reg = _reg(tmp_path, a, b)
    rec = make_record(account="nbfc", destination="fa_mule", domain="bank", action="add", version=1)
    db = sqlite3.connect(str(tmp_path / "d.db"))
    db.execute("INSERT INTO entries VALUES (?, ?, 1, 1, ?, ?)",
               ("nbfc", "fa_mule", json.dumps(rec), json.dumps([sign_record(rec, approver)])))
    db.commit()
    db.close()
    assert reg.check("nbfc", "fa_mule") == (False, "destination entry fails its policy signatures")


def test_history_edit_is_detected(tmp_path, keys):
    a, b, _ = keys
    reg = _reg(tmp_path, a, b)
    for i, d in enumerate(["fa_1", "fa_2"]):
        assert _apply(reg, make_record(account="nbfc", destination=d, domain="bank", action="add", version=1), a, b)[0]
    db = sqlite3.connect(str(tmp_path / "d.db"))
    db.execute("UPDATE history SET body=replace(body, 'fa_1', 'fa_9') WHERE seq=1")
    db.commit()
    db.close()
    assert reg.verify_history()[0] is False


def test_crypto_binds_network_and_asset(tmp_path, keys):
    a, b, _ = keys
    reg = _reg(tmp_path, a, b)
    d = "crypto:ethereum:USDC:0xabc"
    assert _apply(reg, make_record(account="treasury", destination=d, domain="crypto", action="add", version=1), a, b)[0]
    assert reg.check("treasury", d)[0]
    assert not reg.check("treasury", "crypto:tron:USDC:0xabc")[0]
    assert not reg.check("treasury", "crypto:ethereum:USDT:0xabc")[0]


def test_stock_binds_instrument_and_side(tmp_path, keys):
    a, b, _ = keys
    reg = _reg(tmp_path, a, b)
    rec = make_record(account="desk", destination="stock:ACC-7:INFY", domain="stock", action="add", version=1,
                      attrs={"sides": ["BUY"]})
    assert _apply(reg, rec, a, b)[0]
    assert reg.check("desk", "stock:ACC-7:INFY:BUY")[0]
    assert "side SELL" in reg.check("desk", "stock:ACC-7:INFY:SELL")[1]
    assert not reg.check("desk", "stock:ACC-7:TCS:BUY")[0]


def test_concurrent_changes_keep_one_version_line(tmp_path, keys):
    a, b, _ = keys
    _reg(tmp_path, a, b).close()
    results = []

    def worker(i):
        reg = _reg(tmp_path, a, b)
        rec = make_record(account="nbfc", destination="fa_x", domain="bank", action="add", version=1, evidence=f"w{i}")
        results.append(_apply(reg, rec, a, b)[0])
        reg.close()
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count(True) == 1                  # exactly one version 1 wins


def test_bank_destination_never_stores_the_raw_number():
    d = bank_destination("hdfc0001234", "5010 0012 3456")
    assert d.startswith("bank:") and "50100012" not in d and d == bank_destination("HDFC0001234", "501000123456")


# ------------------------------------------------------------------ the shared gate
PER_PAYOUT_CAP_MINOR = 100_000          # "1000.00" in the policy file
LOAN_MINOR = 90_000                     # under every cap
OVER_CAP_MINOR = PER_PAYOUT_CAP_MINOR + 1


@pytest.fixture
def gate_home(tmp_path, keys):
    a, b, _ = keys
    a.export_public_file(str(tmp_path / "pa.pub"))
    b.export_public_file(str(tmp_path / "pb.pub"))
    pol = {"account": "nbfc", "destinations": {"policy_pubkeys": ["pa.pub", "pb.pub"], "required_signers": 2},
           "limits": {"per_payout_max": "1000.00", "daily_max": "1500.00", "daily_count_max": 10,
                      "per_destination_daily_max": "1000.00", "utc_offset_minutes": 330}}
    (tmp_path / "gate_policy.json").write_text(json.dumps(pol), encoding="utf-8")
    return tmp_path


def _ins(approver, dest, amount):
    return sign_instruction(approver, originator="los", amount_minor=amount, currency="INR",
                            beneficiary=token_beneficiary(dest), purpose="loan", reference="LN", approval_ref="S",
                            approved_by="ops", policy="v1", not_before_ms=NOW - 1000)


def _decide(approver, replay, pol, ins, amount, dest):
    return decide(ins, PayoutRequest(amount, "INR", ins.instruction_id, dest), approver.get_public_key(), replay, pol, now_ms=NOW)


def test_gate_refuses_validly_signed_payout_to_unapproved_destination(gate_home, keys):
    a, b, approver = keys
    pol = load_policy(gate_home)
    reg = DestinationRegistry(pol.destinations_db, pol.policy_keys, pol.required_signers)
    assert _apply(reg, make_record(account="nbfc", destination="fa_borrower", domain="bank", action="add", version=1), a, b)[0]
    reg.close()
    replay = ReplayStore(str(gate_home / "r.db"))
    ok = _ins(approver, "fa_borrower", LOAN_MINOR)
    assert _decide(approver, replay, pol, ok, LOAN_MINOR, "fa_borrower").allowed
    stolen = _ins(approver, "fa_mule", LOAN_MINOR)   # approver key stolen: the signature is valid
    d = _decide(approver, replay, pol, stolen, LOAN_MINOR, "fa_mule")
    assert not d.allowed and "not approved by the policy authority" in d.reasons[0]
    big = _ins(approver, "fa_borrower", OVER_CAP_MINOR)
    d = _decide(approver, replay, pol, big, OVER_CAP_MINOR, "fa_borrower")
    assert not d.allowed and "per payout cap" in d.reasons[0]
    replay.close()


def test_no_policy_file_keeps_the_05_behaviour(tmp_path, keys):
    _, _, approver = keys
    assert load_policy(tmp_path) is None
    replay = ReplayStore(str(tmp_path / "r.db"))
    ins = _ins(approver, "fa_any", LOAN_MINOR)
    assert _decide(approver, replay, None, ins, LOAN_MINOR, "fa_any").allowed
    replay.close()


@pytest.mark.parametrize("body", [
    '{"account": "nbfc", "limits": {"per_payout_max": "abc"}}',                 # not an amount
    '{"account": "", "limits": null}',                                          # empty account
    '{"account": "nbfc", "destinations": {"policy_pubkeys": [], "required_signers": 1}}',   # no policy keys
    'not json',
])
def test_broken_policy_file_refuses_instead_of_falling_back(tmp_path, body):
    (tmp_path / "gate_policy.json").write_text(body, encoding="utf-8")
    with pytest.raises(GatePolicyError):
        load_policy(tmp_path)


def test_explicit_policy_path_that_does_not_exist_is_an_error(tmp_path):
    with pytest.raises(GatePolicyError):
        load_policy(tmp_path, str(tmp_path / "missing.json"))


@pytest.mark.parametrize("kw", [{"account": ""}, {"destination": ""}, {"version": 0}, {"domain": "cash"}, {"action": "edit"}])
def test_records_with_empty_or_invalid_fields_are_refused(kw):
    base = dict(account="nbfc", destination="fa_1", domain="bank", action="add", version=1)
    with pytest.raises(ValueError):
        make_record(**{**base, **kw})


def test_registry_needs_policy_keys(tmp_path, keys):
    a, _, _ = keys
    with pytest.raises(ValueError):
        DestinationRegistry(str(tmp_path / "d.db"), [], 1)
    with pytest.raises(ValueError):
        DestinationRegistry(str(tmp_path / "d.db"), [a.get_public_key()], 2)


def test_empty_signature_list_and_unknown_destination_are_refused(tmp_path, keys):
    a, b, _ = keys
    reg = _reg(tmp_path, a, b)
    rec = make_record(account="nbfc", destination="fa_1", domain="bank", action="add", version=1)
    assert not reg.apply(rec, [])[0]
    assert not reg.check("nbfc", "")[0]
    assert not reg.check("", "fa_1")[0]
