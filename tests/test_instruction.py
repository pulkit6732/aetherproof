"""Signed payment instructions: originator signs, executor verifies before money moves."""

import json
import threading

import pytest

from aetherproof.core.instruction import (ALLOW, REJECT, PaymentInstruction, PayoutRequest, ReplayStore,
                                          bank_beneficiary, beneficiary_matches, sign_instruction,
                                          token_beneficiary, verify_instruction)
from aetherproof.core.signer import Signer

T0 = 1_793_000_000_000          # fixed clock so validity checks do not depend on wall time
ORIG = Signer.generate()


def make(**kw):
    args = dict(originator="lender-x", amount_minor=4_850_000, currency="INR",
                beneficiary=token_beneficiary("fa_00000000000001"), purpose="loan_disbursal",
                reference="LN-2048-771", approval_ref="SAN-2048-771", approved_by="credit-ops",
                policy="disbursal-v3", not_before_ms=T0)
    args.update(kw)
    return sign_instruction(kw.pop("signer", ORIG) if "signer" in kw else ORIG,
                            **{k: v for k, v in args.items() if k != "signer"})


def req(ins, **kw):
    r = dict(amount_minor=ins.amount_minor, currency=ins.currency, reference=ins.instruction_id,
             beneficiary_token="fa_00000000000001")
    r.update(kw)
    return PayoutRequest(**r)


@pytest.fixture
def replay(tmp_path):
    store = ReplayStore(str(tmp_path / "replay.db"))
    yield store
    store.close()


def check(ins, request, replay=None, keys=None, at=T0 + 1000):
    return verify_instruction(ins, request, keys or ORIG.get_public_key(), replay, now_ms=at)


def test_authorised_payout_is_allowed(replay):
    ins = make()
    d = check(ins, req(ins), replay)
    assert d.verdict == ALLOW and d.allowed and d.reasons == []


# Regression: failure drill — called without a replay store, the gate returned ALLOW every time,
# so an integrator who forgot the store could pay one approval repeatedly. It now fails closed.
def test_gate_without_a_replay_store_never_allows():
    ins = make()
    for _ in range(3):
        d = check(ins, req(ins), None)
        assert d.verdict == "review" and not d.allowed and "replay store" in d.reasons[0]


# Regression: unknown-attack fuzz — the hex decoder accepted " <sig>", "<SIG>" and spaced forms,
# so differently written documents verified as the same instruction. One canonical form only.
@pytest.mark.parametrize("variant", [lambda s: " " + s, lambda s: s + " ", lambda s: s.upper(),
                                     lambda s: s[:len(s) // 2] + " " + s[len(s) // 2:], lambda s: s + "00",
                                     lambda s: "", lambda s: None])
def test_signature_must_be_canonical_lowercase_hex(replay, variant):
    ins = make()
    data = json.loads(ins.to_json())
    data["signature"] = variant(data["signature"])
    d = check(PaymentInstruction.from_json(json.dumps(data)), req(ins), replay)
    assert d.verdict == REJECT and any("signature" in r for r in d.reasons)


def test_same_instruction_cannot_move_money_twice(replay):
    ins = make()
    assert check(ins, req(ins), replay).allowed
    d = check(ins, req(ins), replay)
    assert d.verdict == REJECT and "replay" in d.reasons[0]


def test_rejected_attempt_does_not_burn_the_instruction(replay):
    ins = make()
    assert not check(ins, req(ins, amount_minor=9_999_999), replay).allowed
    assert check(ins, req(ins), replay).allowed


@pytest.mark.parametrize("change,needle", [
    (dict(amount_minor=4_850_001), "amount"),
    (dict(currency="USD"), "currency"),
    (dict(beneficiary_token="fa_attacker"), "beneficiary"),
    (dict(beneficiary_token=""), "beneficiary"),
    (dict(reference="ins_someone_else"), "reference"),
])
def test_any_change_to_the_payout_is_rejected(replay, change, needle):
    ins = make()
    d = check(ins, req(ins, **change), replay)
    assert d.verdict == REJECT and any(needle in r for r in d.reasons)


def test_expired_and_not_yet_valid(replay):
    ins = make(validity_ms=60_000)
    assert "expired" in check(ins, req(ins), replay, at=T0 + 60_001).reasons[0]
    assert "not yet valid" in check(ins, req(ins), replay, at=T0 - 1).reasons[0]


def test_validity_window_edges_are_inclusive(replay):
    a, b = make(validity_ms=60_000), make(validity_ms=60_000)
    assert check(a, req(a), replay, at=T0).allowed
    assert check(b, req(b), replay, at=T0 + 60_000).allowed


def test_stolen_credential_cannot_mint_an_instruction(replay):
    forged = make(signer=Signer.generate())      # attacker signs with their own key
    d = check(forged, req(forged), replay)
    assert d.verdict == REJECT and "no trusted originator key" in d.reasons[0]


def test_edited_instruction_fails_signature(replay):
    ins = make()
    data = json.loads(ins.to_json())
    data["amount_minor"] = 99_000_000
    edited = PaymentInstruction.from_json(json.dumps(data))
    d = check(edited, req(edited), replay)
    assert any("signature invalid" in r for r in d.reasons)


def test_bank_beneficiary_binding(replay):
    ins = make(beneficiary=bank_beneficiary("HDFC0001234", "50100012345678"))
    assert "50100012345678" not in ins.to_json(), "account number must not appear in the instruction"
    ok = req(ins, beneficiary_token="", ifsc="hdfc0001234 ", account_number="50100012345678")
    assert check(ins, ok, replay).allowed
    bad = req(ins, beneficiary_token="", ifsc="HDFC0001234", account_number="50100012345679")
    assert any("beneficiary" in r for r in check(ins, bad, replay).reasons)


def test_leading_zeros_are_significant():
    ben = bank_beneficiary("SBIN0000001", "00012345")
    assert beneficiary_matches(ben, ifsc="SBIN0000001", account_number="00012345")
    assert not beneficiary_matches(ben, ifsc="SBIN0000001", account_number="12345")


def test_same_account_different_salts_give_different_digests():
    a, b = bank_beneficiary("X", "1"), bank_beneficiary("X", "1")
    assert a["digest"] != b["digest"]


@pytest.mark.parametrize("kw,needle", [
    (dict(amount_minor=0), "positive"),
    (dict(amount_minor=-5), "positive"),
    (dict(amount_minor=48.5), "integer"),
    (dict(currency="RUPEE"), "currency"),
    (dict(beneficiary={"kind": "email"}), "beneficiary"),
    (dict(validity_ms=0), "validity"),
    (dict(instruction_id="x" * 41), "40"),
])
def test_bad_instructions_are_refused_at_signing(kw, needle):
    with pytest.raises(ValueError, match=needle):
        make(**kw)


def test_empty_token_is_refused():
    with pytest.raises(ValueError):
        token_beneficiary("")


def test_wire_format_round_trip_and_type_check():
    ins = make()
    again = PaymentInstruction.from_json(ins.to_json())
    assert again == ins and again.digest() == ins.digest()
    with pytest.raises(ValueError, match="not an AetherProof instruction"):
        PaymentInstruction.from_json(json.dumps({**json.loads(ins.to_json()), "type": "other"}))
    with pytest.raises(ValueError, match="integer"):
        PaymentInstruction.from_json(json.dumps({**json.loads(ins.to_json()), "amount_minor": "4850000"}))


def test_instruction_id_fits_a_provider_reference():
    assert len(make().instruction_id) <= 40


def test_concurrent_executors_allow_exactly_once(tmp_path):
    ins = make()
    store = ReplayStore(str(tmp_path / "race.db"))
    results = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        results.append(check(ins, req(ins), store).allowed)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1 and results.count(False) == 15


def test_replay_store_survives_reopen(tmp_path):
    ins = make()
    first = ReplayStore(str(tmp_path / "r.db"))
    assert check(ins, req(ins), first).allowed
    first.close()
    second = ReplayStore(str(tmp_path / "r.db"))
    assert "replay" in check(ins, req(ins), second).reasons[0]
    second.close()


def test_bad_replay_mode_refused(tmp_path):
    with pytest.raises(ValueError):
        ReplayStore(str(tmp_path / "r.db"), synchronous="OFF")
