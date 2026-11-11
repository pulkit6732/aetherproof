"""Payout outcome verification against signed instructions (RazorpayX-shaped and generic records)."""

import json

import pytest

from aetherproof.core.instruction import bank_beneficiary, sign_instruction, token_beneficiary
from aetherproof.core.payouts import load_payouts, payout_from_row, MAPPINGS, reconcile_payouts
from aetherproof.core.reconcile import AMBIGUOUS, CONFLICT, MATCHED, MISSING
from aetherproof.core.signer import Signer

T0 = 1_793_000_000_000
ORIG = Signer.generate()
FA = "fa_00000000000001"


def ins(i=1, amount=4_850_000, **kw):
    return sign_instruction(ORIG, originator="lender-x", amount_minor=amount, currency="INR",
                            beneficiary=kw.pop("beneficiary", token_beneficiary(FA)), purpose="loan_disbursal",
                            reference=f"LN-{i}", approval_ref=f"SAN-{i}", approved_by="credit-ops",
                            policy="disbursal-v3", not_before_ms=T0, instruction_id=f"ins_{i:06d}", **kw)


def rzp(pid, ref, *, amount=4_850_000, status="processed", fa=FA, at=T0 + 60_000):
    # RazorpayX payout entity shape: amount in paise, created_at in unix seconds
    return payout_from_row({"id": pid, "entity": "payout", "fund_account_id": fa, "amount": amount,
                            "currency": "INR", "status": status, "reference_id": ref,
                            "utr": "UTR123", "created_at": at // 1000}, MAPPINGS["razorpayx"])


def run(instructions, payouts, at=T0 + 3_600_000, keys=None):
    return reconcile_payouts(instructions, payouts, keys or ORIG.get_public_key(), as_of_ms=at)


def one(rep, kind="approval"):
    hits = [r for r in rep.results if r.kind == kind]
    assert len(hits) == 1, rep.to_dict()
    return hits[0]


def test_paid_as_authorised_is_matched():
    rep = run([ins()], [rzp("pout_1", "ins_000001")])
    assert one(rep).verdict == MATCHED and rep.ok


@pytest.mark.parametrize("payout,needle", [
    (dict(amount=5_850_000), "paid 5850000"),
    (dict(fa="fa_attacker"), "different beneficiary"),
    (dict(at=T0 + 17 * 60_000), "outside"),      # window 15 min + 1 min clock tolerance
    (dict(at=T0 - 2 * 60_000), "outside"),
])
def test_payout_that_differs_is_a_conflict(payout, needle):
    r = one(run([ins()], [rzp("pout_1", "ins_000001", **payout)]))
    assert r.verdict == CONFLICT and any(needle in x for x in r.reasons)


def test_whole_second_provider_clock_inside_tolerance_matches():
    # instruction signed at T0 + 0.7 s; provider stamps the same second, truncated to T0
    i = sign_instruction(ORIG, originator="x", amount_minor=4_850_000, currency="INR", beneficiary=token_beneficiary(FA),
                         purpose="p", reference="r", approval_ref="a", approved_by="b", policy="c",
                         not_before_ms=T0 + 700, instruction_id="ins_000001")
    assert one(run([i], [rzp("pout_1", "ins_000001", at=T0)])).verdict == MATCHED


def test_paid_twice_is_a_conflict():
    r = one(run([ins()], [rzp("pout_1", "ins_000001"), rzp("pout_2", "ins_000001")]))
    assert r.verdict == CONFLICT and "paid 2 times" in r.reasons[0]


def test_failed_then_retried_successfully_matches():
    r = one(run([ins()], [rzp("pout_1", "ins_000001", status="failed"), rzp("pout_2", "ins_000001")]))
    assert r.verdict == MATCHED


@pytest.mark.parametrize("status,verdict", [("queued", AMBIGUOUS), ("processing", AMBIGUOUS),
                                            ("reversed", MISSING), ("rejected", MISSING),
                                            ("something_new", AMBIGUOUS)])
def test_payout_states(status, verdict):
    assert one(run([ins()], [rzp("pout_1", "ins_000001", status=status)])).verdict == verdict


def test_no_payout_missing_after_window_ambiguous_before():
    assert one(run([ins()], [])).verdict == MISSING
    assert one(run([ins()], [], at=T0 + 1000)).verdict == AMBIGUOUS


def test_payout_with_no_instruction_is_flagged():
    # the Crafty Falcon path: a stolen credential calls the payout API directly
    rep = run([ins()], [rzp("pout_1", "ins_000001"), rzp("pout_9", "", amount=99_000_000, fa="fa_mule")])
    bad = one(rep, "unapproved_event")
    assert bad.verdict == CONFLICT and "pout_9" in bad.reasons[0] and not rep.ok


def test_failed_unapproved_payout_is_not_reported_but_queued_one_is():
    rep = run([], [rzp("pout_1", "ins_x", status="failed"), rzp("pout_2", "ins_y", status="queued")])
    assert [r.event_ids for r in rep.results] == [["pout_2"]]


def test_instruction_from_untrusted_key_does_not_cover_its_payout():
    forged = sign_instruction(Signer.generate(), originator="x", amount_minor=100, currency="INR",
                              beneficiary=token_beneficiary(FA), purpose="p", reference="r", approval_ref="a",
                              approved_by="b", policy="c", not_before_ms=T0, instruction_id="ins_forged")
    rep = run([forged], [rzp("pout_1", "ins_forged", amount=100)])
    kinds = sorted((r.kind, r.verdict) for r in rep.results)
    assert kinds == [("approval", CONFLICT), ("unapproved_event", CONFLICT)]


def test_bank_account_records_are_checked(tmp_path):
    i = ins(beneficiary=bank_beneficiary("HDFC0001234", "50100012345678"))
    rows = [{"payout_id": "p1", "reference": i.instruction_id, "amount_minor": "4850000", "currency": "INR",
             "status": "processed", "time": str(T0 + 1000), "ifsc": "HDFC0001234", "account_number": "50100012345679"}]
    path = tmp_path / "payouts.csv"
    path.write_text("\n".join([",".join(rows[0]), ",".join(rows[0].values())]), encoding="utf-8")
    r = one(run([i], load_payouts(path, "generic")))
    assert r.verdict == CONFLICT and "different beneficiary" in r.reasons[0]


def test_record_without_beneficiary_cannot_match():
    r = one(run([ins()], [rzp("pout_1", "ins_000001", fa="")]))
    assert r.verdict == CONFLICT and "no beneficiary" in r.reasons[0]


@pytest.mark.parametrize("layout", ["collection", "list", "jsonl"])
def test_razorpayx_file_layouts(tmp_path, layout):
    rows = [{"id": "pout_1", "fund_account_id": FA, "amount": 4_850_000, "currency": "INR", "status": "processed",
             "reference_id": "ins_000001", "created_at": (T0 + 60_000) // 1000}]
    text = {"collection": json.dumps({"entity": "collection", "count": 1, "items": rows}),
            "list": json.dumps(rows), "jsonl": json.dumps(rows[0]) + "\n" + json.dumps({**rows[0], "id": "pout_2"})}[layout]
    p = tmp_path / "payouts.json"
    p.write_text(text, encoding="utf-8")
    recs = load_payouts(p, "razorpayx")
    assert recs[0].payout_id == "pout_1" and recs[0].time_ms == T0 + 60_000 and recs[0].reference == "ins_000001"


def test_fractional_amount_is_refused():
    with pytest.raises(ValueError, match="minor units"):
        payout_from_row({"id": "p", "amount": "48500.00"}, MAPPINGS["razorpayx"])


def test_unknown_source_and_empty_file(tmp_path):
    p = tmp_path / "e.json"
    p.write_text("", encoding="utf-8")
    assert load_payouts(p, "razorpayx") == []
    with pytest.raises(ValueError, match="unknown payout source"):
        load_payouts(p, "stripe")


def test_iso_and_millisecond_times():
    a = payout_from_row({"payout_id": "p", "amount_minor": 1, "time": "2026-11-11T10:00:00Z"}, MAPPINGS["generic"])
    b = payout_from_row({"payout_id": "p", "amount_minor": 1, "time": T0}, MAPPINGS["generic"])
    assert a.time_ms == 1_794_391_200_000 and b.time_ms == T0
