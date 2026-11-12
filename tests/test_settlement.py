"""Independent settlement evidence: provider status vs the bank statement."""

import json

import pytest

from aetherproof.core.instruction import sign_instruction, token_beneficiary
from aetherproof.core.payouts import MAPPINGS, payout_from_row, reconcile_payouts
from aetherproof.core.reconcile import AMBIGUOUS, CONFLICT, MATCHED
from aetherproof.core.settlement import entry_from_row, load_statement
from aetherproof.core.signer import Signer

T0 = 1_793_000_000_000
DAY = 24 * 3600 * 1000
ORIG = Signer.generate()


def ins(i=1, amount=4_850_000):
    return sign_instruction(ORIG, originator="lender", amount_minor=amount, currency="INR", beneficiary=token_beneficiary("fa_1"),
                            purpose="p", reference=f"LN-{i}", approval_ref="a", approved_by="b", policy="c",
                            not_before_ms=T0, instruction_id=f"ins_{i:06d}")


def pay(pid, ref, amount=4_850_000, utr="UTR1", status="processed"):
    return payout_from_row({"id": pid, "reference_id": ref, "amount": amount, "currency": "INR", "fund_account_id": "fa_1",
                            "status": status, "created_at": (T0 + 60_000) // 1000, "utr": utr}, MAPPINGS["razorpayx"])


def debit(eid, amount=4_850_000, utr="UTR1", narration=""):
    return entry_from_row({"entry_id": eid, "utr": utr, "amount_minor": amount, "currency": "INR", "direction": "debit",
                           "time": T0 + 120_000, "narration": narration})


def run(instructions, payouts, statement, at=T0 + 3 * DAY):
    return reconcile_payouts(instructions, payouts, ORIG.get_public_key(), as_of_ms=at, statement=statement)


def approval(rep):
    return [r for r in rep.results if r.kind == "approval"][0]


def test_without_a_statement_settlement_is_not_checked_and_verdicts_unchanged():
    r = approval(reconcile_payouts([ins()], [pay("p1", "ins_000001")], ORIG.get_public_key(), as_of_ms=T0 + DAY))
    assert r.verdict == MATCHED and r.settlement == "not_checked"


def test_bank_debit_confirms_by_utr():
    r = approval(run([ins()], [pay("p1", "ins_000001")], [debit("b1")]))
    assert r.verdict == MATCHED and r.settlement == "confirmed"


def test_bank_debit_confirms_by_payout_id_in_narration():
    r = approval(run([ins()], [pay("p1", "ins_000001", utr="")], [debit("b1", utr="", narration="IMPS/p1/LN-1")]))
    assert r.settlement == "confirmed"


def test_narration_match_is_whole_token_not_substring():
    # "p1" must not claim the debit whose narration names "p12"
    r = approval(run([ins()], [pay("p1", "ins_000001", utr="")], [debit("b1", utr="", narration="IMPS/p12/LN-9")]))
    assert r.settlement == "absent"


def test_forged_processed_status_with_no_bank_debit_is_a_conflict():
    # the Razorpay 2022 pattern: the provider record says success, the money never moved
    r = approval(run([ins()], [pay("p1", "ins_000001")], []))
    assert r.verdict == CONFLICT and r.settlement == "absent" and "no matching debit" in r.reasons[-1]


def test_debit_not_yet_posted_inside_grace_is_pending_not_fraud():
    r = approval(run([ins()], [pay("p1", "ins_000001")], [], at=T0 + 3600_000))
    assert r.verdict == AMBIGUOUS and r.settlement == "pending"


def test_bank_amount_differs_from_provider_amount():
    r = approval(run([ins()], [pay("p1", "ins_000001")], [debit("b1", amount=5_850_000)]))
    assert r.verdict == CONFLICT and r.settlement == "mismatch" and "bank debited 58,500.00 INR" in r.reasons[-1]


def test_debit_that_no_payout_explains_is_flagged():
    rep = run([ins()], [pay("p1", "ins_000001")], [debit("b1"), debit("b9", amount=990_000, utr="UTR9")])
    extra = [r for r in rep.results if r.kind == "unexplained_debit"]
    assert len(extra) == 1 and extra[0].event_ids == ["b9"] and extra[0].verdict == CONFLICT


def test_reversed_payout_debit_returned_by_credit_is_not_unexplained():
    back = entry_from_row({"entry_id": "c1", "utr": "UTR9", "amount_minor": 990_000, "currency": "INR", "direction": "credit", "time": T0})
    rep = run([ins()], [pay("p1", "ins_000001")], [debit("b1"), debit("b9", amount=990_000, utr="UTR9"), back])
    assert [r for r in rep.results if r.kind == "unexplained_debit"] == []
    partial = entry_from_row({"entry_id": "c2", "utr": "UTR9", "amount_minor": 100, "currency": "INR", "direction": "credit", "time": T0})
    rep = run([ins()], [pay("p1", "ins_000001")], [debit("b1"), debit("b9", amount=990_000, utr="UTR9"), partial])
    assert len([r for r in rep.results if r.kind == "unexplained_debit"]) == 1   # a partial refund does not explain it


def test_reversal_without_utr_on_the_debit_pairs_with_its_credit():
    back = entry_from_row({"entry_id": "c1", "utr": "UTR1", "amount_minor": 4_850_000, "currency": "INR", "direction": "credit", "time": T0})
    rep = run([ins()], [pay("p1", "ins_000001", status="reversed")], [debit("b1", utr="", narration="IMPS/p1/X"), back])
    r = approval(rep)
    assert r.verdict == "missing" and r.settlement == "returned"
    assert [x for x in rep.results if x.kind == "unexplained_debit"] == []


def test_reversal_claimed_but_money_never_returned_is_a_conflict():
    rep = run([ins()], [pay("p1", "ins_000001", status="reversed")], [debit("b1")])
    r = approval(rep)
    assert r.verdict == CONFLICT and r.settlement == "absent" and "no return credit" in r.reasons[-1]


def test_one_debit_cannot_settle_two_payouts():
    rep = run([ins(1), ins(2)], [pay("p1", "ins_000001"), pay("p2", "ins_000002", utr="UTR1")], [debit("b1")])
    states = sorted(r.settlement for r in rep.results if r.kind == "approval")
    assert states == ["absent", "confirmed"]


def test_credits_never_settle_payouts():
    credit = entry_from_row({"entry_id": "c1", "utr": "UTR1", "amount_minor": 4_850_000, "currency": "INR", "direction": "credit", "time": T0})
    assert approval(run([ins()], [pay("p1", "ins_000001")], [credit])).settlement == "absent"


def test_missing_optional_fields_load_as_empty_and_do_not_settle():
    e = entry_from_row({"entry_id": "b1", "utr": None, "amount_minor": 4_850_000, "currency": "INR", "direction": "debit",
                        "time": T0, "narration": None})
    assert e.utr == "" and e.narration == ""
    assert approval(run([ins()], [pay("p1", "ins_000001", utr="")], [e])).settlement == "absent"


@pytest.mark.parametrize("bad,needle", [({"direction": "sideways"}, "direction"), ({"amount_minor": "48500.00"}, "integer"),
                                        ({"amount_minor": None}, "integer"), ({"direction": None}, "direction")])
def test_bad_statement_rows_are_refused(bad, needle):
    row = {"entry_id": "e", "utr": "u", "amount_minor": 1, "currency": "INR", "direction": "debit", "time": T0, **bad}
    with pytest.raises(ValueError, match=needle):
        entry_from_row(row)


def test_statement_files_csv_and_json(tmp_path):
    csv_p = tmp_path / "stmt.csv"
    csv_p.write_text("entry_id,utr,amount_minor,currency,direction,time,narration\nb1,UTR1,4850000,INR,debit,2026-11-11T10:02:00Z,IMPS p1\n", encoding="utf-8")
    json_p = tmp_path / "stmt.json"
    json_p.write_text(json.dumps({"entries": [{"entry_id": "b1", "utr": "UTR1", "amount_minor": 4850000, "currency": "INR",
                                                "direction": "debit", "time": T0}]}), encoding="utf-8")
    assert load_statement(csv_p)[0].utr == "UTR1" and load_statement(json_p)[0].amount_minor == 4_850_000
    empty = tmp_path / "e.csv"
    empty.write_text("", encoding="utf-8")
    assert load_statement(empty) == []
