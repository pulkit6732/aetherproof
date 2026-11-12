"""Unknown-attack fuzzing and failure drills. Everything runs in a fresh temp folder; nothing
outside it is read or written.

Part A, mutation fuzzing (attacks nobody wrote down): random corruptions of signed
instructions, payout requests, provider payout rows and bank statement rows. An oracle
written independently of the product decides what a correct answer is:
  - the gate may ALLOW only an unmodified instruction with an equivalent request, once;
  - reconciliation may say MATCHED only when one successful payout equals the instruction
    (amount, currency, exact beneficiary token, inside the window) and an unused bank debit
    with the same amount carries its UTR or its payout id;
  - every successful payout without a trusted instruction must be flagged.
Any disagreement is printed as a fail-open finding.

Part B, failure drills: break one layer at a time and show which layer catches it.
usage: python bench/unknown_attacks.py [cases]   (default 40,000)
"""

import copy
import json
import random
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from aetherproof.core.instruction import (PaymentInstruction, PayoutRequest, ReplayStore, bank_beneficiary,
                                          sign_instruction, token_beneficiary, verify_instruction)
from aetherproof.core.payouts import CLOCK_TOLERANCE_MS, MAPPINGS, SUCCESS, payout_from_row, reconcile_payouts
from aetherproof.core.settlement import entry_from_row
from aetherproof.core.signer import Signer

N = int(sys.argv[1]) if len(sys.argv) > 1 else 40_000
rng = random.Random(20261112)
TMP = Path(tempfile.mkdtemp(prefix="ap_unknown_"))
T0, WINDOW, DAY = 1_795_000_000_000, 15 * 60_000, 86_400_000
ORIG, ATTACKER = Signer.generate(), Signer.generate()
KEY = ORIG.get_public_key()
findings = []

HOMOGLYPH = {"0": "O", "O": "0", "1": "l", "l": "1", "a": "а", "e": "е", "o": "о", "_": "-"}


def mutate_str(s):
    ops = [lambda x: x + " ", lambda x: " " + x, lambda x: x.upper(), lambda x: x.lower(), lambda x: x[:-1],
           lambda x: "", lambda x: x + "​", lambda x: x[:len(x) // 2] + "​" + x[len(x) // 2:],
           lambda x: "".join(HOMOGLYPH.get(c, c) for c in x), lambda x: x + x[-1:],
           lambda x: x.replace("1", "１"), lambda x: x[::-1]]
    return rng.choice(ops)(s)


def mutate_int(v):
    return rng.choice([v + 1, v - 1, v * 10, v // 10, -v, 0, v + 10**15, str(v), float(v) + 0.5, None])


def mutate_value(v):
    if isinstance(v, bool) or v is None:
        return rng.choice(["", 0, "x", None, True])
    if isinstance(v, int):
        return mutate_int(v)
    if isinstance(v, str):
        return mutate_str(v) if v else rng.choice(["x", " ", "​"])
    return v


# ======================================================================== Part A1: gate
def gate_fuzz(n):
    store = ReplayStore(str(TMP / "replay.db"))
    allows, cases, refused = {}, 0, 0
    bases = max(1, n // 25)
    for b in range(bases):
        bank = b % 3 == 0
        ben = bank_beneficiary("HDFC0001234", "000123456789") if bank else token_beneficiary(f"fa_b{b:06d}")
        ins = sign_instruction(ORIG, originator="lender", amount_minor=rng.randrange(100, 10**9), currency="INR",
                               beneficiary=ben, purpose="loan_disbursal", reference=f"LN-{b}", approval_ref=f"S-{b}",
                               approved_by="ops", policy="v3", not_before_ms=T0, validity_ms=WINDOW,
                               instruction_id=f"ins_{b:012d}")
        orig = json.loads(ins.to_json())
        good = dict(amount_minor=ins.amount_minor, currency="INR", reference=ins.instruction_id,
                    beneficiary_token="" if bank else f"fa_b{b:06d}",
                    ifsc="HDFC0001234" if bank else "", account_number="000123456789" if bank else "")
        for _ in range(25):
            cases += 1
            mut, rq = copy.deepcopy(orig), dict(good)
            what = rng.random()
            if what < 0.45:                                  # tamper with the signed instruction
                path = rng.choice([k for k in mut if k != "beneficiary"] + ["beneficiary." + k for k in mut["beneficiary"]])
                if path.startswith("beneficiary."):
                    k = path.split(".", 1)[1]
                    mut["beneficiary"][k] = mutate_value(mut["beneficiary"][k])
                else:
                    mut[path] = mutate_value(mut[path])
            elif what < 0.55:                                # forge: attacker signs a changed copy
                forged = sign_instruction(ATTACKER, originator="lender", amount_minor=ins.amount_minor * 10, currency="INR",
                                          beneficiary=token_beneficiary("fa_mule"), purpose="loan_disbursal",
                                          reference=f"LN-{b}", approval_ref=f"S-{b}", approved_by="ops", policy="v3",
                                          not_before_ms=T0, validity_ms=WINDOW, instruction_id=ins.instruction_id)
                mut = json.loads(forged.to_json())
                if rng.random() < 0.5:
                    mut["signing_key_id"] = orig["signing_key_id"]     # claim the lender's key id
            elif what < 0.95:                                # tamper with the payout request
                k = rng.choice(list(rq))
                rq[k] = mutate_value(rq[k]) if rq[k] != "" else rng.choice(["fa_mule", "x", " "])
            # else: the untouched original request (the only kind that may be allowed, once)
            try:
                p_ins = PaymentInstruction.from_json(json.dumps(mut))
                request = PayoutRequest(**rq)
                d = verify_instruction(p_ins, request, KEY, store, now_ms=T0 + 60_000)
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                refused += 1                                # parse refused: fail closed
                continue
            equivalent = (mut == orig and rq["amount_minor"] == good["amount_minor"]
                          and isinstance(rq["currency"], str) and rq["currency"].upper() == "INR"
                          and rq["reference"] == good["reference"]
                          and (rq["beneficiary_token"] == good["beneficiary_token"] if not bank else
                               (isinstance(rq["ifsc"], str) and rq["ifsc"].strip().upper() == "HDFC0001234"
                                and isinstance(rq["account_number"], str) and rq["account_number"].strip() == "000123456789")))
            if d.verdict == "allow":
                allows[ins.instruction_id] = allows.get(ins.instruction_id, 0) + 1
                if not equivalent:
                    diff = {k: (orig.get(k), mut.get(k)) for k in set(orig) | set(mut) if orig.get(k) != mut.get(k)}
                    findings.append(("gate", f"ALLOW for a modified case: instruction diff={diff} request={rq}"))
    store.close()
    double = sum(1 for c in allows.values() if c > 1)
    if double:
        findings.append(("gate", f"{double} instructions allowed more than once"))
    return {"cases": cases, "parse_refused": refused, "instructions_allowed_once": len(allows), "allowed_twice": double}


# ======================================================================== Part A2: reconcile + settlement
def recon_fuzz(n):
    cases = refused = flagged_ok = 0
    m = MAPPINGS["razorpayx"]
    for i in range(n):
        ins = sign_instruction(ORIG, originator="lender", amount_minor=rng.randrange(100, 10**9), currency="INR",
                               beneficiary=token_beneficiary(f"fa_{i}"), purpose="p", reference=f"LN-{i}",
                               approval_ref="a", approved_by="b", policy="c", not_before_ms=T0, validity_ms=WINDOW,
                               instruction_id=f"ins_r{i:010d}")
        row = {"id": f"pout_{i}", "reference_id": ins.instruction_id, "amount": ins.amount_minor, "currency": "INR",
               "fund_account_id": f"fa_{i}", "status": "processed", "created_at": (T0 + 120_000) // 1000, "utr": f"UTR{i}"}
        deb = {"entry_id": f"d_{i}", "utr": f"UTR{i}", "amount_minor": ins.amount_minor, "currency": "INR",
               "direction": "debit", "time": T0 + 300_000, "narration": f"IMPS/pout_{i}/X"}
        rows, debs = [row], [deb]
        for _ in range(rng.choice([1, 1, 2, 3])):
            what = rng.random()
            target = rng.choice(rows) if what < 0.6 or not debs else rng.choice(debs)
            k = rng.choice(list(target))
            target[k] = mutate_value(target[k])
            if rng.random() < 0.08:                          # a second, cloned payout row
                rows.append(dict(rows[0], id=f"pout_{i}_dup{rng.randrange(9)}"))
            if rng.random() < 0.05:                          # the debit disappears
                debs.clear()
        cases += 1
        try:
            recs = [payout_from_row(r, m) for r in rows]
            stmt = [entry_from_row(d) for d in debs]
            rep = reconcile_payouts([ins], recs, KEY, as_of_ms=T0 + 3 * DAY, statement=stmt)
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            refused += 1
            continue
        res = [r for r in rep.results if r.kind == "approval"][0]
        # independent oracle
        latest = {}
        for r in recs:
            if r.payout_id not in latest or r.time_ms >= latest[r.payout_id].time_ms:
                latest[r.payout_id] = r
        mine = [r for r in latest.values() if r.reference == ins.instruction_id]
        done = [r for r in mine if r.status in SUCCESS]
        ok_payout = (len(done) == 1 and done[0].amount_minor == ins.amount_minor and done[0].currency == "INR"
                     and done[0].beneficiary_token == f"fa_{i}"
                     and T0 - CLOCK_TOLERANCE_MS <= done[0].time_ms <= ins.not_after_ms + CLOCK_TOLERANCE_MS)
        # statement amounts: banks export debits as negative numbers; the loader takes the magnitude by design
        ok_bank = ok_payout and any(e.direction == "debit" and abs(e.amount_minor) == ins.amount_minor
                                    and ((done[0].utr and e.utr == done[0].utr) or
                                         (done[0].payout_id and done[0].payout_id in e.narration.replace("/", " ").split()))
                                    for e in stmt)
        if res.verdict == "matched" and not (ok_payout and ok_bank):
            findings.append(("reconcile", f"MATCHED but oracle disagrees: rows={rows} debits={debs}"))
        # every successful payout not tied to this instruction must be flagged
        flagged = {e for r in rep.results if r.verdict == "conflict" for e in r.event_ids}
        for r in latest.values():
            if r.status in SUCCESS and r.reference != ins.instruction_id:
                if r.payout_id in flagged:
                    flagged_ok += 1
                else:
                    findings.append(("reconcile", f"unapproved payout not flagged: {r}"))
    return {"cases": cases, "parse_refused": refused, "unapproved_payouts_flagged": flagged_ok}


# ======================================================================== Part B: failure drills
def drills():
    out = []
    ins = sign_instruction(ORIG, originator="lender", amount_minor=4_850_000, currency="INR",
                           beneficiary=token_beneficiary("fa_1"), purpose="p", reference="LN-1", approval_ref="a",
                           approved_by="b", policy="c", not_before_ms=T0, validity_ms=WINDOW, instruction_id="ins_drill000000001")
    req = PayoutRequest(4_850_000, "INR", ins.instruction_id, "fa_1")
    row = lambda pid, t=(T0 + 120_000) // 1000: payout_from_row(
        {"id": pid, "reference_id": ins.instruction_id, "amount": 4_850_000, "currency": "INR", "fund_account_id": "fa_1",
         "status": "processed", "created_at": t, "utr": f"U{pid}"}, MAPPINGS["razorpayx"])

    # B1 replay store lost (deleted / restored from an old backup) -> gate pays twice; reconcile catches it
    s1 = ReplayStore(str(TMP / "b1a.db"))
    first = verify_instruction(ins, req, KEY, s1, now_ms=T0 + 60_000).verdict
    s1.close()
    s2 = ReplayStore(str(TMP / "b1b.db"))                    # the "lost" store
    second = verify_instruction(ins, req, KEY, s2, now_ms=T0 + 60_000).verdict
    s2.close()
    rep = reconcile_payouts([ins], [row("p1"), row("p2")], KEY, as_of_ms=T0 + DAY)
    caught = rep.results[0].verdict == "conflict" and "paid 2 times" in rep.results[0].reasons[0]
    out.append(("B1 replay store lost", f"gate: {first} then {second} (prevention lost)",
                "reconcile: CONFLICT 'paid 2 times'" if caught else "NOT CAUGHT", caught))

    # B2 replay store corrupted -> the gate cannot start, so nothing is allowed (fail closed)
    bad = TMP / "b2.db"
    bad.write_bytes(b"not a database" * 100)
    try:
        ReplayStore(str(bad))
        verdict, ok = "store opened on garbage", False
    except sqlite3.DatabaseError as e:
        verdict, ok = f"refused to start ({type(e).__name__})", True
    out.append(("B2 replay store corrupted", "gate store", verdict, ok))

    # B3 integrator forgets the replay store -> REVIEW, never ALLOW
    d = verify_instruction(ins, req, KEY, None, now_ms=T0 + 60_000)
    out.append(("B3 no replay store", "gate", d.verdict.upper(), d.verdict == "review"))

    # B4 executor clock set back a day -> stale approval allowed; provider time exposes it
    s4 = ReplayStore(str(TMP / "b4.db"))
    stale = sign_instruction(ORIG, originator="lender", amount_minor=4_850_000, currency="INR",
                             beneficiary=token_beneficiary("fa_1"), purpose="p", reference="LN-2", approval_ref="a",
                             approved_by="b", policy="c", not_before_ms=T0 - DAY, validity_ms=WINDOW,
                             instruction_id="ins_drill000000002")
    g = verify_instruction(stale, PayoutRequest(4_850_000, "INR", stale.instruction_id, "fa_1"), KEY, s4,
                           now_ms=T0 - DAY + 60_000).verdict           # the wrong clock thinks it is still valid
    s4.close()
    r = payout_from_row({"id": "p4", "reference_id": stale.instruction_id, "amount": 4_850_000, "currency": "INR",
                         "fund_account_id": "fa_1", "status": "processed", "created_at": (T0 + 60_000) // 1000},
                        MAPPINGS["razorpayx"])
    res = reconcile_payouts([stale], [r], KEY, as_of_ms=T0 + DAY).results[0]
    ok = res.verdict == "conflict" and any("outside" in x for x in res.reasons)
    out.append(("B4 executor clock wrong", f"gate: {g} (clock fooled)", "reconcile: CONFLICT outside window" if ok else "NOT CAUGHT", ok))

    # B5 no bank statement supplied -> nothing claims settlement was verified
    res = reconcile_payouts([ins], [row("p5")], KEY, as_of_ms=T0 + DAY).results[0]
    out.append(("B5 bank statement missing", "settlement", f"{res.verdict.upper()} with settlement={res.settlement}",
                res.settlement == "not_checked"))

    # B6 originator signing key stolen -> attacker's instruction is cryptographically valid
    s6 = ReplayStore(str(TMP / "b6.db"))
    evil = sign_instruction(ORIG, originator="lender", amount_minor=9_900_000, currency="INR",
                            beneficiary=token_beneficiary("fa_mule"), purpose="p", reference="LN-404", approval_ref="none",
                            approved_by="attacker", policy="c", not_before_ms=T0, validity_ms=WINDOW,
                            instruction_id="ins_drill000000006")
    g = verify_instruction(evil, PayoutRequest(9_900_000, "INR", evil.instruction_id, "fa_mule"), KEY, s6, now_ms=T0 + 60_000).verdict
    s6.close()
    out.append(("B6 signing key stolen", f"gate: {g}", "NOT CAUGHT by AetherProof alone: needs sanction-register "
                "cross-check and HSM/KMS key custody", False))

    # B7 one insider forges both the provider export and the statement file -> both lie consistently
    out.append(("B7 insider forges provider + statement files", "settlement", "NOT CAUGHT: needs a direct bank "
                "feed (SFTP / account aggregator / bank API)", False))
    return out


if __name__ == "__main__":
    t = time.perf_counter()
    g = gate_fuzz(N)
    r = recon_fuzz(N // 2)
    elapsed = time.perf_counter() - t
    print(json.dumps({"gate_fuzz": g, "reconcile_fuzz": r, "fail_open_findings": len(findings),
                      "seconds": round(elapsed, 1)}, indent=1, ensure_ascii=False))
    for kind, msg in findings[:10]:
        print(f"FINDING [{kind}] {msg[:300]}")
    print("\nFAILURE DRILLS")
    for name, layer, result, ok in drills():
        print(f"{'CAUGHT ' if ok else 'GAP    '} {name:<46} {layer:<38} {result}")
    sys.exit(1 if findings else 0)
