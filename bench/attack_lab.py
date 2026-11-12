"""Attack lab: detection and false-alarm rates on realistic, noisy payout data, plus gate load.

Legitimate traffic carries the noise real payout feeds have (duplicate webhooks, status
progressions, failed-then-retried payouts, provider clock skew, queued and reversed payouts).
Attacks follow documented incidents:
  A1 Crafty Falcon (CERT-In CIAD-2026-0046/0058): stolen payout credentials, direct payouts
     to mule accounts with no approval, including Rs 1 micro "test" transfers
  A2 beneficiary swap        A3 amount inflation      A4 double disbursal
  A5 valid instruction id reused on an extra payout   A6 instruction forged with the attacker's key
  A7 one approval split into several payouts           A8 stale approval paid after its window
Settlement pass (bank statement as an independent source):
  A9 forged "processed" status with no bank debit (2022 Razorpay authorisation-manipulation
     pattern): invisible to provider records alone, caught against the statement
  A10 debits on the bank statement that no payout explains (skimming outside the payout rail)
  Statement noise: bank posting delay up to a day, 30% of debits with no UTR (matched by the
  payout id in the narration), reversals posted as debit + matching credit.
usage: python attack_lab.py [n_instructions]
"""

import json
import random
import statistics
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

from aetherproof.core.instruction import PayoutRequest, ReplayStore, sign_instruction, token_beneficiary, verify_instruction
from aetherproof.core.payouts import PayoutRecord, reconcile_payouts
from aetherproof.core.signer import Signer

rng = random.Random(20261111)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
T0, WINDOW = 1_794_000_000_000, 15 * 60_000
lender, attacker = Signer.generate(), Signer.generate()
pid = iter(range(10**9))


def ins(i, signer=lender, amount=None):
    return sign_instruction(signer, originator="lender", amount_minor=amount or rng.randrange(500_000, 50_000_000, 100),
                            currency="INR", beneficiary=token_beneficiary(f"fa_b{i:07d}"), purpose="loan_disbursal",
                            reference=f"LN-{i}", approval_ref=f"SAN-{i}", approved_by="credit-ops", policy="v3",
                            not_before_ms=T0 + i * 50, validity_ms=WINDOW, instruction_id=f"ins_{i:010d}")


def rec(ref, amount, fa, status="processed", at=None, payout_id=None):
    payout_id = payout_id or f"pout_{next(pid):09d}"
    return PayoutRecord(payout_id=payout_id, reference=ref, amount_minor=amount, currency="INR", status=status,
                        time_ms=at, beneficiary_token=fa, utr=f"UTR{payout_id}")


t = time.perf_counter()
instructions = [ins(i) for i in range(N)]
t_sign = time.perf_counter() - t

records, expect, kind = [], {}, {}          # expect[instruction_id] = verdict; kind = label
ids = list(range(N))
rng.shuffle(ids)
cut = iter(ids)
take = lambda n: [next(cut) for _ in range(n)]
plan = {"A2": take(500), "A3": take(500), "A4": take(500), "A5": take(500), "A7": take(300), "A8": take(300), "A9": take(500),
        "queued": take(N // 100), "failed": take(N // 100), "reversed": take(N // 200)}
special = {i: k for k, v in plan.items() for i in v}

for i, x in enumerate(instructions):
    fa, amt, t_ok = x.beneficiary["value"], x.amount_minor, x.not_before_ms + rng.randrange(1_000, 600_000)
    skew = rng.randrange(-45_000, 45_000)
    k = special.get(i, "benign")
    kind[x.instruction_id] = k
    if k == "queued":
        records.append(rec(x.instruction_id, amt, fa, "queued", t_ok)); expect[x.instruction_id] = "ambiguous"; continue
    if k == "failed":
        records.append(rec(x.instruction_id, amt, fa, "failed", t_ok)); expect[x.instruction_id] = "missing"; continue
    if k == "reversed":
        p = f"pout_r{i}"
        records += [rec(x.instruction_id, amt, fa, "processed", t_ok, p), rec(x.instruction_id, amt, fa, "reversed", t_ok + 3_600_000, p)]
        expect[x.instruction_id] = "missing"; continue
    if k == "A2":
        records.append(rec(x.instruction_id, amt, f"fa_mule{i}", "processed", t_ok + skew)); expect[x.instruction_id] = "conflict"; continue
    if k == "A3":
        records.append(rec(x.instruction_id, amt * 3, fa, "processed", t_ok + skew)); expect[x.instruction_id] = "conflict"; continue
    if k == "A7":
        part = amt // 3
        records += [rec(x.instruction_id, part, fa, "processed", t_ok + j * 1000) for j in range(3)]
        expect[x.instruction_id] = "conflict"; continue
    if k == "A8":
        records.append(rec(x.instruction_id, amt, fa, "processed", x.not_after_ms + 3_600_000)); expect[x.instruction_id] = "conflict"; continue
    # benign noise on the normal path
    if rng.random() < 0.03:                          # failed, then retried with a new payout id
        records.append(rec(x.instruction_id, amt, fa, "failed", t_ok))
        t_ok += 30_000
    p = f"pout_n{i}"
    if rng.random() < 0.20:                          # processing -> processed
        records.append(rec(x.instruction_id, amt, fa, "processing", t_ok + skew, p))
    records.append(rec(x.instruction_id, amt, fa, "processed", t_ok + skew + 2_000, p))
    if rng.random() < 0.05:                          # duplicate webhook
        records.append(rec(x.instruction_id, amt, fa, "processed", t_ok + skew + 2_000, p))
    if k == "A4":
        records.append(rec(x.instruction_id, amt, fa, "processed", t_ok + 90_000)); expect[x.instruction_id] = "conflict"
    elif k == "A5":
        records.append(rec(x.instruction_id, amt, f"fa_mule{i}", "processed", t_ok + 120_000)); expect[x.instruction_id] = "conflict"
    else:
        expect[x.instruction_id] = "matched"

# A1: direct payouts with stolen credentials, no instruction; 500 of them Rs 1 test transfers
a1 = [rec("", 100 if j < 500 else rng.randrange(1_000_000, 30_000_000, 100), f"fa_mule{j % 40}", "processed", T0 + j * 997)
      for j in range(2_000)]
# A6: instructions minted with the attacker's own key, then paid
forged = [ins(N + j, signer=attacker) for j in range(300)]
a6 = [rec(f.instruction_id, f.amount_minor, f.beneficiary["value"], "processed", f.not_before_ms + 5_000) for f in forged]
records += a1 + a6
rng.shuffle(records)

t = time.perf_counter()
rep = reconcile_payouts(instructions + forged, records, lender.get_public_key(), as_of_ms=T0 + N * 50 + 2 * WINDOW)
t_rec = time.perf_counter() - t

got = {r.action_id: r.verdict for r in rep.results if r.kind == "approval"}
flagged_payouts = {e for r in rep.results if r.kind == "unapproved_event" for e in r.event_ids}
by_kind = defaultdict(lambda: [0, 0])
for iid, want in expect.items():
    k = kind[iid]
    by_kind[k][1] += 1
    by_kind[k][0] += got.get(iid) == want
benign_total = by_kind["benign"][1]
false_alarms = sum(1 for iid, k in kind.items() if k == "benign" and got.get(iid) != "matched")
a1_hit = sum(1 for r in a1 if r.payout_id in flagged_payouts)
a1_micro = sum(1 for r in a1[:500] if r.payout_id in flagged_payouts)
a6_hit = sum(1 for f in forged if got.get(f.instruction_id) == "conflict")
a6_pay = sum(1 for r in a6 if r.payout_id in flagged_payouts)
a9_ids = {instructions[i].instruction_id for i in plan["A9"]}
a9_clean_without_statement = sum(1 for iid in a9_ids if got.get(iid) == "matched")
by_kind.pop("A9", None)   # provider records alone cannot catch A9; reported separately, not as a "pass"

# ---------------------------------------------------------------- settlement pass (bank statement)
from aetherproof.core.payouts import SUCCESS
from aetherproof.core.settlement import BankEntry

latest = {}
for r in records:
    if r.payout_id not in latest or r.time_ms >= latest[r.payout_id].time_ms:
        latest[r.payout_id] = r
statement = []
for r in latest.values():
    if r.reference in a9_ids:
        continue                                     # A9: provider says processed, money never left
    if r.status in SUCCESS or r.status == "reversed":
        no_utr = rng.random() < 0.30                 # bank omits the UTR; narration quotes the payout id
        statement.append(BankEntry(f"d_{r.payout_id}", "" if no_utr else r.utr, r.amount_minor, "INR", "debit",
                                   r.time_ms + rng.randrange(5_000, 86_400_000), f"IMPS/{r.payout_id}/NBFC"))
        if r.status == "reversed":                   # reversal: the debit comes back as a credit
            statement.append(BankEntry(f"c_{r.payout_id}", r.utr, r.amount_minor, "INR", "credit", r.time_ms + 3_700_000))
a10 = [BankEntry(f"skim_{j}", f"UTRX{j}", rng.randrange(100_000, 5_000_000, 100), "INR", "debit", T0 + j * 7_001, "NEFT/VENDOR")
       for j in range(200)]
statement += a10
rng.shuffle(statement)
t = time.perf_counter()
rep2 = reconcile_payouts(instructions + forged, records, lender.get_public_key(), as_of_ms=T0 + N * 50 + 3 * 86_400_000,
                         statement=statement)
t_rec2 = time.perf_counter() - t
got2 = {r.action_id: r for r in rep2.results if r.kind == "approval"}
false_alarms2 = sum(1 for iid, k in kind.items() if k == "benign" and (got2[iid].verdict != "matched" or got2[iid].settlement != "confirmed"))
attacks_still_caught = sum(1 for iid, want in expect.items() if kind[iid] not in ("benign", "A9") and got2[iid].verdict == want)
attacks_total = sum(1 for iid in expect if kind[iid] not in ("benign", "A9"))
a9_caught = sum(1 for iid in a9_ids if got2[iid].verdict == "conflict" and got2[iid].settlement == "absent")
unexplained = {e for r in rep2.results if r.kind == "unexplained_debit" for e in r.event_ids}
a10_caught = sum(1 for e in a10 if e.entry_id in unexplained)
unexplained_false = len(unexplained) - a10_caught

# ---------------------------------------------------------------- gate under load
gate_n = 20_000 if N >= 20_000 else N
tmp = Path(tempfile.mkdtemp())
store = ReplayStore(str(tmp / "replay.db"))
key = lender.get_public_key()
lat = []
now = lambda x: x.not_before_ms + 1_000
for x in instructions[:gate_n]:
    req = PayoutRequest(x.amount_minor, "INR", x.instruction_id, x.beneficiary["value"])
    s = time.perf_counter_ns()
    d = verify_instruction(x, req, key, store, now_ms=now(x))
    lat.append((time.perf_counter_ns() - s) / 1e6)
    assert d.allowed, d
lat.sort()
attacks = {
    "replay of a used instruction": [verify_instruction(x, PayoutRequest(x.amount_minor, "INR", x.instruction_id, x.beneficiary["value"]), key, store, now_ms=now(x)) for x in instructions[:2000]],
    "changed amount": [verify_instruction(x, PayoutRequest(x.amount_minor + 100, "INR", x.instruction_id, x.beneficiary["value"]), key, store, now_ms=now(x)) for x in instructions[gate_n:gate_n + 2000]],
    "mule beneficiary": [verify_instruction(x, PayoutRequest(x.amount_minor, "INR", x.instruction_id, "fa_mule"), key, store, now_ms=now(x)) for x in instructions[gate_n:gate_n + 2000]],
    "expired approval": [verify_instruction(x, PayoutRequest(x.amount_minor, "INR", x.instruction_id, x.beneficiary["value"]), key, store, now_ms=x.not_after_ms + 1) for x in instructions[gate_n:gate_n + 2000]],
    "forged with attacker key": [verify_instruction(f, PayoutRequest(f.amount_minor, "INR", f.instruction_id, f.beneficiary["value"]), key, store, now_ms=now(f)) for f in forged],
}
# 8 executors racing on the same 1,000 instructions: each must pay exactly once
race = instructions[gate_n + 2000:gate_n + 3000]
wins = Counter()
lock = threading.Lock()


def worker():
    for x in race:
        d = verify_instruction(x, PayoutRequest(x.amount_minor, "INR", x.instruction_id, x.beneficiary["value"]), key, store, now_ms=now(x))
        if d.allowed:
            with lock:
                wins[x.instruction_id] += 1


threads = [threading.Thread(target=worker) for _ in range(8)]
t = time.perf_counter()
for th in threads:
    th.start()
for th in threads:
    th.join()
t_race = time.perf_counter() - t
store.close()

out = {
    "instructions": N, "payout_records": len(records), "sign_s": round(t_sign, 2), "reconcile_s": round(t_rec, 2),
    "per_scenario_correct": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_kind.items())},
    "false_alarm_rate_benign": f"{false_alarms}/{benign_total} = {false_alarms / benign_total:.5%}",
    "A1_direct_payouts_flagged": f"{a1_hit}/2000 (Rs 1 test transfers {a1_micro}/500)",
    "A6_forged_instructions": f"{a6_hit}/300 rejected, {a6_pay}/300 payouts flagged",
    "A9_without_statement": f"{a9_clean_without_statement}/500 look MATCHED from provider records alone (the gap)",
    "settlement_pass": {
        "statement_entries": len(statement), "reconcile_s": round(t_rec2, 2),
        "A9_forged_processed_caught": f"{a9_caught}/500",
        "A10_unexplained_debits_caught": f"{a10_caught}/200",
        "benign_false_alarms": f"{false_alarms2}/{benign_total}",
        "unexplained_debit_false_alarms": unexplained_false,
        "earlier_attacks_still_correct": f"{attacks_still_caught}/{attacks_total}",
    },
    "gate_latency_ms": {"p50": round(lat[len(lat) // 2], 3), "p99": round(lat[int(len(lat) * 0.99)], 3), "max": round(lat[-1], 3), "n": gate_n},
    "gate_attacks_rejected": {k: f"{sum(not d.allowed for d in v)}/{len(v)}" for k, v in attacks.items()},
    "race_8_executors": f"{sum(1 for c in wins.values() if c == 1)}/{len(race)} paid exactly once, {sum(1 for c in wins.values() if c > 1)} paid twice, {t_race:.2f}s",
}
print(json.dumps(out, indent=2))
ok = (false_alarms == 0 and all(v[0] == v[1] for v in by_kind.values()) and a1_hit == 2000 and a6_hit == 300
      and all(all(not d.allowed for d in v) for v in attacks.values()) and all(c == 1 for c in wins.values()) and len(wins) == len(race)
      and a9_caught == 500 and a10_caught == 200 and false_alarms2 == 0 and unexplained_false == 0 and attacks_still_caught == attacks_total)
print("PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
