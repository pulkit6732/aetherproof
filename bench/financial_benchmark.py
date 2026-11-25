"""Financial adversarial benchmark: bank payouts, crypto withdrawals and stock orders, 16
attack families modelled on documented incidents, four control systems side by side.

S1  authenticated API: valid key from an allowed IP (what the stolen-credential attacks had)
S2  conventional policy engine, modelled on publicly documented provider controls: per payout
    and daily caps (atomic, no race), beneficiary allowlist that the API credential can extend,
    24 hour idempotency keys. A model, not any vendor's product.
S3  AetherProof 0.5.2 gate, real code: verify_instruction + ReplayStore
S4  AetherProof gate + limits + revocation (real code: core/limits.py), plus after the fact
    reconciliation against provider records and the bank statement (real code: reconcile_payouts)

Synthetic data only. Prints the table and writes financial_benchmark_result.json.
Run: python bench/financial_benchmark.py
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from aetherproof.contract import MATCHED  # noqa: E402
from aetherproof.core.instruction import PayoutRequest, ReplayStore, sign_instruction, token_beneficiary, verify_instruction  # noqa: E402
from aetherproof.core.limits import LimitPolicy, LimitStore, verify_with_limits  # noqa: E402
from aetherproof.core.payouts import PayoutRecord, reconcile_payouts  # noqa: E402
from aetherproof.core.settlement import BankEntry  # noqa: E402
from aetherproof.core.signer import Signer  # noqa: E402

T0 = 1_780_000_000_000          # fixed clock for reproducibility
MIN = 60_000
HOUR = 60 * MIN
VALIDITY = 15 * MIN             # AetherProof default instruction validity
IDEMPOTENCY_WINDOW = 24 * HOUR  # conventional engine dedupe window
POLICY = LimitPolicy(per_payout_max_minor=20_000_000, daily_max_minor=800_000_000, daily_count_max=500,
                     per_destination_daily_max_minor=20_000_000)  # paise: 2 lakh, 80 lakh, 500, 2 lakh
LEGIT_PER_ENV = 300
# trading repeats the same symbol all day, so its per destination cap is the account cap
POLICIES = {"bank_payout": POLICY, "crypto_withdrawal": POLICY,
            "stock_order": LimitPolicy(POLICY.per_payout_max_minor, POLICY.daily_max_minor, POLICY.daily_count_max,
                                       POLICY.daily_max_minor)}
SYSTEMS = ("S1_api_key", "S2_policy_engine", "S2b_policy_locked_allowlist", "S3_aetherproof_gate", "S4_aetherproof_full")

ENVS = {
    # dest(i) builds the destination; every field that must not change is inside the token
    "bank_payout": {"currency": "INR", "dest": lambda i: f"bank:HDFC0001234:5010{i:08d}", "mule": "bank:YESB0000001:9999000011"},
    "crypto_withdrawal": {"currency": "USD", "dest": lambda i: f"crypto:ethereum:USDC:0xA{i:039x}", "mule": "crypto:ethereum:USDC:0xBAD0000000000000000000000000000000000001"},
    "stock_order": {"currency": "INR", "dest": lambda i: f"stock:ACC-7:SYM{i % 40:02d}:BUY", "mule": "stock:ACC-9:SYM00:SELL"},
}


@dataclass
class Req:
    env: str
    dest: str
    amount: int
    currency: str
    t: int
    ins: object = None          # signed instruction presented, if any
    idem: str = ""              # idempotency key (conventional engines)
    legit: bool = False


# ------------------------------------------------------------------ the four systems
class S1:
    def decide(self, r):
        return True, "valid key from allowed IP"


class S2:
    def __init__(self, allowlist, policy):
        self.allow, self.idem, self.spent, self.count, self.p = set(allowlist), {}, 0, 0, policy

    def add_beneficiary(self, dest):   # API credential can add beneficiaries: the stolen key can too
        self.allow.add(dest)

    def decide(self, r):
        if r.idem and r.idem in self.idem and r.t - self.idem[r.idem] < IDEMPOTENCY_WINDOW:
            return False, "duplicate idempotency key"
        if r.dest not in self.allow:
            return False, "beneficiary not on allowlist"
        if r.amount > self.p.per_payout_max_minor:
            return False, "per payout cap"
        if self.spent + r.amount > self.p.daily_max_minor or self.count + 1 > self.p.daily_count_max:
            return False, "daily cap"
        self.spent += r.amount
        self.count += 1
        if r.idem:
            self.idem[r.idem] = r.t
        return True, ""


class S3:
    def __init__(self, keys, path):
        self.keys, self.replay = keys, ReplayStore(path)

    def decide(self, r):
        if r.ins is None:
            return False, "no signed instruction"
        d = verify_instruction(r.ins, PayoutRequest(r.amount, r.currency, r.ins.instruction_id, r.dest), self.keys, self.replay, now_ms=r.t)
        return d.allowed, "; ".join(d.reasons)


class S4:
    def __init__(self, keys, rpath, lpath):
        self.keys, self.rpath, self.lpath = keys, rpath, lpath
        self.replay, self.limits = ReplayStore(rpath), LimitStore(lpath)

    def decide(self, r, replay=None, limits=None):
        if r.ins is None:
            return False, "no signed instruction"
        d = verify_with_limits(r.ins, PayoutRequest(r.amount, r.currency, r.ins.instruction_id, r.dest), self.keys,
                               replay or self.replay, limits or self.limits, POLICIES[r.env], account=r.env, destination=r.dest, now_ms=r.t)
        return d.allowed, "; ".join(d.reasons)


# ------------------------------------------------------------------ helpers
def sign(signer, env, dest, amount, t, ref="LN"):
    return sign_instruction(signer, originator=env, amount_minor=amount, currency=ENVS[env]["currency"],
                            beneficiary=token_beneficiary(dest), purpose="disbursal", reference=ref,
                            approval_ref="SAN", approved_by="credit-ops", policy="v1", not_before_ms=t, validity_ms=VALIDITY)


def fresh_systems(tmp, tag, approver, allowlist, env):
    keys = approver.get_public_key()
    # S2b: same engine, but the allowlist can only change through a separate, uncompromised
    # approval path. The strongest fair version of a conventional engine.
    return {"S1_api_key": S1(), "S2_policy_engine": S2(allowlist, POLICIES[env]),
            "S2b_policy_locked_allowlist": S2(allowlist, POLICIES[env]),
            "S3_aetherproof_gate": S3(keys, os.path.join(tmp, f"{tag}_s3.db")),
            "S4_aetherproof_full": S4(keys, os.path.join(tmp, f"{tag}_s4r.db"), os.path.join(tmp, f"{tag}_s4l.db"))}


def run_requests(systems, reqs, timing):
    out = {}
    for name, sysm in systems.items():
        allowed_bad, allowed_bad_amt, blocked_legit, allowed = 0, 0, 0, 0
        for r in reqs:
            a = time.perf_counter()
            ok, _ = sysm.decide(r)
            timing.setdefault(name, []).append((time.perf_counter() - a) * 1000)
            allowed += ok
            if ok and not r.legit:
                allowed_bad += 1
                allowed_bad_amt += r.amount
            if not ok and r.legit:
                blocked_legit += 1
        out[name] = {"executed_unauthorized": allowed_bad, "amount_unauthorized_minor": allowed_bad_amt,
                     "legit_blocked": blocked_legit}
    return out


# ------------------------------------------------------------------ main
def main():
    rng = np.random.default_rng(20261125)
    tmp = tempfile.mkdtemp(prefix="finbench_")
    approver = Signer.generate()
    results, timing, legit_summary = {}, {}, {}

    for env, spec in ENVS.items():
        cur = spec["currency"]
        dests = [spec["dest"](i) for i in range(LEGIT_PER_ENV)]
        # legit traffic: loan sized amounts (median about 15,000 rupees), one signed approval each
        amts = np.clip(rng.lognormal(np.log(1_500_000), 0.6, LEGIT_PER_ENV).astype(int), 50_000, POLICY.per_payout_max_minor)
        amts[0] = POLICY.per_payout_max_minor                      # edge: exactly at the cap
        legit = []
        for i in range(LEGIT_PER_ENV):
            t = T0 + i * MIN
            ins = sign(approver, env, dests[i], int(amts[i]), t)
            legit.append(Req(env, dests[i], int(amts[i]), cur, t + (VALIDITY - 1000 if i == 1 else 2000), ins, f"idem-{env}-{i}", True))
        systems = fresh_systems(tmp, env, approver, dests, env)
        legit_summary[env] = run_requests(systems, legit, timing)
        # legit retry of payout 5 after a timeout: must not pay twice (correct outcome is a refusal)
        retry = Req(env, dests[5], int(amts[5]), cur, legit[5].t + 30_000, legit[5].ins, legit[5].idem, False)
        mule, last_t = spec["mule"], T0 + LEGIT_PER_ENV * MIN

        def attack(name, source, reqs, before=None):
            s = fresh_systems(tmp, f"{env}_{name}", approver, dests, env)
            # each attack runs against systems that have already seen the legit day
            run_requests(s, legit, {})
            if before:
                before(s)
            results.setdefault(name, {"source": source, "by_env": {}})["by_env"][env] = run_requests(s, reqs, {})

        attack("01_stolen_api_key_new_mule", "NBFC payout API heists, India 2026 (press, CERT-In advisory)",
               [Req(env, mule, 1_900_000, cur, last_t + i * 1000, None, f"atk-{i}") for i in range(20)],
               before=lambda s: s["S2_policy_engine"].add_beneficiary(mule))
        fresh = [sign(approver, env, dests[i], int(amts[i]), last_t) for i in range(10, 20)]
        attack("02_account_swapped_on_approved_loan", "Delhi NCR NBFC cases 2026: borrower account swapped for a mule",
               [Req(env, mule, int(amts[10 + i]), cur, last_t + 1000, fresh[i], f"swap-{i}") for i in range(10)],
               before=lambda s: s["S2_policy_engine"].add_beneficiary(mule))
        attack("03_amount_inflated", "Altered payment instructions (BEC and insider patterns, FBI IC3)",
               [Req(env, dests[10 + i], int(amts[10 + i]) * 3, cur, last_t + 1000, fresh[i], f"inf-{i}") for i in range(10)])
        attack("04_replay_same_idempotency_key", "Duplicate payouts from retried or replayed calls",
               [retry])
        attack("05_replay_new_idempotency_key", "Replay with a fresh request id",
               [Req(env, dests[i], int(amts[i]), cur, legit[i].t + 60_000, legit[i].ins, f"new-{i}") for i in range(10, 30)])
        attack("06_replay_after_48h", "Old approval reused later",
               [Req(env, dests[i], int(amts[i]), cur, legit[i].t + 48 * HOUR, legit[i].ins, f"late-{i}") for i in range(10, 30)])
        attack("07_structuring_small_payouts", "Delhi NBFC case: 317 transactions, Rs 12.84 crore (ThePrint)",
               [Req(env, mule, 499_000, cur, last_t + i * 500, None, f"str-{i}") for i in range(200)],
               before=lambda s: s["S2_policy_engine"].add_beneficiary(mule))
        attack("08_expired_authority", "Approval used after its window",
               [Req(env, dests[i], int(amts[i]), cur, last_t + VALIDITY + HOUR, fresh[i - 10], f"exp-{i}") for i in range(10, 20)])

        def revoke_all(s):
            for f in fresh:
                s["S4_aetherproof_full"].limits.revoke(f.instruction_id)
        attack("09_revoked_authority", "Loan cancelled after approval, payout still sent",
               [Req(env, dests[10 + i], int(amts[10 + i]), cur, last_t + 1000, fresh[i], f"rev-{i}") for i in range(10)],
               before=revoke_all)
        if env == "crypto_withdrawal":
            alt = [d.replace("crypto:ethereum:USDC:", "crypto:tron:USDT:") for d in dests[10:20]]
            attack("10_network_or_asset_swapped", "Same address on another chain or token (address poisoning, wrong network)",
                   [Req(env, alt[i], int(amts[10 + i]), cur, last_t + 1000, fresh[i], f"net-{i}") for i in range(10)],
                   before=lambda s: [s["S2_policy_engine"].add_beneficiary(x) for x in alt])
        if env == "stock_order":
            flip = [d.replace(":BUY", ":SELL") for d in dests[10:20]]
            attack("11_instrument_or_side_swapped", "Compromised trading agent flips side or symbol",
                   [Req(env, flip[i], int(amts[10 + i]), cur, last_t + 1000, fresh[i], f"flip-{i}") for i in range(10)],
                   before=lambda s: [s["S2_policy_engine"].add_beneficiary(x) for x in flip])
        thief = [sign(approver, env, f"{mule}:{i}", POLICY.per_payout_max_minor, last_t) for i in range(60)]
        attack("12_stolen_signing_key_burst", "Ronin bridge 2022 (validator keys), Knight Capital 2012 (runaway orders)",
               [Req(env, f"{mule}:{i}", POLICY.per_payout_max_minor, cur, last_t + 1000, thief[i], f"key-{i}") for i in range(60)],
               before=lambda s: [s["S2_policy_engine"].add_beneficiary(f"{mule}:{i}") for i in range(60)])
        blind = [sign(approver, env, mule, 19_000_000, last_t) for _ in range(3)]
        attack("13_approver_tricked_into_signing", "Bybit 2025: signers approved a payload the UI misrepresented",
               [Req(env, mule, 19_000_000, cur, last_t + 1000, blind[i], f"blind-{i}") for i in range(3)],
               before=lambda s: s["S2_policy_engine"].add_beneficiary(mule))

    # concurrency: 16 threads, each with its own store connections, burst a stolen key at S4
    approver2 = Signer.generate()
    s4 = S4(approver2.get_public_key(), os.path.join(tmp, "race_r.db"), os.path.join(tmp, "race_l.db"))
    burst = [Req("bank_payout", f"bank:MULE:{i}", POLICY.per_payout_max_minor, "INR", T0,
                 sign(approver2, "bank_payout", f"bank:MULE:{i}", POLICY.per_payout_max_minor, T0)) for i in range(160)]

    def worker(chunk):
        rp, lp = ReplayStore(s4.rpath), LimitStore(s4.lpath)
        n = sum(s4.decide(r, rp, lp)[0] for r in chunk)
        rp.close()
        lp.close()
        return n
    with ThreadPoolExecutor(16) as ex:
        passed = sum(ex.map(worker, [burst[i::16] for i in range(16)]))
    race = {"threads": 16, "requests": len(burst), "each_minor": POLICY.per_payout_max_minor,
            "allowed": passed, "allowed_amount_minor": passed * POLICY.per_payout_max_minor,
            "daily_cap_minor": POLICY.daily_max_minor, "cap_held": passed * POLICY.per_payout_max_minor <= POLICY.daily_max_minor}

    # after the fact: what each system can still detect (only S4 reconciles provider records and the bank)
    det_signer = Signer.generate()
    ins = [sign(det_signer, "bank_payout", f"bank:B:{i}", 1_000_000, T0) for i in range(5)]
    pay = [PayoutRecord(f"p{i}", ins[i].instruction_id, 1_000_000, "INR", "processed", T0 + MIN, f"bank:B:{i}", utr=f"U{i}") for i in range(5)]
    stmt = [BankEntry(f"e{i}", f"U{i}", 1_000_000, "INR", "debit", T0 + 2 * MIN) for i in range(5)]
    scenarios = {
        "14_route_bypass_direct_provider_payout": ("Payout made at the provider dashboard, skipping the gate",
            pay + [PayoutRecord("px", "", 4_000_000, "INR", "processed", T0 + MIN, "bank:MULE", utr="UX")],
            stmt + [BankEntry("ex", "UX", 4_000_000, "INR", "debit", T0 + 2 * MIN)]),
        "15_provider_status_forged": ("Bangladesh Bank 2016 pattern: records altered to hide the transfer",
            pay[:4] + [PayoutRecord("p4", ins[4].instruction_id, 1_000_000, "INR", "processed", T0 + MIN, "bank:B:4", utr="U4-fake")],
            stmt[:4] + [BankEntry("ez", "UZ", 2_500_000, "INR", "debit", T0 + 2 * MIN)]),
        "16_insider_forges_both_files": ("One insider edits provider export and statement consistently",
            pay, stmt),
    }
    detect = {}
    for name, (source, payouts, statement) in scenarios.items():
        rep = reconcile_payouts(ins, payouts, det_signer.get_public_key(), as_of_ms=T0 + 48 * HOUR,
                                statement=statement, settlement_grace_ms=HOUR)
        flagged = [r for r in rep.results if r.verdict != MATCHED]
        detect[name] = {"source": source, "S1_api_key": False, "S2_policy_engine": False, "S2b_policy_locked_allowlist": False,
                        "S3_aetherproof_gate": False,
                        "S4_aetherproof_full": bool(flagged), "flags": [f"{r.kind or r.verdict}: {r.reasons[0] if r.reasons else ''}" for r in flagged]}

    lat = {k: {"median_ms": round(statistics.median(v), 3), "p99_ms": round(float(np.percentile(v, 99)), 3)} for k, v in timing.items()}
    out = {"date": "2026-11-25", "synthetic": True, "policy_minor": POLICY.__dict__, "legit": legit_summary,
           "attacks": results, "race": race, "after_the_fact": detect, "latency": lat}
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "financial_benchmark_result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, default=str)

    # ---------------- print
    print(f"legit traffic, {LEGIT_PER_ENV} approved payouts per environment, wrongly blocked:")
    for env, r in legit_summary.items():
        print(f"  {env:18s} " + "  ".join(f"{s.split('_')[0]} {r[s]['legit_blocked']}" for s in SYSTEMS))
    print("\nunauthorized actions executed (count / amount in units), lower is better:")
    print(f"  {'attack':40s} " + " ".join(f"{s.split('_')[0]:>16s}" for s in SYSTEMS))
    for name, v in results.items():
        cells = []
        for s in SYSTEMS:
            n = sum(e[s]["executed_unauthorized"] for e in v["by_env"].values())
            amt = sum(e[s]["amount_unauthorized_minor"] for e in v["by_env"].values()) / 100
            cells.append(f"{n:4d} / {amt:>10,.0f}")
        print(f"  {name:40s} " + " ".join(f"{c:>16s}" for c in cells))
    print(f"\nrace: {race['threads']} threads, {race['requests']} stolen-key payouts of {race['each_minor']/100:,.0f}: "
          f"{race['allowed']} allowed = {race['allowed_amount_minor']/100:,.0f} vs daily cap {race['daily_cap_minor']/100:,.0f}; cap held: {race['cap_held']}")
    print("\nafter the fact, detected:")
    for name, v in detect.items():
        print(f"  {name:40s} S4 {v['S4_aetherproof_full']}  " + (v["flags"][0][:90] if v["flags"] else "(nothing flagged)"))
    print("\ndecision latency on legitimate payouts: " + ", ".join(f"{k.split('_')[0]} {v['median_ms']} ms median, {v['p99_ms']} p99" for k, v in lat.items()))


if __name__ == "__main__":
    main()
