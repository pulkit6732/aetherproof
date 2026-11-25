"""Aggregate limits and revocation: caps hold under concurrency, revocation blocks, a refused
payout gives its reservation back, and a store failure is a reject, never an allow."""
import subprocess
import sys
import textwrap

import pytest

from aetherproof.core.instruction import PayoutRequest, ReplayStore, sign_instruction, token_beneficiary
from aetherproof.core.limits import LimitPolicy, LimitStore, verify_with_limits
from aetherproof.core.signer import Signer

NOW = 1_780_000_000_000
POLICY = LimitPolicy(per_payout_max_minor=100_000, daily_max_minor=250_000, daily_count_max=4,
                     per_destination_daily_max_minor=150_000)


@pytest.fixture
def env(tmp_path):
    s = Signer.generate()
    replay, limits = ReplayStore(str(tmp_path / "r.db")), LimitStore(str(tmp_path / "l.db"))
    yield s, replay, limits
    replay.close()
    limits.close()


def _ins(s, amount, dest="fa_1"):
    return sign_instruction(s, originator="los", amount_minor=amount, currency="INR", beneficiary=token_beneficiary(dest),
                            purpose="loan", reference="LN", approval_ref="SAN", approved_by="ops", policy="v1",
                            not_before_ms=NOW - 1000)


def _pay(s, replay, limits, ins, amount=None, dest="fa_1"):
    req = PayoutRequest(amount or ins.amount_minor, "INR", ins.instruction_id, dest)
    return verify_with_limits(ins, req, s.get_public_key(), replay, limits, POLICY, account="acc", destination=dest, now_ms=NOW)


def test_caps_per_payout_daily_total_count_and_destination(env):
    s, replay, limits = env
    assert "per payout cap" in _pay(s, replay, limits, _ins(s, 100_001)).reasons[0]
    assert _pay(s, replay, limits, _ins(s, 90_000, "fa_a"), dest="fa_a").allowed
    assert _pay(s, replay, limits, _ins(s, 60_000, "fa_a"), dest="fa_a").allowed
    assert "destination" in _pay(s, replay, limits, _ins(s, 10_000, "fa_a"), dest="fa_a").reasons[0]
    assert _pay(s, replay, limits, _ins(s, 90_000, "fa_b"), dest="fa_b").allowed
    assert "daily cap" in _pay(s, replay, limits, _ins(s, 20_000, "fa_c"), dest="fa_c").reasons[0]
    assert _pay(s, replay, limits, _ins(s, 5_000, "fa_c"), dest="fa_c").allowed
    assert "count cap" in _pay(s, replay, limits, _ins(s, 1_000, "fa_d"), dest="fa_d").reasons[0]
    assert limits.spent("acc", NOW, POLICY) == (245_000, 4)


def test_revoked_instruction_is_refused_and_spends_nothing(env):
    s, replay, limits = env
    ins = _ins(s, 50_000)
    limits.revoke(ins.instruction_id)
    d = _pay(s, replay, limits, ins)
    assert not d.allowed and d.reasons == ["instruction revoked"]
    assert limits.spent("acc", NOW, POLICY) == (0, 0)


def test_replay_is_refused_and_gives_its_reservation_back(env):
    s, replay, limits = env
    ins = _ins(s, 50_000)
    assert _pay(s, replay, limits, ins).allowed
    again = _pay(s, replay, limits, ins)
    assert not again.allowed and "already used" in again.reasons[0]
    assert limits.spent("acc", NOW, POLICY) == (50_000, 1)


def test_hard_check_failure_spends_nothing(env):
    s, replay, limits = env
    ins = _ins(s, 50_000)
    assert not _pay(s, replay, limits, ins, amount=60_000).allowed
    assert not _pay(s, replay, limits, ins, dest="fa_mule").allowed
    assert limits.spent("acc", NOW, POLICY) == (0, 0)


def test_store_failure_is_a_reject_not_an_allow(env):
    s, replay, limits = env
    limits.close()
    d = _pay(s, replay, limits, _ins(s, 1_000))
    assert not d.allowed and "limit store unavailable" in d.reasons[0]


@pytest.mark.parametrize("account,dest,amount", [("", "fa_1", 1_000), ("acc", "", 1_000), ("acc", "fa_1", 0)])
def test_empty_account_destination_or_zero_amount_is_refused(env, account, dest, amount):
    s, replay, limits = env
    ins = _ins(s, 1_000)
    req = PayoutRequest(amount, "INR", ins.instruction_id, "fa_1")
    d = verify_with_limits(ins, req, s.get_public_key(), replay, limits, POLICY, account=account, destination=dest, now_ms=NOW)
    assert not d.allowed and "required" in d.reasons[0]
    assert limits.spent("acc", NOW, POLICY) == (0, 0)


def test_day_rolls_over_at_local_midnight():
    p = LimitPolicy(1, 1, 1, 1, utc_offset_minutes=330)
    # 18:29 UTC is 23:59 IST; 18:31 UTC is the next IST day
    assert LimitStore.day_of(1_767_205_740_000, p) != LimitStore.day_of(1_767_205_860_000, p)


def test_cap_holds_across_concurrent_processes(tmp_path):
    """8 processes race 10 payouts each of 30,000 against a 250,000 daily cap (count cap 100):
    exactly 8 may pass in total, whatever the interleaving."""
    script = textwrap.dedent(f"""
        import sys
        from aetherproof.core.instruction import PayoutRequest, ReplayStore, sign_instruction, token_beneficiary
        from aetherproof.core.limits import LimitPolicy, LimitStore, verify_with_limits
        from aetherproof.core.signer import Signer
        p = LimitPolicy(100_000, 250_000, 100, 250_000)
        s = Signer.generate()
        r, l = ReplayStore(sys.argv[1]), LimitStore(sys.argv[2])
        ok = 0
        for i in range(10):
            ins = sign_instruction(s, originator="o", amount_minor=30_000, currency="INR", beneficiary=token_beneficiary("fa"),
                                   purpose="p", reference="r", approval_ref="a", approved_by="b", policy="c",
                                   not_before_ms={NOW} - 1000)
            d = verify_with_limits(ins, PayoutRequest(30_000, "INR", ins.instruction_id, "fa"), s.get_public_key(), r, l, p,
                                   account="acc", destination="fa", now_ms={NOW})
            ok += d.allowed
        print(ok)
    """)
    procs = [subprocess.Popen([sys.executable, "-c", script, str(tmp_path / "r.db"), str(tmp_path / "l.db")],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(8)]
    outs = [p.communicate(timeout=120) for p in procs]
    assert all(p.returncode == 0 for p in procs), [e for _, e in outs]
    assert sum(int(o.strip()) for o, _ in outs) == 8
