"""Section 6 tests of the MarketLab proposal, as far as they can run on one machine.
Prints every number it reports; writes results.json next to this file."""
import json
import math
import os
import time

import numpy as np

from marketlab import Config, EventChain, run, stylized

HERE = os.path.dirname(os.path.abspath(__file__))
R = {}


def closes(name, minute_only=False):
    try:
        with open(os.path.join(HERE, "data", name), encoding="utf-8") as f:
            d = json.load(f)
        r = d["chart"]["result"][0]
        pairs = [(t, c) for t, c in zip(r["timestamp"], r["indicators"]["quote"][0]["close"])
                 if isinstance(c, (int, float)) and c > 0]
    except (OSError, ValueError, KeyError, IndexError, TypeError) as e:
        print(f"  real data {name} unavailable: {type(e).__name__}")
        return None
    if len(pairs) < 2:
        print(f"  real data {name} has too few prices to compare")
        return None
    if not minute_only:
        return np.array([c for _, c in pairs], dtype=float)
    # keep only runs of consecutive minutes: the overnight jump is not a one minute return
    runs, cur = [], [pairs[0][1]]
    for (t0, _), (t1, c1) in zip(pairs, pairs[1:]):
        if t1 - t0 == 60:
            cur.append(c1)
        else:
            runs.append(cur)
            cur = [c1]
    runs.append(cur)
    return runs


def stylized_runs(runs):
    r = np.concatenate([np.diff(np.log(np.asarray(x))) for x in runs if len(x) > 1])
    return stylized(np.exp(np.cumsum(np.concatenate([[0.0], r]))), every=1)


def timed(cfg):
    a = time.perf_counter()
    out = run(cfg)
    out["seconds"] = time.perf_counter() - a
    return out


print("T1 reproducibility: same seed and inputs give the same run")
a, b, c = timed(Config(seed=7)), timed(Config(seed=7)), timed(Config(seed=8))
R["T1"] = {"seed7_run1": a["digest"], "seed7_run2": b["digest"], "seed8": c["digest"],
           "same_seed_identical": a["digest"] == b["digest"], "different_seed_differs": a["digest"] != c["digest"],
           "trades": a["trades"], "steps": 20000, "seconds_per_run": round(a["seconds"], 2)}
print(f"  same seed identical: {R['T1']['same_seed_identical']}, different seed differs: "
      f"{R['T1']['different_seed_differs']}, {a['trades']} trades, {a['seconds']:.1f} s per 20,000 steps")

print("T2 realism: stylized facts, simulated vs real SPY vs a plain random walk")
sims = [stylized(timed(Config(seed=s))["mids"], every=10) for s in (7, 11, 13, 17, 19)]
sim = {k: (float(np.mean([s[k] for s in sims])), float(np.std([s[k] for s in sims]))) for k in sims[0] if k != "n"}
rng = np.random.default_rng(0)
gauss = stylized(np.exp(np.cumsum(rng.normal(0, 0.001, 20000))), every=1)
real_d, real_m = closes("spy_yahoo.json"), closes("spy_1m.json", minute_only=True)
R["T2"] = {"simulated_5_seeds_mean_sd": sim, "gaussian_walk": gauss,
           "spy_daily_10y": stylized(real_d, every=1) if real_d is not None else None,
           "spy_1min_7d_within_session": stylized_runs(real_m) if real_m is not None else None}
for name, s in (("simulated (mean of 5 seeds)", {k: v[0] for k, v in sim.items()}), ("gaussian walk", gauss),
                ("SPY daily, 10 y", R["T2"]["spy_daily_10y"]), ("SPY 1 min, within session", R["T2"]["spy_1min_7d_within_session"])):
    if s:
        print(f"  {name:28s} kurtosis {s['excess_kurtosis']:7.2f}  acf(r,1) {s['acf_r_lag1']:6.3f}  "
              f"acf(|r|,1..10) {s['acf_abs_r_mean_lags_1_10']:6.3f}")

print("T3 liquidity shock: market makers withdraw and 8 sellers dump for 600 steps")
base, shock = timed(Config(seed=7)), timed(Config(seed=7, shock=True))
S, L = 12000, 600


def window(x, lo, hi):
    return float(np.nanmean(x[lo:hi]))


pre = base["mids"][S - 1]
low = float(np.min(shock["mids"][S:S + L]))
drop = pre - low
t_low = S + int(np.argmin(shock["mids"][S:S + L]))
rec = next((t for t in range(t_low, len(shock["mids"])) if shock["mids"][t] >= low + drop * 0.5), None)
R["T3"] = {
    "one_sided_share_during": float(np.mean(np.isnan(shock["spreads"][S:S + L]))),
    "spread_ticks_before": window(shock["spreads"], S - L, S), "spread_ticks_during": window(shock["spreads"], S, S + L),
    "spread_ticks_after": window(shock["spreads"], S + L, S + 2 * L),
    "depth_top5_before": window(shock["depths"], S - L, S), "depth_top5_during": window(shock["depths"], S, S + L),
    "price_drop_ticks_shock": drop, "price_drop_ticks_same_seed_no_shock": pre - float(np.min(base["mids"][S:S + L])),
    "low_at_step_into_shock": t_low - S, "steps_from_low_to_half_recovery": (rec - t_low) if rec is not None else None,
}
t3 = R["T3"]
print(f"  one side of the book empty in {t3['one_sided_share_during']:.0%} of shock steps; mean spread where both sides existed,")
print(f"  before/during/after: {t3['spread_ticks_before']:.2f} / {t3['spread_ticks_during']:.2f} / "
      f"{t3['spread_ticks_after']:.2f} ticks; depth {t3['depth_top5_before']:.0f} -> {t3['depth_top5_during']:.0f}")
print(f"  drop {drop:.0f} ticks with shock vs {t3['price_drop_ticks_same_seed_no_shock']:.0f} without; "
      f"low reached {t3['low_at_step_into_shock']} steps in; half recovered {t3['steps_from_low_to_half_recovery']} steps after the low")

print("T4 rogue trading agent: with the AetherProof gate vs without")
g, n = timed(Config(seed=7, attack=True, gate=True)), timed(Config(seed=7, attack=True, gate=False))
A = 12000


def drop_in(o):
    return float(o["mids"][A - 1] - np.min(o["mids"][A:A + 600]))


legit = g["attempts"].get("legit", 0)
R["T4"] = {"attempts": g["attempts"], "blocked_with_gate": g["blocked"], "rejects_by_reason": g["gate_rejects"],
           "legit_orders": legit, "legit_blocked_after_window_expired": g["blocked"].get("legit:outside_window", 0), "legit_wrongly_blocked": sum(v for k, v in g["blocked"].items() if k.startswith("legit:") and k != "legit:outside_window"),
           "price_drop_ticks_with_gate": drop_in(g), "price_drop_ticks_without_gate": drop_in(n),
           "rogue_position_with_gate": g["adv_pos"], "rogue_position_without_gate": n["adv_pos"],
           "mandate_limits": {"max_order_qty": 5, "max_abs_pos": 60}}
t4 = R["T4"]
print(f"  attempts {t4['attempts']}")
print(f"  blocked  {t4['blocked_with_gate']}  reasons {t4['rejects_by_reason']}")
print(f"  legit orders: {legit}; blocked after the permission window expired (correct): "
      f"{t4['legit_blocked_after_window_expired']}; wrongly blocked inside the window: {t4['legit_wrongly_blocked']}")
print(f"  price drop: {t4['price_drop_ticks_with_gate']:.0f} ticks with gate vs {t4['price_drop_ticks_without_gate']:.0f} "
      f"without; rogue position {t4['rogue_position_with_gate']} vs {t4['rogue_position_without_gate']}")

print("T5 evidence: the event chain verifies, and one edited trade breaks it")
ev = list(g["events"])
ok = EventChain.digest_of(ev) == g["digest"]
i = next(k for k, line in enumerate(ev) if line.startswith('{"k":"T"'))
tampered = ev[:]
tampered[i] = tampered[i].replace('"px":', '"px":1', 1)
R["T5"] = {"events": len(ev), "recomputed_matches": ok, "tampered_detected": EventChain.digest_of(tampered) != g["digest"]}
print(f"  {len(ev)} events, recomputed digest matches: {ok}, edited trade detected: {R['T5']['tampered_detected']}")

try:
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as f:
        json.dump(R, f, indent=2, default=lambda x: None if isinstance(x, float) and math.isnan(x) else str(x))
    print("written results.json")
except OSError as e:  # the numbers above are already printed; a failed save must say so, not crash silently
    raise SystemExit(f"could not write results.json: {e}")
