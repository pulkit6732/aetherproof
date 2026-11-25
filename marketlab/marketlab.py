"""MarketLab prototype: one event driven limit order book, heterogeneous agents, shocks,
an authorization gate built on AetherProof's signer and replay store, and a hash chained
event log. Research prototype, synthetic market, not calibrated to any real instrument.
"""
from __future__ import annotations

import hashlib
import json
import atexit
import os
import shutil
import sqlite3
import tempfile
from collections import deque
from dataclasses import dataclass, field

import numpy as np

from aetherproof.core.instruction import ReplayStore
from aetherproof.core.signer import Signer

BUY, SELL = 1, -1


# ------------------------------------------------------------------ evidence log
class EventChain:
    """Every accepted order, rejection and trade, hash chained. Changing any past event
    changes the final digest."""

    def __init__(self):
        self.head = "0" * 64
        self.events = []

    def add(self, **ev):
        line = json.dumps(ev, sort_keys=True, separators=(",", ":"))
        self.head = hashlib.sha256((self.head + line).encode()).hexdigest()
        self.events.append(line)

    @staticmethod
    def digest_of(lines):
        h = "0" * 64
        for line in lines:
            h = hashlib.sha256((h + line).encode()).hexdigest()
        return h


# ------------------------------------------------------------------ order book
class Book:
    def __init__(self, log: EventChain):
        self.bids, self.asks = {}, {}          # price -> deque of [oid, agent, qty]
        self.vol = {BUY: {}, SELL: {}}         # live quantity per level
        self.orders = {}                       # oid -> order list
        self.next_oid = 0
        self.last = None
        self.log = log
        self.trades = 0

    def best(self, side):
        lv = self.vol[side]
        if not lv:
            return None
        return max(lv) if side == BUY else min(lv)

    def _fill(self, taker, side, qty, limit, t):
        book, lv = (self.asks, self.vol[SELL]) if side == BUY else (self.bids, self.vol[BUY])
        while qty > 0 and lv:
            px = min(lv) if side == BUY else max(lv)
            if limit is not None and ((side == BUY and px > limit) or (side == SELL and px < limit)):
                break
            q = book[px]
            while q and qty > 0:
                o = q[0]
                if o[2] == 0:
                    q.popleft()
                    continue
                f = min(qty, o[2])
                o[2] -= f
                qty -= f
                lv[px] -= f
                maker = o[1]
                taker.pos += side * f
                taker.cash -= side * f * px
                maker.pos -= side * f
                maker.cash += side * f * px
                self.last = px
                self.trades += 1
                self.log.add(k="T", t=t, px=px, q=f, tk=taker.name, mk=maker.name)
                if o[2] == 0:
                    q.popleft()
                    self.orders.pop(o[0], None)
            if lv[px] == 0:
                del lv[px]
                del book[px]
        return qty

    def market(self, agent, side, qty, t):
        return self._fill(agent, side, qty, None, t)

    def limit(self, agent, side, px, qty, t):
        rest = self._fill(agent, side, qty, px, t)
        if rest > 0:
            oid = self.next_oid
            self.next_oid += 1
            book = self.bids if side == BUY else self.asks
            o = [oid, agent, rest, t, side, px]
            book.setdefault(px, deque()).append(o)
            self.vol[side][px] = self.vol[side].get(px, 0) + rest
            self.orders[oid] = o
            return oid
        return None

    def cancel(self, oid):
        o = self.orders.pop(oid, None)
        if o is None or o[2] == 0:
            return
        side, px = o[4], o[5]
        lv = self.vol[side]
        lv[px] -= o[2]
        o[2] = 0
        if lv[px] <= 0:
            del lv[px]
            (self.bids if side == BUY else self.asks).pop(px, None)

    def expire(self, t, age):
        for oid in [k for k, o in self.orders.items() if t - o[3] > age and o[1].kind != "mm"]:
            self.cancel(oid)

    def mid(self):
        b, a = self.best(BUY), self.best(SELL)
        if b is not None and a is not None:
            return (a + b) / 2
        return float(self.last) if self.last is not None else None

    def depth(self, side, levels=5):
        lv = self.vol[side]
        ks = sorted(lv, reverse=(side == BUY))[:levels]
        return sum(lv[k] for k in ks)


# ------------------------------------------------------------------ agents
@dataclass(eq=False)
class Agent:
    name: str
    kind: str
    pos: int = 0
    cash: float = 0.0
    quotes: list = field(default_factory=list)


# ------------------------------------------------------------------ authorization gate
class Gate:
    """Checks a signed mandate before an order reaches the book: signature, account,
    per order size, position limit, time window, and single use of the order id
    (AetherProof ReplayStore, SQLite, durable)."""

    def __init__(self, desk: Signer, path):
        self.verifier = desk.get_public_key()
        self.replay = ReplayStore(path)
        self.rejects = {}
        self.allowed = 0

    @staticmethod
    def mandate_bytes(m):
        return json.dumps({k: m[k] for k in sorted(m) if k != "sig"}, sort_keys=True).encode()

    def check(self, m, order, agent):
        why = None
        if not self.verifier.verify(self.mandate_bytes(m), m.get("sig", "")):
            why = "forged_mandate"
        elif order["account"] != m["account"]:
            why = "wrong_account"
        elif not (m["from_t"] <= order["t"] <= m["to_t"]):
            why = "outside_window"
        elif order["qty"] > m["max_order_qty"]:
            why = "order_too_large"
        elif abs(agent.pos + order["side"] * order["qty"]) > m["max_abs_pos"]:
            why = "position_limit"
        else:
            try:
                fresh = self.replay.consume(order["oid"], hashlib.sha256(json.dumps(order, sort_keys=True).encode()).hexdigest())
            except (OSError, sqlite3.Error):  # fail closed: if single use cannot be checked, the order does not go
                fresh, why = False, "replay_store_error"
            if not fresh and why is None:
                why = "replayed_order_id"
        if why:
            self.rejects[why] = self.rejects.get(why, 0) + 1
            return False, why
        self.allowed += 1
        return True, None


# ------------------------------------------------------------------ simulation
@dataclass
class Config:
    seed: int = 7
    steps: int = 20000
    n_noise: int = 200
    n_mm: int = 5
    n_mom: int = 30
    n_fund: int = 30
    arrivals: float = 3.0
    start_px: int = 10000          # ticks
    shock: bool = False            # market makers withdraw and coordinated selling
    shock_t: int = 12000
    shock_len: int = 600
    attack: bool = False           # a compromised agent dumps and abuses its mandate
    gate: bool = True
    attack_t: int = 12000
    attack_len: int = 600


def run(cfg: Config):
    rng = np.random.default_rng(cfg.seed)
    log = EventChain()
    book = Book(log)
    noise = [Agent(f"n{i}", "noise") for i in range(cfg.n_noise)]
    mms = [Agent(f"m{i}", "mm") for i in range(cfg.n_mm)]
    mom = [Agent(f"p{i}", "mom") for i in range(cfg.n_mom)]
    fund = [Agent(f"f{i}", "fund") for i in range(cfg.n_fund)]
    takers = noise + mom + fund
    sellers = noise[:40]
    adv = Agent("x0", "adv")

    gate, mandate, forged = None, None, None
    tmpdir = None
    if cfg.attack:
        desk = Signer.generate()
        try:
            tmpdir = tempfile.mkdtemp(prefix="marketlab_")
            atexit.register(shutil.rmtree, tmpdir, True)  # also removed if the run stops with an error
            gate = Gate(desk, os.path.join(tmpdir, "replay.db"))
        except (OSError, sqlite3.Error) as e:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
            raise RuntimeError(f"cannot open the gate's replay store: {e}") from e
        mandate = {"agent": "x0", "account": "ACC-7", "max_order_qty": 5, "max_abs_pos": 60,
                   "from_t": 0, "to_t": cfg.attack_t + cfg.attack_len // 2}
        mandate["sig"] = desk.sign(Gate.mandate_bytes(mandate))
        forged = dict(mandate, max_order_qty=10_000, max_abs_pos=10_000, to_t=cfg.steps)
        forged["sig"] = Signer.generate().sign(Gate.mandate_bytes(forged))

    V = float(cfg.start_px)
    mids, spreads, depths = [], [], []
    attempts, blocked = {}, {}
    used_oids = []
    oid_n = 0

    # seed the book
    for i in range(1, 30):
        book.limit(mms[i % cfg.n_mm], BUY, cfg.start_px - i, 5, 0)
        book.limit(mms[i % cfg.n_mm], SELL, cfg.start_px + i, 5, 0)

    for t in range(cfg.steps):
        V += rng.normal(0, 0.6)
        mid = book.mid() or cfg.start_px
        recent = mids[-50:]
        vol = float(np.std(np.diff(recent))) if len(recent) > 5 else 1.0

        withdrawn = cfg.shock and cfg.shock_t <= t < cfg.shock_t + cfg.shock_len
        # market makers: refresh quotes, wider when volatile, skewed by inventory, step back under stress
        for m in mms:
            for oid in m.quotes:
                book.cancel(oid)
            m.quotes = []
            if withdrawn:
                continue
            h = 1 + int(round(1.5 * vol))
            skew = int(round(m.pos / 20))
            c = int(round(mid)) - skew
            if m.pos < 80:
                q = book.limit(m, BUY, c - h, 6, t)
                if q is not None:
                    m.quotes.append(q)
            if m.pos > -80:
                q = book.limit(m, SELL, c + h, 6, t)
                if q is not None:
                    m.quotes.append(q)

        # takers arrive at random
        for _ in range(rng.poisson(cfg.arrivals)):
            a = takers[rng.integers(len(takers))]
            mid = book.mid() or mid
            if a.kind == "noise":
                side = BUY if rng.random() < 0.5 else SELL
                if rng.random() < 0.3:
                    book.market(a, side, int(rng.integers(1, 6)), t)
                else:
                    off = int(rng.geometric(0.25)) - 1
                    px = int(round(mid)) - side * off
                    book.limit(a, side, px, int(rng.integers(1, 6)), t)
            elif a.kind == "mom" and len(mids) > 100:
                r = mids[-1] - mids[-100]
                if abs(r) > 4:
                    book.market(a, BUY if r > 0 else SELL, int(rng.integers(2, 6)), t)
            elif a.kind == "fund":
                if mid < V - 8:
                    book.market(a, BUY, int(rng.integers(2, 6)), t)
                elif mid > V + 8:
                    book.market(a, SELL, int(rng.integers(2, 6)), t)

        if withdrawn:  # coordinated selling during the shock
            for s in sellers[:8]:
                book.market(s, SELL, 3, t)

        # the compromised agent
        if cfg.attack and cfg.attack_t <= t < cfg.attack_t + cfg.attack_len:
            tries = []
            tries.append(("dump", mandate, {"account": "ACC-7", "qty": 40, "side": SELL}))
            if t % 5 == 0:
                tries.append(("legit", mandate, {"account": "ACC-7", "qty": 2, "side": BUY if t % 10 else SELL}))
            if t % 10 == 0:
                tries.append(("wrong_account", mandate, {"account": "MULE-1", "qty": 3, "side": SELL}))
            if t % 25 == 0:
                tries.append(("forged", forged, {"account": "ACC-7", "qty": 40, "side": SELL}))
            for kind, m, o in tries:
                oid_n += 1
                o = dict(o, t=t, oid=f"x0-{oid_n}")
                if kind == "legit" and used_oids and t % 20 == 0:
                    o["oid"] = used_oids[0]          # reuse an id that already traded
                    kind = "replay"
                attempts[kind] = attempts.get(kind, 0) + 1
                if gate is not None and cfg.gate:
                    ok, why = gate.check(m, o, adv)
                    log.add(k="G", t=t, oid=o["oid"], ok=ok, why=why or "")
                    if not ok:
                        blocked[f"{kind}:{why}"] = blocked.get(f"{kind}:{why}", 0) + 1
                        continue
                used_oids.append(o["oid"])
                book.market(adv, o["side"], o["qty"], t)

        if t % 50 == 0:
            book.expire(t, 300)
        m_now = book.mid()
        mids.append(m_now if m_now is not None else mids[-1])
        b, a = book.best(BUY), book.best(SELL)
        spreads.append((a - b) if (a is not None and b is not None) else np.nan)
        depths.append(book.depth(BUY) + book.depth(SELL))

    out = {
        "mids": np.array(mids, dtype=float), "spreads": np.array(spreads, dtype=float),
        "depths": np.array(depths, dtype=float), "digest": log.head, "events": log.events,
        "trades": book.trades, "attempts": attempts, "blocked": blocked,
        "gate_rejects": dict(gate.rejects) if gate else {}, "gate_allowed": gate.allowed if gate else 0,
        "adv_pos": adv.pos,
    }
    if gate:
        gate.replay.close()
    if tmpdir:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return out


# ------------------------------------------------------------------ statistics
def stylized(prices, every=10):
    p = np.asarray(prices, dtype=float)[::every]
    r = np.diff(np.log(p))
    r = r[np.isfinite(r)]
    r = r - r.mean()

    def acf(x, k):
        return float(np.corrcoef(x[:-k], x[k:])[0, 1])

    kurt = float(np.mean(r ** 4) / np.mean(r ** 2) ** 2 - 3)
    return {"n": int(len(r)), "excess_kurtosis": kurt, "acf_r_lag1": acf(r, 1),
            "acf_abs_r_mean_lags_1_10": float(np.mean([acf(np.abs(r), k) for k in range(1, 11)]))}
