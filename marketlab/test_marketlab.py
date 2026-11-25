"""Matching engine correctness: price priority, then time priority, cancels, partial fills,
and a deterministic event log. Run: python -m pytest marketlab/test_marketlab.py"""
from marketlab import BUY, SELL, Agent, Book, Config, EventChain, run


def _book():
    return Book(EventChain())


def test_better_price_fills_first_then_earlier_order():
    b = _book()
    early, late, better, taker = Agent("early", "noise"), Agent("late", "noise"), Agent("better", "noise"), Agent("t", "noise")
    b.limit(early, SELL, 101, 5, 0)
    b.limit(late, SELL, 101, 5, 1)
    b.limit(better, SELL, 100, 5, 2)
    b.market(taker, BUY, 7, 3)
    assert better.pos == -5 and early.pos == -2 and late.pos == 0 and taker.pos == 7
    assert b.best(SELL) == 101 and b.vol[SELL][101] == 8


def test_cancel_removes_volume_and_level():
    b = _book()
    a = Agent("a", "noise")
    oid = b.limit(a, BUY, 99, 4, 0)
    b.cancel(oid)
    assert b.best(BUY) is None and b.vol[BUY] == {}


def test_marketable_limit_fills_then_rests_the_remainder():
    b = _book()
    seller, buyer = Agent("s", "noise"), Agent("b", "noise")
    b.limit(seller, SELL, 100, 3, 0)
    oid = b.limit(buyer, BUY, 100, 5, 1)
    assert buyer.pos == 3 and oid is not None and b.best(BUY) == 100 and b.vol[BUY][100] == 2


def test_every_trade_moves_equal_and_opposite_position_and_cash():
    b = _book()
    agents = [Agent(f"a{i}", "noise") for i in range(6)]
    for i, a in enumerate(agents[:3]):
        b.limit(a, SELL, 100 + i, 4, i)
        b.limit(agents[3 + i], BUY, 97 - i, 4, i)
    b.market(agents[4], BUY, 9, 10)
    b.market(agents[1], SELL, 6, 11)
    assert sum(a.pos for a in agents) == 0 and abs(sum(a.cash for a in agents)) < 1e-9


def test_same_seed_same_log_different_seed_different_log():
    assert run(Config(seed=5, steps=2000))["digest"] == run(Config(seed=5, steps=2000))["digest"]
    assert run(Config(seed=5, steps=2000))["digest"] != run(Config(seed=6, steps=2000))["digest"]
