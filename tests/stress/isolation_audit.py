"""Fault-isolation and extreme-stress audit.

Design rule for this file: **no verdict is a literal.** Every pass/fail is
derived from a value computed at runtime, and the raw evidence (counts, timings,
exception text) is printed alongside so the verdict can be re-derived by hand.

Two things this measures that the combined suite did not:

  I · ISOLATION — break exactly one component, then probe every other component
      independently. Answers "if one part of AetherProof fails, does the rest
      keep working, or does the whole thing go down with it?"

  S · STRESS  — ramp load until something breaks and report the exact
      threshold, rather than asserting a single arbitrary N.

Run: python tests/stress/isolation_audit.py
"""

import gc
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer, Verifier
from aetherproof.core.verifier import verify_receipt
from aetherproof.core.log import ReceiptLog
from aetherproof.core.keystore import load_or_create_signer, issue_receipt
from aetherproof.core.hash import sha256, compute_merkle_root

ROWS = []


def probe(section, name, fn, expect_independent=True):
    """Run fn(); derive the verdict from what it returns or raises.

    fn returns (ok: bool, evidence: str). Any escaping exception is itself the
    evidence and counts as a failure of independence.
    """
    try:
        ok, evidence = fn()
    except Exception as e:
        ok, evidence = False, f"UNCAUGHT {type(e).__name__}: {e}"
    ROWS.append((section, name, ok, evidence))
    print(f"  [{'OK ' if ok else 'BAD'}] {name}\n         {evidence}")
    return ok


def banner(t):
    print(f"\n{'=' * 76}\n{t}\n{'=' * 76}")


def tmpdir():
    return Path(tempfile.mkdtemp(prefix="ap_iso_"))


def mkreceipt(signer, i=0, **kw):
    base = dict(model_weight_root="a" * 64, model_root_type="artifact_hash",
                input_commitment="b" * 64, output_hash="%064x" % i)
    base.update(kw)
    r = Receipt(**base)
    r.signature = signer.sign(r.signing_bytes())
    return r


# ══ I · FAULT ISOLATION ══════════════════════════════════════════════════════
# Each test breaks ONE thing, then probes the others independently.

def i1_log_deleted_signing_still_works():
    """Delete the log DB entirely. Can the signer still produce a valid receipt?"""
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    log.append(mkreceipt(s, 1))

    # The log caches a connection, so on Windows the file is held open and an
    # external delete fails with WinError 32. Record which case we are in rather
    # than assuming: an accidental-deletion guard on Windows, a clean delete on
    # POSIX, and either way the signing path must be unaffected.
    held = False
    try:
        os.remove(d / "log.db")
    except PermissionError:
        held = True
        log.close()
        os.remove(d / "log.db")

    r = mkreceipt(s, 2)
    ok = verify_receipt(r, s.get_public_key())
    note = ("open handle blocked the delete until close() — Windows"
            if held else "deleted while open — POSIX")
    return ok, (f"log.db removed ({note}); new receipt signed+verified={ok} "
                f"(signing path has no log dependency)")


def i2_log_corrupted_offline_verify_survives():
    """Fill the log DB with garbage. Does standalone receipt verification survive?"""
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    r = mkreceipt(s, 1)
    log.append(r)
    saved = r.to_json()

    with open(d / "log.db", "wb") as f:
        f.write(os.urandom(8192))

    back = Receipt.from_json(saved)
    verified = verify_receipt(back, s.get_public_key())

    try:
        log.verify_integrity()
        log_behaviour = "verify_integrity returned without raising"
        log_raised = False
    except Exception as e:
        log_behaviour = f"verify_integrity raised {type(e).__name__}"
        log_raised = True

    ok = verified is True
    return ok, (f"db overwritten with 8KB random; offline verify={verified}; "
                f"log side: {log_behaviour}. Independence={'held' if ok else 'BROKEN'}"
                + ("" if not log_raised else " (log failure is loud, not silent — good)"))


def i3_private_key_destroyed_verification_survives():
    """Destroy the private key. Do already-issued receipts still verify?"""
    d = tmpdir()
    s = load_or_create_signer(key_dir=d)
    r = mkreceipt(s, 1)
    pub_pem = s.get_public_key().export_public_pem()

    os.remove(d / "signing_key.pem")
    del s
    gc.collect()

    v = Verifier.from_public_pem(pub_pem)
    ok = verify_receipt(r, v)
    return ok, (f"private key deleted; receipt still verifies={ok} "
                f"(verification depends only on the public key — the stated invariant)")


def i4_public_key_corrupted_fails_closed():
    """Corrupt the public key PEM. Does it fail CLOSED (reject) or crash?"""
    d = tmpdir()
    s = load_or_create_signer(key_dir=d)
    r = mkreceipt(s, 1)
    pub = d / "signing_key.pub"
    raw = bytearray(pub.read_bytes())
    raw[len(raw) // 2] ^= 0xFF
    pub.write_bytes(bytes(raw))

    try:
        v = Verifier.from_public_file(str(pub))
        result = verify_receipt(r, v)
        ok = result is False
        ev = f"corrupted PEM loaded; verify returned {result} (fails closed={ok})"
    except Exception as e:
        ok = True
        ev = f"corrupted PEM rejected at load: {type(e).__name__} (fails closed)"
    return ok, ev


def i5_readonly_dir_append_fails_loudly():
    """Make the log dir read-only. Does append fail loudly or silently no-op?"""
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    log.append(mkreceipt(s, 1))
    before = log.count()

    dbfile = d / "log.db"
    os.chmod(dbfile, 0o444)
    raised, after = None, before
    try:
        log.append(mkreceipt(s, 2))
    except Exception as e:
        raised = type(e).__name__
    try:
        after = log.count()
    except Exception as e:
        raised = raised or type(e).__name__
    os.chmod(dbfile, 0o666)

    silent_loss = (raised is None) and (after == before)
    ok = not silent_loss
    return ok, (f"read-only db: raised={raised} count {before}->{after}; "
                f"silent data loss={'YES — receipt vanished with no error' if silent_loss else 'no'}")


def i6_crash_midwrite_leaves_log_consistent():
    """Simulate a crash between INSERT and the entry_hash UPDATE."""
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    for i in range(3):
        log.append(mkreceipt(s, i))

    # emulate the exact interrupted state append() can leave: row present,
    # entry_hash never filled in
    r = mkreceipt(s, 99)
    conn = sqlite3.connect(d / "log.db")
    conn.execute(
        "INSERT INTO receipts (receipt_id, model_weight_root, input_commitment, "
        "output_hash, timestamp_ms, signature, receipt_json, prev_hash, entry_hash) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (r.receipt_id, r.model_weight_root, r.input_commitment, r.output_hash,
         r.timestamp_ms, r.signature, r.to_json(), "0" * 64, ""))
    conn.commit()
    conn.close()

    detected = log.verify_integrity() is False
    return detected, (f"row inserted with empty entry_hash (crash window); "
                      f"verify_integrity detected it={detected}")


def i7_hash_module_independent_of_everything():
    """Does the hashing layer work with no key, no log, no filesystem?"""
    a, b = sha256("a"), sha256("b")
    root = compute_merkle_root([a, b])
    deterministic = compute_merkle_root([a, b]) == root
    nonempty = len(root) == 64
    ok = deterministic and nonempty
    return ok, f"merkle root computed with zero I/O; deterministic={deterministic} len={len(root)}"


def i8_receipt_serialisation_independent_of_signer():
    """Can a receipt be built, serialised and re-parsed with no key present?"""
    r = Receipt(model_weight_root="a" * 64, output_hash="c" * 64)
    j = r.to_json()
    back = Receipt.from_json(j)
    ok = (back.model_weight_root == r.model_weight_root
          and back.canonical_message() == r.canonical_message())
    return ok, f"receipt built+round-tripped with no Signer instantiated; preimage stable={ok}"


def i9_verifier_needs_no_aetherproof_log():
    """Verify a receipt with only receipt + pubkey — no log object at all."""
    s = Signer.generate()
    r = mkreceipt(s, 1)
    ok = verify_receipt(r, s.get_public_key(), log_entry=None) is True
    return ok, f"verify_receipt(receipt, pubkey, log=None)={ok} — the 3-input invariant with log omitted"


def i10_one_bad_receipt_does_not_block_the_rest():
    """Put a receipt with a broken signature in the log. Do the others still verify?"""
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    good = []
    for i in range(5):
        r = mkreceipt(s, i)
        if i == 2:
            r.signature = "00" * 64  # broken
        log.append(r)
        good.append(r)

    pub = s.get_public_key()
    individually = [verify_receipt(Receipt.from_json(log.get_by_sequence(n)["receipt_json"]), pub)
                    for n in range(1, 6)]
    survivors = sum(1 for v in individually if v)
    ok = survivors == 4 and individually[2] is False
    return ok, (f"1 corrupt receipt among 5: per-receipt verify={individually} "
                f"-> {survivors}/5 still provable independently")


# ══ S · EXTREME STRESS — find the actual threshold ═══════════════════════════

def s1_concurrency_threshold():
    """Ramp thread count until the chain first breaks. Report the exact N."""
    results = []
    first_break = None
    for n in (1, 2, 3, 4, 8, 16, 32, 64, 128):
        d = tmpdir()
        log = ReceiptLog(db_path=str(d / "log.db"))
        s = Signer.generate()
        errs = []

        def w(i):
            try:
                log.append(mkreceipt(s, i))
            except Exception as e:
                errs.append(type(e).__name__)

        ts = [threading.Thread(target=w, args=(i,)) for i in range(n)]
        t0 = time.perf_counter()
        [t.start() for t in ts]
        [t.join() for t in ts]
        dt = time.perf_counter() - t0
        intact = log.verify_integrity()
        results.append((n, log.count(), len(errs), intact, dt))
        if not intact and first_break is None:
            first_break = n
        shutil.rmtree(d, ignore_errors=True)

    lines = "\n         ".join(
        f"threads={n:4d}  rows={c:4d}  errors={e:4d}  chain_intact={i}  {t*1000:7.1f} ms"
        for n, c, e, i, t in results)
    ok = first_break is None
    return ok, (f"first chain break at N={first_break} concurrent writers\n         {lines}")


def s2_corruption_rate_vs_load(n=64, trials=5):
    """Same load, repeated. Is the race deterministic or flaky?"""
    broken = 0
    detail = []
    for t in range(trials):
        d = tmpdir()
        log = ReceiptLog(db_path=str(d / "log.db"))
        s = Signer.generate()

        def w(i):
            try:
                log.append(mkreceipt(s, i))
            except Exception:
                pass

        ts = [threading.Thread(target=w, args=(i,)) for i in range(n)]
        [x.start() for x in ts]
        [x.join() for x in ts]
        intact = log.verify_integrity()
        broken += 0 if intact else 1
        detail.append("intact" if intact else "BROKEN")
        shutil.rmtree(d, ignore_errors=True)

    ok = broken == 0
    return ok, (f"{trials} trials at {n} threads -> {broken}/{trials} corrupted "
                f"[{', '.join(detail)}]  "
                f"{'DETERMINISTIC' if broken in (0, trials) else 'FLAKY — passes some runs, fails others'}")


def s3_keygen_race_repeatability(n=16, trials=8):
    """The key race passed once and failed once. Measure how often."""
    diverged = 0
    counts = []
    for t in range(trials):
        d = tmpdir()
        got = []

        def w(_):
            try:
                got.append(load_or_create_signer(key_dir=d))
            except Exception:
                pass

        ts = [threading.Thread(target=w, args=(i,)) for i in range(n)]
        [x.start() for x in ts]
        [x.join() for x in ts]
        pubs = {s.get_public_key().export_public_pem() for s in got}
        counts.append(len(pubs))
        if len(pubs) > 1:
            diverged += 1
        shutil.rmtree(d, ignore_errors=True)

    ok = diverged == 0
    return ok, (f"{trials} trials x {n} threads -> {diverged}/{trials} produced >1 key; "
                f"distinct-key counts per trial={counts}")


def s4_verify_scaling_curve():
    """Measure how full-log verification scales. Real timings, not O() guesses."""
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    pub = s.get_public_key()
    pts = []
    added = 0
    for target in (100, 250, 500, 1000, 2000):
        while added < target:
            log.append(mkreceipt(s, added))
            added += 1
        t0 = time.perf_counter(); log.verify_integrity(); free = time.perf_counter() - t0
        t0 = time.perf_counter(); log.verify_integrity(pub); keyed = time.perf_counter() - t0
        pts.append((target, free * 1000, keyed * 1000))

    ratios = [pts[i][2] / pts[i - 1][2] for i in range(1, len(pts))]
    doubling = [f"{r:.2f}x" for r in ratios]
    lines = "\n         ".join(
        f"n={n:5d}  keyfree={f:8.1f} ms  keyed={k:8.1f} ms  ({k/n:.3f} ms/receipt)"
        for n, f, k in pts)
    last = pts[-1]
    ok = last[2] < 10_000
    return ok, (f"verify cost grows with total log size; per-step ratios {doubling}\n         {lines}\n"
                f"         at 2000 receipts a full keyed audit costs {last[2]/1000:.2f} s")


def s5_memory_growth():
    """Does signing N receipts leak? Measured, not assumed."""
    tracemalloc.start()
    s = Signer.generate()
    base = tracemalloc.take_snapshot()
    keep = []
    for i in range(2000):
        keep.append(mkreceipt(s, i))
    held = tracemalloc.take_snapshot()
    keep.clear()
    gc.collect()
    after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    held_kb = sum(x.size_diff for x in held.compare_to(base, "lineno")) / 1024
    leaked_kb = sum(x.size_diff for x in after.compare_to(base, "lineno")) / 1024
    ok = leaked_kb < held_kb * 0.25
    return ok, (f"2000 receipts held={held_kb:.0f} KB ({held_kb/2000*1024:.0f} B each); "
                f"after release residual={leaked_kb:.0f} KB -> "
                f"{'reclaimed' if ok else 'RETAINED — possible leak'}")


def s6_single_turn_inclusion_cost():
    """MEASURED replacement for the hardcoded e2.

    Question: to prove turn K is in an N-turn session, how many receipts must
    the auditor be given, and how much work is it? Derived by counting, not
    asserted.
    """
    N, K = 1000, 457
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    for i in range(N):
        log.append(mkreceipt(s, i))

    # (a) signature-only check for the single turn
    row = log.get_by_sequence(K)
    r = Receipt.from_json(row["receipt_json"])
    t0 = time.perf_counter()
    sig_ok = verify_receipt(r, s.get_public_key())
    sig_ms = (time.perf_counter() - t0) * 1000

    # (b) membership: count rows that must actually be read to establish that
    # this receipt sits at position K in an unbroken chain
    conn = sqlite3.connect(d / "log.db")
    rows_needed = conn.execute(
        "SELECT COUNT(*) FROM receipts WHERE sequence <= ?", (K,)).fetchone()[0]
    total_rows = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    conn.close()

    t0 = time.perf_counter()
    log.verify_integrity()
    memb_ms = (time.perf_counter() - t0) * 1000

    # (c) the same question via the session tree, measured head to head
    import math
    from aetherproof.core.session import Session
    sess = Session(s)
    for i in range(N):
        sess.record(prompt=f"q{i}", output=f"a{i}")
    t0 = time.perf_counter()
    seal = sess.seal()
    seal_ms = (time.perf_counter() - t0) * 1000
    proof = sess.prove(K)
    t0 = time.perf_counter()
    tree_ok = Session.verify_turn(proof, seal, s.get_public_key())
    tree_ms = (time.perf_counter() - t0) * 1000

    ideal = math.ceil(math.log2(N))
    compact = len(proof.proof) <= ideal
    ok = tree_ok and compact
    return ok, (f"turn {K} of {N}: signature-only verify={sig_ok} in {sig_ms:.2f} ms.\n"
                f"         LOG PATH    : {rows_needed} prior rows read, full scan over "
                f"{total_rows} rows, {memb_ms:.1f} ms, auditor needs every receipt.\n"
                f"         SESSION TREE: verified={tree_ok} from {len(proof.proof)} "
                f"sibling hashes (ceil(log2({N}))={ideal}) in {tree_ms:.3f} ms; "
                f"proof {len(proof.to_json())} bytes, seal {len(seal.to_json())} bytes "
                f"({seal_ms:.1f} ms to seal all {N} turns with ONE signature).\n"
                f"         speedup {memb_ms / max(tree_ms, 1e-6):.0f}x, and the other "
                f"{N - 1} turns are never disclosed.")


def s7_key_attribution_measured():
    """MEASURED replacement for the hardcoded f5.

    With M distinct signers, how much work identifies the right key for a
    receipt? Counted by actually trying them.
    """
    M = 50
    signers = [Signer.generate() for _ in range(M)]
    target_idx = 37
    target = signers[target_idx]
    r = mkreceipt(target, 1, signing_key_id=Receipt.key_id(target.get_public_key()))

    # (a) brute force, as any pre-v1.3 verifier had to
    brute = 0
    t0 = time.perf_counter()
    for s in signers:
        brute += 1
        if verify_receipt(r, s.get_public_key()):
            break
    brute_ms = (time.perf_counter() - t0) * 1000

    # (b) named lookup against a keyring
    ring = {Receipt.key_id(s.get_public_key()): s.get_public_key() for s in signers}
    t0 = time.perf_counter()
    picked = ring.get(r.signing_key_id)
    direct_ok = picked is not None and verify_receipt(r, picked)
    direct_ms = (time.perf_counter() - t0) * 1000

    named = r.signing_key_id != ""
    signed_in = r.signing_key_id in r.canonical_message()
    ok = named and direct_ok and signed_in
    return ok, (f"signing_key_id={r.signing_key_id!r} present={named}, "
                f"inside the signed preimage={signed_in}\n"
                f"         BRUTE FORCE : {brute} trial verifications over {M} keys, "
                f"{brute_ms:.2f} ms\n"
                f"         NAMED LOOKUP: 1 dict hit, verified={direct_ok}, "
                f"{direct_ms:.3f} ms -> {brute_ms / max(direct_ms, 1e-6):.0f}x faster, "
                f"and O(1) rather than O(M)")


def s8_large_payload():
    """Real timings on progressively larger outputs."""
    s = Signer.generate()
    pts = []
    for mb in (1, 8, 32):
        blob = os.urandom(mb * 1024 * 1024)
        t0 = time.perf_counter()
        h = sha256(blob.hex()[:0] or blob.decode("latin-1"))
        hash_ms = (time.perf_counter() - t0) * 1000
        r = Receipt(model_weight_root="a" * 64, output_hash=h,
                    model_root_type="artifact_hash")
        t0 = time.perf_counter()
        r.signature = s.sign(r.signing_bytes())
        sign_ms = (time.perf_counter() - t0) * 1000
        v = verify_receipt(r, s.get_public_key())
        pts.append((mb, hash_ms, sign_ms, v))

    lines = "\n         ".join(
        f"{mb:3d} MB output: hash={h:8.1f} ms  sign={sg:.3f} ms  verified={v}"
        for mb, h, sg, v in pts)
    ok = all(v for _, _, _, v in pts)
    return ok, (f"signing cost is constant in payload size (hash dominates)\n         {lines}")


def main():
    banner("I · FAULT ISOLATION — break one part, probe the others independently")
    probe("I", "i1  log destroyed -> signing still works", i1_log_deleted_signing_still_works)
    probe("I", "i2  log corrupted -> offline verify survives", i2_log_corrupted_offline_verify_survives)
    probe("I", "i3  private key destroyed -> old receipts still verify", i3_private_key_destroyed_verification_survives)
    probe("I", "i4  public key corrupted -> fails closed", i4_public_key_corrupted_fails_closed)
    probe("I", "i5  read-only storage -> append fails loudly", i5_readonly_dir_append_fails_loudly)
    probe("I", "i6  crash mid-write -> inconsistency detected", i6_crash_midwrite_leaves_log_consistent)
    probe("I", "i7  hash layer runs with zero I/O", i7_hash_module_independent_of_everything)
    probe("I", "i8  receipt layer runs with no signer", i8_receipt_serialisation_independent_of_signer)
    probe("I", "i9  verifier runs with no log", i9_verifier_needs_no_aetherproof_log)
    probe("I", "i10 one corrupt receipt -> others independently provable", i10_one_bad_receipt_does_not_block_the_rest)

    banner("S · EXTREME STRESS — ramp to the breaking point, report the threshold")
    probe("S", "s1  concurrency threshold (where does the chain first break?)", s1_concurrency_threshold)
    probe("S", "s2  is the corruption deterministic or flaky?", s2_corruption_rate_vs_load)
    probe("S", "s3  keygen race repeatability", s3_keygen_race_repeatability)
    probe("S", "s4  verification scaling curve", s4_verify_scaling_curve)
    probe("S", "s5  memory growth over 2000 receipts", s5_memory_growth)
    probe("S", "s6  cost to prove ONE turn of a 1000-turn session", s6_single_turn_inclusion_cost)
    probe("S", "s7  cost to identify WHICH key signed a receipt", s7_key_attribution_measured)
    probe("S", "s8  large payload signing", s8_large_payload)

    banner("SUMMARY")
    for sec in ("I", "S"):
        rows = [r for r in ROWS if r[0] == sec]
        p = sum(1 for r in rows if r[2])
        print(f"  {sec}: {p} OK · {len(rows) - p} BAD  ({len(rows)} probes)")
    bad = [r for r in ROWS if not r[2]]
    print(f"\n  TOTAL: {len(ROWS) - len(bad)} OK · {len(bad)} BAD  ({len(ROWS)} probes)")
    if bad:
        print("\n  BAD:")
        for sec, name, _, _ in bad:
            print(f"    [{sec}] {name}")


if __name__ == "__main__":
    main()
