"""Industrial-scale stress: real processes, sustained load, mixed workload.

The earlier batteries used threads and modest N. This one is shaped like actual
deployments:

  P1  agent fleet     — N separate OS PROCESSES hammering one shared log+key,
                        the way a CI matrix or a container fleet does
  P2  sustained       — high volume over time, watching for drift or degradation
  P3  mixed workload  — single receipts AND session sealing at once, contending
  P4  cold start swarm— M processes racing to create the key from nothing
  P5  crash recovery  — kill writers mid-flight, verify the log survives
  P6  long session    — 50k turns, proof cost and memory at scale
  P7  headless matrix — the automation module under the same pressure

Run: python tests/stress/industrial_stress.py [scale]
     scale defaults to 1; pass 2, 4 ... to multiply the load.

No verdict here is a literal. Every result is computed and its evidence printed.
"""

from __future__ import annotations

import concurrent.futures as cf
import gc
import math
import multiprocessing as mp
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from aetherproof.core.log import ReceiptLog
from aetherproof.core.receipt import Receipt
from aetherproof.core.session import Session
from aetherproof.core.signer import Signer

ROWS = []
SCALE = 1


def probe(section, name, fn):
    t0 = time.perf_counter()
    try:
        ok, evidence = fn()
    except Exception as e:
        import traceback
        ok, evidence = False, f"UNCAUGHT {type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}"
    dt = time.perf_counter() - t0
    ROWS.append((section, name, ok, evidence, dt))
    print(f"  [{'OK ' if ok else 'BAD'}] {name}   ({dt:.1f}s)\n         {evidence}")


def banner(t):
    print(f"\n{'=' * 78}\n{t}\n{'=' * 78}")


def tmpdir():
    return Path(tempfile.mkdtemp(prefix="ap_ind_"))


def mkreceipt(signer, i, **kw):
    base = dict(model_weight_root="a" * 64, model_root_type="artifact_hash",
                input_commitment="b" * 64, output_hash="%064x" % i)
    base.update(kw)
    r = Receipt(**base)
    r.signature = signer.sign(r.signing_bytes())
    return r


# ── module-level workers (must be picklable for ProcessPoolExecutor) ─────────

def _fleet_worker(args):
    """One agent process: open the shared log, append a batch."""
    db, key_pem, n, wid = args
    try:
        from aetherproof.core.signer import Signer as S
        from aetherproof.core.log import ReceiptLog as L
        sgn = S.from_private_pem(key_pem)
        log = L(db_path=db)
        wrote, errs = 0, []
        for i in range(n):
            try:
                log.append(mkreceipt(sgn, wid * 100000 + i))
                wrote += 1
            except Exception as e:
                errs.append(type(e).__name__)
        return (wrote, errs)
    except Exception as e:
        return (0, [f"FATAL {type(e).__name__}: {e}"])


def _coldstart_worker(args):
    """Race to create the signing key from an empty directory."""
    home, _ = args
    try:
        from aetherproof.core.keystore import load_or_create_signer
        s = load_or_create_signer(key_dir=Path(home))
        return s.get_public_key().export_public_pem()
    except Exception as e:
        return f"ERR {type(e).__name__}: {e}".encode()


def _mixed_worker(args):
    """Half the processes issue receipts, half seal sessions, same key+log."""
    db, key_pem, n, wid, mode = args
    try:
        from aetherproof.core.signer import Signer as S
        from aetherproof.core.log import ReceiptLog as L
        from aetherproof.core.session import Session as Sess
        sgn = S.from_private_pem(key_pem)
        if mode == "receipts":
            log = L(db_path=db)
            ok = 0
            for i in range(n):
                try:
                    log.append(mkreceipt(sgn, wid * 100000 + i))
                    ok += 1
                except Exception:
                    pass
            return ("receipts", ok, "")
        else:
            s = Sess(sgn)
            for i in range(n):
                s.record(prompt=f"q{i}", output=f"a{i}")
            seal = s.seal()
            proof = s.prove(n // 2)
            good = Sess.verify_turn(proof, seal, sgn.get_public_key())
            return ("session", 1 if good else 0, seal.merkle_root[:12])
    except Exception as e:
        return ("error", 0, f"{type(e).__name__}: {e}")


def _crash_worker(args):
    """Append, then hard-exit partway through to simulate a killed container."""
    db, key_pem, n, wid, die_at = args
    from aetherproof.core.signer import Signer as S
    from aetherproof.core.log import ReceiptLog as L
    sgn = S.from_private_pem(key_pem)
    log = L(db_path=db)
    for i in range(n):
        if i == die_at:
            os._exit(9)  # no cleanup, no flush — a real kill
        try:
            log.append(mkreceipt(sgn, wid * 100000 + i))
        except Exception:
            pass
    return wid


def _headless_worker(args):
    """The automation module, under process-level contention."""
    home, n, wid = args
    try:
        os.environ["AETHERPROOF_HOME"] = home
        os.environ["AETHERPROOF_STRICT"] = "1"
        from aetherproof import auto
        auto.reset()
        made = 0
        with auto.AutoSession(model_id="claude-opus-5") as s:
            for i in range(n):
                if s.turn(prompt=f"q{wid}-{i}", output=f"a{wid}-{i}") is not None:
                    made += 1
        sealed = s.seal is not None
        return (made, sealed, "")
    except Exception as e:
        return (0, False, f"{type(e).__name__}: {e}")


# ── P1 · agent fleet ─────────────────────────────────────────────────────────

def p1_process_fleet():
    procs = 12 * SCALE
    per = 25
    d = tmpdir()
    db = str(d / "log.db")
    ReceiptLog(db_path=db)
    signer = Signer.generate()
    pem = signer.export_private_pem()

    t0 = time.perf_counter()
    with cf.ProcessPoolExecutor(max_workers=procs) as ex:
        results = list(ex.map(_fleet_worker,
                              [(db, pem, per, w) for w in range(procs)]))
    dt = time.perf_counter() - t0

    wrote = sum(w for w, _ in results)
    errs = [e for _, es in results for e in es]
    log = ReceiptLog(db_path=db)
    report = log.verify_integrity_report(signer.get_public_key())
    expected = procs * per
    rows = log.count()          # read everything BEFORE the tree is removed

    ok = report.ok and wrote == expected and rows == expected and not errs
    shutil.rmtree(d, ignore_errors=True)
    return ok, (f"{procs} PROCESSES x {per} receipts = {expected} expected; "
                f"wrote={wrote} rows={rows} errors={len(errs)} "
                f"({sorted(set(errs))[:3] if errs else 'none'})\n"
                f"         chain {report}; {expected/dt:.0f} receipts/sec aggregate")


# ── P2 · sustained volume ────────────────────────────────────────────────────

def p2_sustained_volume():
    n = 20000 * SCALE
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    signer = Signer.generate()

    marks, t0 = [], time.perf_counter()
    for i in range(n):
        log.append(mkreceipt(signer, i))
        if (i + 1) % (n // 5) == 0:
            marks.append((i + 1, time.perf_counter() - t0))
    total = time.perf_counter() - t0

    # per-quintile rate: is throughput degrading as the log grows?
    rates = []
    prev_i, prev_t = 0, 0.0
    for i, t in marks:
        rates.append((i - prev_i) / (t - prev_t))
        prev_i, prev_t = i, t
    drift = rates[-1] / rates[0] if rates[0] else 0

    t0 = time.perf_counter()
    intact = log.verify_integrity()
    verify_s = time.perf_counter() - t0
    size_mb = (d / "log.db").stat().st_size / 1e6

    ok = intact and drift > 0.5  # no worse than 2x slowdown across the run
    shutil.rmtree(d, ignore_errors=True)
    return ok, (f"{n} sequential receipts in {total:.1f}s "
                f"({n/total:.0f}/sec, {total/n*1000:.2f} ms each)\n"
                f"         throughput by quintile: {' '.join(f'{r:.0f}' for r in rates)} /sec "
                f"-> last/first = {drift:.2f}x\n"
                f"         db {size_mb:.1f} MB; key-free verify of all {n} rows "
                f"{verify_s:.1f}s; intact={intact}")


# ── P3 · mixed workload ──────────────────────────────────────────────────────

def p3_mixed_workload():
    procs = 8 * SCALE
    d = tmpdir()
    db = str(d / "log.db")
    ReceiptLog(db_path=db)
    signer = Signer.generate()
    pem = signer.export_private_pem()

    jobs = [(db, pem, 30, w, "receipts" if w % 2 == 0 else "sessions")
            for w in range(procs)]
    with cf.ProcessPoolExecutor(max_workers=procs) as ex:
        results = list(ex.map(_mixed_worker, jobs))

    rec_ok = sum(c for m, c, _ in results if m == "receipts")
    sess_ok = sum(c for m, c, _ in results if m == "session")
    errors = [x for m, _, x in results if m == "error"]
    roots = {x for m, _, x in results if m == "session" and x}

    log = ReceiptLog(db_path=db)
    report = log.verify_integrity_report(signer.get_public_key())
    expected_receipts = (procs // 2) * 30
    expected_sessions = procs - procs // 2

    ok = (report.ok and rec_ok == expected_receipts
          and sess_ok == expected_sessions and not errors
          and len(roots) == expected_sessions)
    shutil.rmtree(d, ignore_errors=True)
    return ok, (f"{procs} processes, half appending receipts + half sealing sessions "
                f"against ONE key and log\n"
                f"         receipts {rec_ok}/{expected_receipts}, "
                f"sessions verified {sess_ok}/{expected_sessions}, "
                f"distinct roots {len(roots)} (must equal sessions), errors={errors[:2]}\n"
                f"         {report}")


# ── P4 · cold-start swarm ────────────────────────────────────────────────────

def p4_cold_start_swarm():
    procs = 16 * SCALE
    d = tmpdir()
    home = str(d / "home")
    Path(home).mkdir(parents=True)

    with cf.ProcessPoolExecutor(max_workers=procs) as ex:
        pems = list(ex.map(_coldstart_worker, [(home, w) for w in range(procs)]))

    errs = [p for p in pems if p.startswith(b"ERR")]
    distinct = {p for p in pems if not p.startswith(b"ERR")}
    on_disk = (Path(home) / "signing_key.pub").read_bytes()
    orphaned = sum(1 for p in distinct if p != on_disk)

    ok = len(distinct) == 1 and orphaned == 0 and not errs
    shutil.rmtree(d, ignore_errors=True)
    return ok, (f"{procs} PROCESSES racing to create a key from an empty dir: "
                f"distinct keys={len(distinct)} orphaned={orphaned} errors={len(errs)}\n"
                f"         (>1 key here means some processes signed with a key whose "
                f"public half was overwritten — permanently unverifiable receipts)")


# ── P5 · crash recovery ──────────────────────────────────────────────────────

def p5_crash_recovery():
    d = tmpdir()
    db = str(d / "log.db")
    ReceiptLog(db_path=db)
    signer = Signer.generate()
    pem = signer.export_private_pem()

    killed = 4
    survivors = 4
    procs = []
    ctx = mp.get_context("spawn")
    for w in range(killed):
        p = ctx.Process(target=_crash_worker, args=((db, pem, 40, w, 15),))
        p.start()
        procs.append(p)
    for w in range(killed, killed + survivors):
        p = ctx.Process(target=_crash_worker, args=((db, pem, 20, w, -1),))
        p.start()
        procs.append(p)
    for p in procs:
        p.join(timeout=120)

    exits = [p.exitcode for p in procs]
    log = ReceiptLog(db_path=db)
    report = log.verify_integrity_report(signer.get_public_key())
    rows = log.count()

    # the log must be internally consistent despite hard kills mid-write
    ok = report.ok and rows > 0
    shutil.rmtree(d, ignore_errors=True)
    return ok, (f"{killed} processes os._exit(9) mid-write + {survivors} clean; "
                f"exit codes {exits}\n"
                f"         {rows} rows committed; {report}\n"
                f"         (a hard kill must never leave a chain that reads as tampered)")


# ── P6 · very long session ───────────────────────────────────────────────────

def p6_long_session():
    n = 50000 * SCALE
    signer = Signer.generate()
    pub = signer.get_public_key()

    tracemalloc.start()
    base = tracemalloc.take_snapshot()
    s = Session(signer)
    t0 = time.perf_counter()
    for i in range(n):
        s.record(prompt_hash="%064x" % i, output_hash="%064x" % (i + 1))
    record_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    seal = s.seal()
    seal_s = time.perf_counter() - t0

    held = sum(x.size_diff for x in tracemalloc.take_snapshot().compare_to(base, "lineno"))
    tracemalloc.stop()

    picks = [0, n // 3, n // 2, n - 1, random.randrange(n)]
    proofs, verify_ms, sizes = [], [], []
    for k in picks:
        p = s.prove(k)
        t0 = time.perf_counter()
        good = Session.verify_turn(p, seal, pub)
        verify_ms.append((time.perf_counter() - t0) * 1000)
        proofs.append((k, len(p.proof), good))
        sizes.append(len(p.to_json()))

    ideal = math.ceil(math.log2(n))
    all_good = all(g for _, _, g in proofs)
    compact = all(l <= ideal for _, l, _ in proofs)
    ok = all_good and compact

    del s
    gc.collect()
    return ok, (f"{n} turns: record {record_s:.1f}s ({record_s/n*1e6:.0f} us/turn), "
                f"seal {seal_s:.1f}s, held {held/1e6:.0f} MB ({held/n:.0f} B/turn)\n"
                f"         proofs {[(k, l) for k, l, _ in proofs]} "
                f"(ceil(log2({n}))={ideal}), all verified={all_good}\n"
                f"         proof {min(sizes)}-{max(sizes)} B, verify "
                f"{min(verify_ms):.3f}-{max(verify_ms):.3f} ms, seal {len(seal.to_json())} B")


# ── P7 · headless under load ─────────────────────────────────────────────────

def p7_headless_matrix():
    procs = 8 * SCALE
    per = 50
    d = tmpdir()
    home = str(d / "home")
    Path(home).mkdir(parents=True)

    with cf.ProcessPoolExecutor(max_workers=procs) as ex:
        results = list(ex.map(_headless_worker, [(home, per, w) for w in range(procs)]))

    made = sum(m for m, _, _ in results)
    sealed = sum(1 for _, s, _ in results if s)
    errs = [e for _, _, e in results if e]
    seals = list((Path(home) / "sessions").glob("*.seal.json"))

    ok = (made == procs * per and sealed == procs
          and not errs and len(seals) == procs)
    shutil.rmtree(d, ignore_errors=True)
    return ok, (f"{procs} PROCESSES x {per} turns via aetherproof.auto with STRICT=1, "
                f"sharing one AETHERPROOF_HOME\n"
                f"         turns recorded {made}/{procs*per}, sessions sealed "
                f"{sealed}/{procs}, seal files on disk {len(seals)}, errors={errs[:2]}")


def main():
    global SCALE
    if len(sys.argv) > 1:
        SCALE = int(sys.argv[1])
    print(f"AetherProof industrial stress — scale x{SCALE}, "
          f"{mp.cpu_count()} CPUs, pid {os.getpid()}")

    banner("P · INDUSTRIAL LOAD")
    probe("P", "p1  agent fleet: 12 OS processes on one shared log", p1_process_fleet)
    probe("P", "p2  sustained: 20k receipts, watching for throughput drift", p2_sustained_volume)
    probe("P", "p3  mixed workload: receipts + session sealing concurrently", p3_mixed_workload)
    probe("P", "p4  cold-start swarm: 16 processes racing to create the key", p4_cold_start_swarm)
    probe("P", "p5  crash recovery: hard-kill writers mid-flight", p5_crash_recovery)
    probe("P", "p6  long session: 50k turns, proof cost at scale", p6_long_session)
    probe("P", "p7  headless module under process-level contention", p7_headless_matrix)

    banner("SUMMARY")
    ok = sum(1 for r in ROWS if r[2])
    total_s = sum(r[4] for r in ROWS)
    print(f"  {ok} OK · {len(ROWS) - ok} BAD  ({len(ROWS)} probes, {total_s:.0f}s)")
    bad = [r for r in ROWS if not r[2]]
    if bad:
        print("\n  BAD:")
        for sec, name, _, ev, _ in bad:
            print(f"    [{sec}] {name}")
    return 0 if not bad else 1


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
