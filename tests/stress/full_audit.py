"""Full adversarial + stress audit of AetherProof.

Standalone diagnostic harness (not a pytest suite) — it reports on behaviour
rather than asserting it, so a broken invariant prints a finding instead of
aborting the run. Run: python tests/stress/full_audit.py

Battery:
  A  concurrency (threads and processes) — the agentic-fleet case
  B  log tamper-evidence
  C  cryptographic correctness
  D  input robustness
  E  multi-turn session / selective verification
  F  key lifecycle
"""

import concurrent.futures as cf
import json
import multiprocessing as mp
import os
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from aetherproof.core.receipt import Receipt
from aetherproof.core.signer import Signer
from aetherproof.core.verifier import verify_receipt
from aetherproof.core.log import ReceiptLog, GENESIS
from aetherproof.core.keystore import load_or_create_signer, issue_receipt
from aetherproof.core.hash import sha256, compute_merkle_root, compute_model_weight_root

RESULTS = []


def record(section, name, passed, detail=""):
    RESULTS.append((section, name, passed, detail))
    mark = "PASS" if passed else "FAIL"
    print(f"  [{mark}] {name}" + (f"\n         {detail}" if detail else ""))


def banner(t):
    print(f"\n{'=' * 74}\n{t}\n{'=' * 74}")


def tmpdir():
    return Path(tempfile.mkdtemp(prefix="ap_audit_"))


def mkreceipt(signer, i=0, **kw):
    base = dict(model_weight_root="a" * 64, model_root_type="artifact_hash",
                input_commitment="b" * 64, output_hash="%064x" % i)
    base.update(kw)
    r = Receipt(**base)
    r.signature = signer.sign(r.signing_bytes())
    return r


# ── A · CONCURRENCY ───────────────────────────────────────────────────────────

def a1_concurrent_append(n=64):
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    signer = Signer.generate()
    errs = []

    def w(i):
        try:
            log.append(mkreceipt(signer, i))
        except Exception as e:
            errs.append(type(e).__name__)

    ts = [threading.Thread(target=w, args=(i,)) for i in range(n)]
    [t.start() for t in ts]
    [t.join() for t in ts]

    intact = log.verify_integrity()
    record("A", f"a1 concurrent append x{n} keeps the hash chain intact", intact,
           f"rows={log.count()} exceptions={len(errs)} integrity={intact} "
           f"-> silent corruption: writes succeed, chain is broken" if not intact else "")
    return d


def a2_concurrent_keygen(n=16):
    d = tmpdir()
    got = []

    def w(_):
        got.append(load_or_create_signer(key_dir=d))

    ts = [threading.Thread(target=w, args=(i,)) for i in range(n)]
    [t.start() for t in ts]
    [t.join() for t in ts]

    pubs = {s.get_public_key().export_public_pem() for s in got}
    on_disk = (d / "signing_key.pub").read_bytes()
    orphaned = sum(1 for s in got if s.get_public_key().export_public_pem() != on_disk)
    ok = len(pubs) == 1
    record("A", f"a2 concurrent load_or_create_signer x{n} yields ONE key", ok,
           f"distinct keys={len(pubs)} orphaned signers={orphaned} "
           f"-> receipts from orphaned signers are PERMANENTLY UNVERIFIABLE"
           if not ok else "")


def a3_concurrent_issue_receipt(n=32):
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    signer = Signer.generate()
    errs, made = [], []

    def w(i):
        try:
            r, p = issue_receipt(signer, log, model_weight_root="a" * 64,
                                 output_hash="%064x" % i,
                                 receipts_dir=d / "receipts")
            made.append(r)
        except Exception as e:
            errs.append(f"{type(e).__name__}")

    ts = [threading.Thread(target=w, args=(i,)) for i in range(n)]
    [t.start() for t in ts]
    [t.join() for t in ts]

    intact = log.verify_integrity()
    seqs = [r.log_sequence for r in made]
    dupes = len(seqs) - len(set(seqs))
    ok = intact and not errs and dupes == 0
    record("A", f"a3 concurrent issue_receipt x{n} (sign+persist+log)", ok,
           f"issued={len(made)} failed={len(errs)} dup_sequences={dupes} "
           f"integrity={intact} -> max_sequence()+1 is a TOCTOU race" if not ok else "")


def _proc_worker(args):
    dbpath, i = args
    try:
        log = ReceiptLog(db_path=dbpath)
        s = Signer.generate()
        log.append(mkreceipt(s, i))
        return None
    except Exception as e:
        return type(e).__name__


def a4_multiprocess_append(n=16):
    d = tmpdir()
    dbpath = str(d / "log.db")
    ReceiptLog(db_path=dbpath)
    with cf.ProcessPoolExecutor(max_workers=8) as ex:
        errs = [e for e in ex.map(_proc_worker, [(dbpath, i) for i in range(n)]) if e]
    log = ReceiptLog(db_path=dbpath)
    intact = log.verify_integrity()
    ok = intact and not errs
    record("A", f"a4 multi-PROCESS append x{n} (real agent fleet)", ok,
           f"rows={log.count()} errors={errs[:3]} integrity={intact} "
           f"-> no cross-process lock; sqlite default is not enough" if not ok else "")


def a5_sustained_load(n=500):
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    signer = Signer.generate()
    t0 = time.perf_counter()
    for i in range(n):
        log.append(mkreceipt(signer, i))
    dt = time.perf_counter() - t0
    intact = log.verify_integrity()
    t1 = time.perf_counter()
    log.verify_integrity(signer.get_public_key())
    vdt = time.perf_counter() - t1
    record("A", f"a5 sequential {n} receipts stay intact", intact,
           f"append {dt / n * 1000:.2f} ms/receipt · full-log verify {vdt * 1000:.0f} ms "
           f"-> verify is O(n), grows with every receipt ever issued")


# ── B · LOG TAMPER-EVIDENCE ───────────────────────────────────────────────────

def _seeded_log(n=6):
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    for i in range(n):
        log.append(mkreceipt(s, i))
    return d, log, s


def b_tamper_suite():
    # b1 delete a row
    d, log, s = _seeded_log()
    c = sqlite3.connect(d / "log.db"); c.execute("DELETE FROM receipts WHERE sequence=3"); c.commit(); c.close()
    record("B", "b1 row deletion is detected", not log.verify_integrity())

    # b2 content edit
    d, log, s = _seeded_log()
    c = sqlite3.connect(d / "log.db")
    c.execute("UPDATE receipts SET output_hash='f'*64 WHERE sequence=2"); c.commit(); c.close()
    record("B", "b2 column edit is detected", not log.verify_integrity())

    # b3 body edit
    d, log, s = _seeded_log()
    c = sqlite3.connect(d / "log.db")
    row = c.execute("SELECT receipt_json FROM receipts WHERE sequence=2").fetchone()[0]
    j = json.loads(row); j["output_hash"] = "e" * 64
    c.execute("UPDATE receipts SET receipt_json=? WHERE sequence=2", (json.dumps(j),)); c.commit(); c.close()
    record("B", "b3 receipt_json body edit is detected", not log.verify_integrity())

    # b4 tail truncation — the documented gap
    d, log, s = _seeded_log()
    c = sqlite3.connect(d / "log.db"); c.execute("DELETE FROM receipts WHERE sequence>4"); c.commit(); c.close()
    detected = not log.verify_integrity()
    record("B", "b4 TAIL truncation is detected", detected,
           "" if detected else "known gap: a shorter chain is self-consistent; "
                               "needs a signed/published log head (SIGNET)")

    # b5 delete-then-renumber
    d, log, s = _seeded_log()
    c = sqlite3.connect(d / "log.db")
    c.execute("DELETE FROM receipts WHERE sequence=3")
    c.execute("UPDATE receipts SET sequence=sequence-1 WHERE sequence>3"); c.commit(); c.close()
    record("B", "b5 delete-then-renumber is detected", not log.verify_integrity())


# ── C · CRYPTOGRAPHIC CORRECTNESS ─────────────────────────────────────────────

def c_crypto_suite():
    a, b, c_ = sha256("a"), sha256("b"), sha256("c")
    record("C", "c1 merkle odd-leaf duplication (CVE-2012-2459)",
           compute_merkle_root([a, b, c_]) != compute_merkle_root([a, b, c_, c_]))

    from aetherproof.core.hash import merkle_leaf, merkle_node
    internal = merkle_node(merkle_leaf(a), merkle_leaf(b))
    record("C", "c2 leaf/internal domain separation",
           compute_merkle_root([a, b]) != compute_merkle_root([internal]))

    d = tmpdir()
    for name, (f1, f2) in {"m1": ("weights.bin", "config.json"),
                           "m2": ("config.json", "weights.bin")}.items():
        p = d / name; p.mkdir()
        (p / f1).write_bytes(b"AAAA"); (p / f2).write_bytes(b"BBBB")
    record("C", "c3 model root binds file NAMES not just bytes",
           compute_model_weight_root(d / "m1") != compute_model_weight_root(d / "m2"))

    honest = Receipt.api_attested_root("m", "openai", system_fingerprint="fp_2")
    forged = Receipt.api_attested_root("m|system_fingerprint:fp_2", "openai")
    record("C", "c4 api_attested_root resists model_id smuggling", honest != forged,
           "" if honest != forged else 'non-injective "|".join — caller can forge '
                                       "the provider fingerprint binding")

    r = mkreceipt(Signer.generate())
    record("C", "c5 receipt_id is bound by the signature",
           r.receipt_id in r.canonical_message(),
           "" if r.receipt_id in r.canonical_message()
           else "receipt_id is unsigned: a standalone receipt file's id can be "
                "rewritten and still verify")

    # preimage injectivity against delimiter injection
    s = Signer.generate()
    x = mkreceipt(s, log_anchor="local://log/1", model_root_type="artifact_hash")
    y = mkreceipt(s, log_anchor="", model_root_type="artifact_hash1:local://log/1")
    record("C", "c6 preimage resists delimiter injection",
           x.canonical_message() != y.canonical_message())


# ── D · INPUT ROBUSTNESS ──────────────────────────────────────────────────────

def d_input_suite():
    s = Signer.generate()

    try:
        r = Receipt(model_weight_root="a" * 64,
                    output_hash=sha256("unicode 日本語 \x00 pipe| colon: back\\ end"),
                    input_commitment=sha256("emoji"))
        r.signature = s.sign(r.signing_bytes())
        ok = verify_receipt(r, s.get_public_key())
    except Exception as e:
        ok = False
    record("D", "d1 unicode / NUL in hashed content round-trips", ok)

    r = Receipt(model_weight_root="a" * 64, output_hash="c" * 64,
                timestamp_ms="1700000000000", log_sequence="5")
    r2 = Receipt.from_dict(r.to_dict())
    record("D", "d2 str/int type confusion is coerced",
           isinstance(r2.timestamp_ms, int) and isinstance(r2.log_sequence, int))

    r = mkreceipt(s)
    d = r.to_dict(); d["future_field_from_v9"] = "x"
    try:
        Receipt.from_dict(d); ok = True
    except Exception:
        ok = False
    record("D", "d3 unknown fields ignored (forward compat)", ok)

    big = "x" * 5_000_000
    t0 = time.perf_counter()
    h = sha256(big)
    record("D", f"d4 5 MB output hashes in {(time.perf_counter() - t0) * 1000:.0f} ms", True)

    r = mkreceipt(s)
    j = r.to_json()
    back = Receipt.from_json(j)
    record("D", "d5 JSON round-trip preserves the signature",
           verify_receipt(back, s.get_public_key()))

    r = Receipt(model_weight_root="", output_hash="", signature="")
    record("D", "d6 empty receipt is rejected by verifier",
           not verify_receipt(r, s.get_public_key()))


# ── E · MULTI-TURN SESSION ────────────────────────────────────────────────────

def e_session_suite(turns=1000, target=457):
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    s = Signer.generate()
    for i in range(turns):
        log.append(mkreceipt(s, i))

    row = log.get_by_sequence(target)
    r = Receipt.from_json(row["receipt_json"])
    single_ok = verify_receipt(r, s.get_public_key())
    record("E", f"e1 turn #{target} of {turns} verifies standalone (sig only)", single_ok)

    # membership via the session tree: one turn + a sibling path, nothing else
    from aetherproof.core.session import Session
    sess = Session(s)
    for i in range(turns):
        sess.record(prompt=f"q{i}", output=f"a{i}")
    seal = sess.seal()
    proof = sess.prove(target)
    t0 = time.perf_counter()
    member = Session.verify_turn(proof, seal, s.get_public_key())
    memb_ms = (time.perf_counter() - t0) * 1000
    import math
    compact = len(proof.proof) <= math.ceil(math.log2(turns))
    record("E", f"e2 proving turn #{target} is IN the log without reading all {turns}",
           member and compact,
           f"session tree: verified={member} from {len(proof.proof)} sibling hashes "
           f"(ceil(log2({turns}))={math.ceil(math.log2(turns))}) in {memb_ms:.3f} ms; "
           f"proof is {len(proof.to_json())} bytes and carries no other turn")

    turn_ids = {log.get_by_sequence(i)["receipt_id"] for i in range(1, turns + 1)}
    record("E", "e3 receipts are unique across a long session",
           len(turn_ids) == turns, f"unique ids={len(turn_ids)}/{turns}")

    # a turn must be bound to ITS session: the same proof under a different
    # session's seal has to fail, or "which conversation" means nothing
    other = Session(s)
    for i in range(turns):
        other.record(prompt=f"q{i}", output=f"a{i}")
    cross = Session.verify_turn(proof, other.seal(), s.get_public_key())
    bound = (proof.session_id == seal.session_id) and (cross is False)
    record("E", "e4 a turn is bound to its own session, not a replayable copy", bound,
           f"session_id carried={proof.session_id[:12]}…; replaying this proof "
           f"against an identical-content sibling session verified={cross} "
           f"(must be False)")


# ── F · KEY LIFECYCLE ─────────────────────────────────────────────────────────

def f_key_suite():
    d = tmpdir()
    log = ReceiptLog(db_path=str(d / "log.db"))
    old = Signer.generate()
    for i in range(3):
        log.append(mkreceipt(old, i))

    new = Signer.generate()
    record("F", "f1 old receipts still verify with the OLD key after rotation",
           verify_receipt(Receipt.from_json(log.get_by_sequence(1)["receipt_json"]),
                          old.get_public_key()))
    record("F", "f2 key-free log integrity survives rotation", log.verify_integrity())
    keyed = log.verify_integrity(new.get_public_key())
    rep = log.verify_integrity_report(new.get_public_key())
    record("F", "f3 keyed log verify after rotation does not false-flag", keyed,
           f"{rep}; rows we hold no key for are reported unverifiable rather than "
           f"forged, and strict_keys=True still demands full coverage")

    # opt-in passphrase: measure both paths rather than assuming either
    import os as _os
    dd = tmpdir()
    _os.environ["AETHERPROOF_KEY_PASSPHRASE"] = "correct horse battery staple"
    try:
        load_or_create_signer(key_dir=dd)
        priv = dd / "signing_key.pem"
        enc = b"ENCRYPTED" in priv.read_bytes()
        mode = oct(priv.stat().st_mode)[-3:]
    finally:
        _os.environ.pop("AETHERPROOF_KEY_PASSPHRASE", None)

    dd2 = tmpdir()
    load_or_create_signer(key_dir=dd2)
    plain = dd2 / "signing_key.pem"
    plain_enc = b"ENCRYPTED" in plain.read_bytes()
    record("F", "f4 private key can be encrypted at rest", enc and not plain_enc,
           f"with AETHERPROOF_KEY_PASSPHRASE set: encrypted={enc}, mode {mode}. "
           f"Without it: encrypted={plain_enc} (file-permission protection only) "
           f"— opt-in, so the default install still leaks on a readable disk")

    d3 = tmpdir()
    l3 = ReceiptLog(db_path=str(d3 / "log.db"))
    sg = Signer.generate()
    issued, _ = issue_receipt(sg, l3, model_weight_root="a" * 64,
                              output_hash="c" * 64, receipts_dir=d3 / "r")
    named = issued.signing_key_id == Receipt.key_id(sg.get_public_key())
    signed_in = issued.signing_key_id in issued.canonical_message()
    record("F", "f5 a receipt names which key signed it", named and signed_in,
           f"signing_key_id={issued.signing_key_id} matches the signer={named}, "
           f"and is inside the signed preimage={signed_in} -> O(1) key lookup "
           f"instead of trying every key held")


def main():
    banner("A · CONCURRENCY — the agentic-fleet case")
    a1_concurrent_append()
    a2_concurrent_keygen()
    a3_concurrent_issue_receipt()
    a4_multiprocess_append()
    a5_sustained_load()

    banner("B · LOG TAMPER-EVIDENCE")
    b_tamper_suite()

    banner("C · CRYPTOGRAPHIC CORRECTNESS")
    c_crypto_suite()

    banner("D · INPUT ROBUSTNESS")
    d_input_suite()

    banner("E · MULTI-TURN SESSION / SELECTIVE VERIFICATION")
    e_session_suite()

    banner("F · KEY LIFECYCLE")
    f_key_suite()

    banner("SUMMARY")
    bys = {}
    for sec, name, ok, _ in RESULTS:
        p, f = bys.get(sec, (0, 0))
        bys[sec] = (p + (1 if ok else 0), f + (0 if ok else 1))
    for sec in sorted(bys):
        p, f = bys[sec]
        print(f"  {sec}: {p} pass · {f} FAIL")
    tp = sum(p for p, _ in bys.values()); tf = sum(f for _, f in bys.values())
    print(f"\n  TOTAL: {tp} pass · {tf} FAIL  ({tp + tf} checks)")
    print("\n  FAILING:")
    for sec, name, ok, _ in RESULTS:
        if not ok:
            print(f"    [{sec}] {name}")


if __name__ == "__main__":
    mp.freeze_support()
    main()
