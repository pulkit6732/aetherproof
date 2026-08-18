# v0.4.0 — concurrency, key custody, session proofs, headless API

**If you are running 0.2.x, upgrade.** The transparency log's hash chain forked at
**two** concurrent writers — silently, with every row written and no exception raised.
An auditor running the integrity check on such a log gets `False` and concludes
tampering, when two threads merely wrote at once. Details below.

```
pip install --upgrade aetherproof
```

Every defect listed here was found by executing the shipped code, not by reading it.
Each fix carries a regression test that fails against the previous version.

---

## ⚠️ Concurrency — the reason to upgrade

The log chain broke at **N=2** concurrent writers. Measured, before the fix:

```
threads=  1  rows=  1  errors=0  chain_intact=True
threads=  2  rows=  2  errors=0  chain_intact=False   ← breaks here
threads=128  rows=128  errors=0  chain_intact=False
```

**Zero exceptions at every level.** `append()` read the chain head and wrote the row
without a lock spanning both, so concurrent writers read the same head and the chain
forked. At 32 threads, 31 of 32 rows broke the chain and 22 shared one parent.

This is the worst possible failure shape for a tamper-evidence tool: genuine tampering
became indistinguishable from a benign race, in both directions.

**Fixed** with WAL + `BEGIN IMMEDIATE`, making the read-then-write atomic across threads
*and* processes. Verified intact to 128 threads and 12 OS processes.

Two related races closed with it:

- `load_or_create_signer()` handed out **2–4 distinct keys in 8 of 8 trials**. The losing
  threads' public keys were overwritten and never persisted, making their receipts
  **permanently unverifiable**. Now an atomic `O_EXCL` claim — 8/8 trials, one key.
- `issue_receipt()` failed **29 of 32** concurrent calls. The sequence is inside the
  signing preimage, so it now re-signs against the new head with a bounded retry.

**Throughput: 112 → 1406 receipts/sec.** Profiling showed connection churn was two thirds
of every append; the journal mode is now set once and connections are cached per thread.

---

## Cryptographic correctness

- **Merkle odd-leaf duplication (CVE-2012-2459 pattern).** `root([A,B,C])` equalled
  `root([A,B,C,C])`, so a model directory's root did not identify a unique file set.
  Now RFC 6962 domain separation, odd node promoted rather than duplicated.
- **`api_attested_root` was forgeable.** A non-injective `"|".join` let a caller smuggle
  `|system_fingerprint:…` into `model_id` and produce the same root as an honest call
  that really carried that fingerprint. Now length-prefixed.
- **`model_weight_root` ignored filenames.** Two directories holding identical bytes under
  different names produced the same root; renaming `weights.bin` to `config.json` was
  invisible. Leaves now commit to path and content.
- **`receipt_id` collided** for receipts issued in the same millisecond — it was derived
  from `timestamp_ms`. Now random, and bound inside the signature.
- **Extension aggregation was ambiguous** — see the interoperability note below.

---

## Interoperability fix (issue #1)

Reported by **Aleksey Safonov ([@safal207](https://github.com/safal207))** on 2026-06-24.

The `signed_extensions` aggregate sorted **namespace keys** while the specification sorted
the resulting **commitments**. With two or more extensions those orders diverge, so two
implementations — each correctly following one reading — signed the same receipt
differently. Reproduced:

```
namespaces   'ns.a3/v1' < 'ns.b3/v1'        (namespace order)
commitments   d54ac416… > 99776f84…         (reversed)

sorted by namespace   → sha256:c55734d7…
sorted by commitment  → sha256:cc60ffcc…
```

**The normative rule is now to sort the commitments**, with cross-implementation test
vectors in `tests/security/test_v12_extensions.py`. Single-extension receipts are
unaffected — one leaf sorts to itself — so nothing already issued breaks.

Also per that issue, the scope of the aggregate is now stated explicitly: it provides
multi-extension **integrity**, not standalone selective disclosure. Verifying one disclosed
namespace requires either every other commitment or a Merkle inclusion proof. Disclosure is
all-or-nothing at v1.2 by design; a domain-separated Merkle profile is deferred.

---

## Receipt v1.3

New receipts default to `receipt_version` **1.3**, which binds two fields the signature
previously left free:

| Field | Why |
|---|---|
| `receipt_id` | was rewritable on a standalone receipt file without breaking the signature |
| `signing_key_id` | identifies the signing key, so a verifier holding many keys picks the right one in one lookup instead of trying each in turn (measured: 38 trial verifications across 50 keys → 1) |

**v1.1 and v1.2 receipts still verify, byte-exact.** The legacy preimage builders are
retained verification-only. A fix that invalidated receipts already in an auditor's hands
would be worse than the defect it closed.

---

## New: session proofs

`aetherproof.core.session` — sign a whole conversation, or any slice of it, with **one**
signature, then prove any single turn without disclosing the others.

```python
from aetherproof.core.session import Session

s = Session(signer)
s.record(prompt="…", output="…")     # turn 0
s.record(prompt="…", output="…")     # turn 1

seal  = s.seal()                      # whole session
seal  = s.seal(start=5, end=12)       # a range
proof = s.prove(457)                  # one turn

Session.verify_turn(proof, seal, public_key)     # offline
```

Measured at 1000 turns:

| | Before | After |
|---|---|---|
| Prove one turn | 457 log rows read, full scan | **10 hashes** (`⌈log₂1000⌉`) |
| Proof size | every receipt in the session | **1094 bytes** |
| Verify | 20.9 ms | **0.225 ms** |
| Seal | — | **412 bytes, one signature for 1000 turns** |

Verifying one turn reveals nothing about the other 999. At 50,000 turns: 51 µs/turn to
record, proofs ≤16 hashes, verify 0.3–1.2 ms.

Receipts can also name their session and turn *inside* the signature, populating the v1.2
extension mechanism proposed in issue #1.

---

## New: headless API

`aetherproof.auto` — for CI, agent loops, cron, and cloud coding models. Never prompts,
never blocks, never reads stdin.

```python
from aetherproof.auto import sign, AutoSession, receipted

sign(prompt="…", output="…", model_id="gpt-4o")   # one call, no setup

with AutoSession(model_id="…") as s:               # seals on exit
    s.turn(prompt="…", output="…")

@receipted(model_id="gpt-4o")                      # wrap any client
def ask(prompt): ...
```

| Env var | Effect |
|---|---|
| `AETHERPROOF_HOME` | where key, log and receipts live |
| `AETHERPROOF_KEY_PASSPHRASE` | encrypts the key at rest |
| `AETHERPROOF_DISABLE=1` | every call becomes a no-op |
| `AETHERPROOF_STRICT=1` | raise on failure instead of degrading |

**Failure policy:** by default a receipt failure returns `None` and your work proceeds — a
pipeline losing a receipt is bad, a pipeline crashing over one is worse. `STRICT=1` inverts
that where a missing receipt *is* the failure.

---

## Verification and key rotation

- **Key rotation no longer false-flags an authentic log.** `verify_integrity` accepts a
  single key, a list, or a `{key_id: key}` mapping. A row naming a key you were not given
  is reported **unverifiable**, not forged — conflating those two was a false accusation of
  tampering for a routine operation. `verify_integrity_report()` returns the detail;
  `strict_keys=True` demands full coverage.
- **The log was CWD-relative** (`./receipts/log.db`), so signing from two directories
  produced two separate logs and the append-only chain forked per working directory. It is
  now anchored to an absolute path under `AETHERPROOF_HOME`.

---

## CLI

- **The model file is now optional.** Cloud users (ChatGPT, Claude, Gemini) cannot download
  weights, so requiring a model path made the tool unusable for most of its actual users.
  Without one the receipt is tiered `name_only` rather than implying the weights were checked.
- **`sign --input FILE`** binds the prompt as well as the answer. Previously
  `input_commitment` was always empty — the receipt proved the answer was unaltered but said
  nothing about the question.
- **`export --format hex`** is implemented. `cbor` was advertised in the help, printed
  "not yet implemented", and exited 0 — it has been withdrawn rather than left pretending.
- **`export`, `inspect` and `keygen` returned `None` on failure**, so errors exited 0 and
  `aetherproof inspect missing.json && deploy` deployed. All failure paths now exit 1.
- **The banner printed to stdout** and corrupted piped output —
  `export --format hex | consumer` piped the banner into the consumer and the hex did not
  decode. Chrome and human-readable errors now go to **stderr**; stdout carries data only.
- **The interactive wizard had drifted onto its own pre-hardening copy** of the issuance
  path, pinned to `receipt_version="1.1"` with no `signing_key_id`, its own import-frozen
  receipts directory, and no sequence retry. The path aimed at non-technical users was the
  least-hardened one in the project. It now shares `issue_receipt`.

---

## Tests

**568 passing, coverage 48% → 93%.**

| Suite | What it covers |
|---|---|
| unit + regression | every defect above, each failing against 0.2.x |
| `tests/stress/full_audit.py` | 31 adversarial checks — concurrency, tamper, crypto, input, session, key |
| `tests/stress/isolation_audit.py` | 18 probes — break one component, verify the others independently |
| `tests/stress/industrial_stress.py` | 7 multi-**process** probes — 12-process fleet, 20k sustained, hard-kill (`os._exit(9)`) recovery, 50k-turn session |
| `tests/test_independent_verification.py` | the documented offline procedure, run against a real CLI receipt in a process where importing `aetherproof` is **blocked** |

**Fault isolation: 10/10.** Delete the log and signing still works; corrupt it and offline
verification is unaffected; destroy the private key and old receipts still verify; corrupt
the public key and it fails closed; one bad receipt among five leaves the other four
independently provable.

The independent-verification suite exists so the README cannot drift from the format: it
extracts the documented procedure, runs it against v1.1/v1.2/v1.3 receipts, and fails if
the two disagree.

---

## Housekeeping

- Version was inconsistent — `pyproject.toml` said 0.2.3 while `__init__.py` said 0.2.2.
  Both are now 0.4.0, and the banner reads from `__version__`.
- New plain-language guide for non-developers: [`docs/GETTING-STARTED.md`](GETTING-STARTED.md).
- `AETHERPROOF_HOME` is honoured everywhere, resolved per call rather than frozen at import.

---

## What has not changed

The invariant:

```
Verify(receipt, public_key, log) = TRUE
```

using only those three inputs — offline, forever, no server, no vendor SDK, no hardware
driver. That is now **executed as a test** rather than asserted in prose.

And what a receipt still does **not** prove is unchanged and documented in
[`docs/CLAIMS.md`](CLAIMS.md): it does not prove the named model produced the output, that
the timestamp is truthful, that the signing key is held securely, or that the log's tail
was not truncated. Signatures are **Ed25519 only** — there is no post-quantum signing in
this release.
