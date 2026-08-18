# Deep analysis — AetherProof 0.5.0 development line

**AetherProof — Pulkit Kr Srivastava**
**Compiled:** 2026-08-16. Every figure was produced by executing the code on one
machine and is re-runnable from this repository.

This is an assessment, not a summary. Where the project is weak, that is stated
in the same voice as where it is strong.

---

## 1. What exists

| | Rust — `rust/` | Python — `aetherproof/` |
|---|---|---|
| Production code | 2,353 LOC | 3,782 LOC |
| Tests | 59 | 642 |
| Test code | in-file | 7,251 LOC (1.9× the package) |
| Coverage | not instrumented | 93% |
| Receipt | 128 B fixed binary | 646 B JSON |
| Post-quantum | **ML-DSA-65 (FIPS 204)** | none |
| Merkle session proofs | yes | yes |
| Secret zeroization | **yes** | no — Python `bytes` cannot be wiped |
| Constant-time compare | **yes** (`subtle`) | no |
| `unsafe` in production | **zero, compiler-enforced** | n/a |
| Distribution | source + CI wheels (unrun) | PyPI 0.4.0 |

Seven commits this session, all pushed.

## 2. Measured performance

Medians of seven isolated runs, 50,000 leaves:

| Operation | Python | Rust | Ratio |
|---|---|---|---|
| Merkle build | 102.71 ms | **28.16 ms** | 3.6× |
| Inclusion verify | 17.17 µs | **3.93 µs** | 4.4× |
| Receipt sign | 45.38 µs | **18.84 µs** | 2.4× |
| Receipt verify | 101.69 µs | **22.77 µs** | 4.5× |
| Receipt size | 646 B | **128 B** | 5.05× |

Through the PyO3 binding the gains are smaller — 2.9–4.3× on build — because
marshalling a Python list of hex strings into `Vec<String>` is real work and is
counted.

Post-quantum costs, measured:

| | Ed25519 | ML-DSA-65 | Factor |
|---|---|---|---|
| Sign | 18.84 µs | 787.83 µs | 42× |
| Verify | 22.77 µs | 177.59 µs | 7.8× |
| Signature | 64 B | **3,309 B** | 52× |

## 3. Security posture

### What was tested

| Probe | Scope | Result |
|---|---|---|
| Panic probes | 26 attacker-controlled inputs | 0 panics |
| Fail-open probes | 7 paths that must return false | 0 fail-open |
| Fuzz campaign | 200,000 parser + 150,000 verifier iterations | 0 panics, 0 forgeries |
| Zeroization | process-memory scan after `destroy()` and after `Drop` | key absent both times |
| Timing analysis | 400 rounds × 200,000 iterations, address held fixed | see below |
| Bit-flip | every byte of a 128-byte receipt, sampled across a 3,309-byte PQ signature | all rejected |
| Key validation | 7 malformed public-key lengths, 7 malformed signature lengths | all rejected at construction |

### Three defects found by that testing, all in code written this session

**1. Zeroization did not zeroize.** `self.seed.take()` moves the array out of the
`Option` and wipes the moved copy, leaving the original storage intact. The key
survived a `destroy()` that reported success. Caught only because the test reads
through a raw pointer to the original address rather than trusting that "dropped"
means "erased".

**2. `ct_eq` was not constant-time.** The loop never short-circuits in the source.
LLVM introduced one anyway. At 400 rounds × 200,000 iterations with the buffer
address held fixed, a difference in byte 0 ran 3.55% faster than one in byte 63
against a 0.11% noise floor — the direction a short-circuit produces. Delegating to
`subtle` moved the skew to 0.40% and the direction to indistinguishable, at a cost
of ~4 ns → ~435 ns per call.

Finding this needed two attempts. The first measurement compared two different
stack buffers and showed a 6% skew in the *wrong* direction; that was cache-line
alignment, not a leak. Controlling the address was what made the real signal visible.

**3. The Rust Merkle port was 12.8× slower than Python.** `format!("{b:02x}")` per
byte allocated a `String` for each of 32 digest bytes, and every tree level was
cloned twice. A Rust port that loses to Python is not worth shipping, and only the
benchmark caught it.

### A correction to this project's own published numbers

The Merkle build advantage was documented as **9.2×**. It is **3.6×**. The original
figure came from a run where Python's build sat inside a loop that also generated
proofs for three tree sizes; memory pressure inflated it to 374 ms against an
isolated median of 102.71 ms.

Nothing external forced that correction. It surfaced because the number was
re-measured rather than re-quoted.

### Zero unsafe, and what it cost

`hex()` used `String::from_utf8_unchecked`. The call is sound — every byte comes
from a 16-entry ASCII table — but it was the only `unsafe` in production code.
Replacing it with a checked conversion costs **15.7 ns per call, 27.5% on that
function and roughly 4% on tree construction**, and buys
`#![cfg_attr(not(test), forbid(unsafe_code))]`: the compiler now refuses to build
production code containing `unsafe`. For a library whose entire value is
trustworthiness, that trade is worth making, and the cost is stated rather than
hidden.

### Attack surface

45 crates in the Rust dependency graph, of which the security-relevant direct
dependencies are `ed25519-dalek`, `fips204`, `sha2`, `zeroize`, and `subtle` — all
widely used, none written here. Python adds `cryptography`, plus `rich` and
`questionary` for the CLI, which the verifier path does not need.

**`cargo audit` could not be run** — it failed to compile in this environment.
Known-vulnerability status of the dependency graph is therefore **unverified**, and
CI should run it.

## 4. Honest position against the literature

From `signet/RESEARCH.md`, where every competitor was read in full:

| System | Where it is ahead | Where AetherProof is ahead |
|---|---|---|
| **Sello** (arXiv:2606.04193) | receiver-attested trust model; witness-cosigned log | shipped, tested, no blockchain required |
| **IMMACULATE** (arXiv:2602.22700) | detects model substitution; binds a prior model commitment | offline verification, no infrastructure |
| **VeriLLM** (arXiv:2509.24257) | on-chain model parameter hash; commit-then-sample with proofs | no GPU cluster, no honest-majority assumption |
| **TOPLOC** | 258-byte activation commitments | **unread — could invalidate the compact-commitment framing** |
| **Ambient** | <0.1% overhead proof-of-logits | **unread** |
| **AuditWeave** | closest architectural sibling | — |

**The engineering is now genuinely strong. The novelty position is not settled**,
because two of the nearest neighbours — TOPLOC and Ambient — remain unread. That is
Tier 1 item 4 and 5 in `RESEARCH.md` §6b, and it has not moved.

## 5. What is not verified

Listed plainly, because an unstated gap is a claim.

1. **Linux and macOS wheels have never been built.** This machine has only
   `x86_64-pc-windows-gnu` and `x86_64-unknown-none` installed. `wheels.yml` is
   written and its YAML parses; **no CI run has executed it**. The cross-platform
   claim is a configuration, not a result.
2. **`cargo audit` did not run.** Dependency vulnerability status is unknown.
3. **No external security review.** Every adversarial test here was written by the
   same process that wrote the code being tested. That finds implementation
   mistakes — it found three — and it does not find design blind spots.
4. **`inclusion_proof` is O(n), not O(log n)**, in both implementations: it rebuilds
   the whole tree per call. 28 ms per proof at 50,000 leaves in Rust, 300 ms+ in
   Python. Verification is correctly O(log n). Caching levels for repeated proofs
   against one sealed session is the fix and is unbuilt.
5. **The high-level Python API still runs pure Python.** `Signer`, `Verifier`,
   `Receipt`, and `Session` are not routed through the extension. The primitives and
   the security layer are bound and verified; the object layer above them is not.
6. **Completeness remains unsolved**, and is unsolvable locally. Somebody who logs
   9,000 of 10,000 outputs passes every check in this repository. That requires an
   external witness, which is SIGNET, which has 0 lines of code.
7. **Phase 0 customer validation has never been run.** Every market framing that
   died, died on a fact one conversation would have surfaced.

## 6. Assessment

**What is genuinely good.** The adversarial discipline is the real asset — not the
cryptography, which is standard by design. Three defects were found and fixed
because the tests were built to fail rather than to pass, and one published number
was corrected because it was re-measured rather than re-quoted. A repository whose
own test suite blocks a README from overclaiming ML-DSA, and which I could not
satisfy without making the guard *stricter*, is unusual.

**What is oversold if anyone quotes it carelessly.** Nothing currently in the docs,
as of this commit — but the 9.2× figure was live for several hours, and the
152-byte hybrid claim was live much longer. Both were wrong in the flattering
direction. That is the failure mode this project has to keep watching for.

**The binding constraint is not engineering.** Five roadmap steps closed in one
session with real tests behind each. Meanwhile the two papers that could invalidate
the novelty claim are still unread, and no customer conversation has ever happened.
Effort is going into the part that was already strong.

**Highest-value next actions, in order:**

1. **Read TOPLOC and Ambient.** Either could collapse the compact-commitment
   framing. Nothing else in the strategy is stable until they are read.
2. **Run CI once.** The wheel matrix is currently an assertion.
3. **Add `cargo audit` to CI.** It is the one security check that was attempted and
   failed.
4. Cache Merkle levels — turns O(n) proof generation into O(log n).
5. Route the high-level Python API through the extension.

Steps 2 through 5 are a day of work. Step 1 is an afternoon and is the only one
that can change what the project *is*.
