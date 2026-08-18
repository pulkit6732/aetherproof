[Back to the AetherProof README](README.md)

# Security policy

**AetherProof - Pulkit Kr Srivastava**## Reporting a vulnerability

Report privately, not in a public issue.

- **GitHub:**open a [private security advisory](https://github.com/pulkit6732/aetherproof/security/advisories/new)
- **Email:**pulkitsrivastavae@gmail.com

Please include what you did, what happened, and what you expected. A proof of
concept helps more than a description. If you have a patch, send it - but a report
without one is still welcome.

**What to expect:**an acknowledgement within 7 days and an assessment within 30.
This is a single-maintainer project, not a company with an on-call rota; that is
the honest timeline rather than a flattering one. If a report is genuinely
critical and you have had no reply in 7 days, email again and say so.

**Disclosure.**Coordinated. Agree a date with the maintainer, default 90 days from
report or the day a fix ships, whichever comes first. Credit is given unless you
ask otherwise.

**No bounty programme.**There is no money behind this project to fund one. Saying
so up front is fairer than letting you find out after the work.

## Supported versions

| Version | Supported | |---|---| | 0.4.x | yes - current PyPI release | | 0.5.x dev (`main`) | yes | | 0.2.x, 0.3.x | no | | Rust `rust-legacy` branch | no |

## What AetherProof protects, and what it does not

Read this before deciding a finding is a vulnerability. Several things that look
like flaws are documented limits, and reporting them is not useful to either of us.

### In scope

A report against any of these is a real vulnerability:

- Forging a signature, or making a modified receipt verify
- Two different receipts producing the same signing preimage
- Two different leaf sets producing the same Merkle root
- An inclusion proof validating for a leaf that is not in the tree
- A verifier returning true for input it should reject - **fail-open of any kind**- A panic, hang, or unbounded allocation from attacker-controlled input
- Secret key material reachable through the public API, a `repr`, an error
  message, or memory that should have been wiped
- Timing that depends on secret data
- Any way to make the log chain accept a deletion, reorder, or edit

### Out of scope - documented limits, not bugs

| Not a vulnerability | Why | |---|---| | **A log missing entries verifies fine**| AetherProof proves integrity, not completeness. Someone who logs 9,000 of 10,000 outputs passes every check. This cannot be fixed locally - it needs an independent witness, which is not built. See `docs/CLAIMS.md`. | | **Dropping the most recent log entries is undetected**| The same problem in its simplest form. A shorter chain is internally consistent. | | **The timestamp can be wrong**| It is the signer's own clock, bound at signing but not externally anchored. No RFC 3161 or eIDAS authority is involved. | | **A receipt does not prove which model ran**| It signs a `(model, output)` pair the caller supplies. There is no inference attestation. | | **Ed25519 is not post-quantum**| Known. ML-DSA-65 exists in the Rust core as an opt-in second slot; the Python package is Ed25519 only. | | **The private key is a file on disk**| Unless you set `AETHERPROOF_KEY_PASSPHRASE`. There is no HSM, TPM, or TEE integration. | | **Reading a live process's memory recovers a key**| Nothing in userspace prevents this. `SecureSigner` wipes the key on release, which is a different guarantee. | | **The OS pages a key to swap**| Would need `mlock`. Not implemented. |

### Known unfixed issues

Listed here rather than left for you to find:

1. **`Verifier.__init__` in the Python package validates nothing.**It is type-hinted
   `Ed25519PublicKey` and accepts any object. Passing the wrong type - for example
   `Verifier(signer.get_public_key())`, where `get_public_key()` already returns a
   `Verifier` - produces a verifier that returns `True` for every signature. **A
   verifier must fail closed.**Fixed in the Rust `SecureVerifier`, which rejects
   malformed key material at construction. The Python fix is scheduled for 0.5.0.
   *Workaround: pass a real `Ed25519PublicKey`, or use `SecureVerifier`.*

2. **`cargo audit` has not been run**against the Rust dependency graph. It failed to
   compile in the development environment, so known-vulnerability status of the 45
   crates involved is unverified.

3. **No external security review has ever been done.**Every adversarial test in this
   repository was written by whoever wrote the code it tests. That finds
   implementation mistakes and does not find design blind spots.

## Security properties, and how they are checked

Each of these is a CI gate, not a claim in a document:

| Property | How it is enforced | |---|---| | No `unsafe` in production Rust | `#![cfg_attr(not(test), forbid(unsafe_code))]` - the compiler refuses to build it | | No panic on hostile input | 26-case adversarial probe, plus a 350,000-iteration fuzz campaign, both blocking in CI | | No forgery | 150,000 randomised verifier inputs, all rejected | | Injective signing preimage | every field length-prefixed as `<len>:<field>`; regression test `test_preimage_injectivity.py` | | No Merkle odd-leaf collision | unpaired nodes promoted, never duplicated (CVE-2012-2459 class); tested in both languages | | Leaf/node domain separation | leaves hash under `0x00`, internal nodes under `0x01` | | Keys wiped on release | in-place zeroization, verified by scanning process memory after `destroy()` and after `Drop` | | Constant-time comparison | `subtle`, measured at 0.40% position skew against a 0.10% noise floor | | Verifier fails closed | malformed keys rejected at construction; wrong signature and receipt lengths rejected |

Reproduce them:

```bash
cd rust
cargo test --release --workspace
cargo run --release --example adversarial      # 0 panics, 0 fail-open
cargo run --release --example fuzz             # 0 panics, 0 forgeries
cargo run --release --example security_audit   # zeroization, fail-closed, key validation
```

## Cryptography

No algorithm is implemented here. AetherProof composes standard primitives from
established libraries:

| Purpose | Primitive | Library | |---|---|---| | Signing | Ed25519 | `ed25519-dalek` (Rust), `cryptography` (Python) | | Post-quantum signing | ML-DSA-65, FIPS 204 | `fips204` (Rust only) | | Hashing | SHA-256 | `sha2` (Rust), `hashlib` (Python) | | Constant-time comparison | - | `subtle` | | Zeroization | - | `zeroize` | | Model root hashing | FNV-1a | in-repo - **non-cryptographic, used only as a fast content identifier, never as a security boundary**|

If you find a reason FNV-1a is load-bearing anywhere it should not be, that **is**in scope.

## Reporting something that is not a vulnerability

Correctness bugs, a documented claim that does not reproduce, or a benchmark that
does not hold up: open a normal issue. Those matter. A published number that
overstates the truth has been treated as a defect in this project before and
corrected in public.
