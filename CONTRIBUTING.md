# Contributing to AetherProof

AetherProof is the open-source R0/L2 receipt engine — Ed25519 + SHA-256, offline
verifiable, append-only hash-chained log. It is the prototype base for Signet.
Contributions that strengthen the core invariant are welcome:

> **Verify(receipt, public_key, log) = TRUE** — using only those three inputs,
> forever, with zero dependency on any server, vendor SDK, or hardware driver.

If a change would break that invariant, it does not merge.

## Ground rules

1. **Tests are the gate, not assertions.** Every behavioral change ships with a
   test. Security-relevant changes go in `tests/security/` and must encode the
   actual attack (see the existing preimage-injectivity / extension tests).
2. **The signing preimage is sacred.** `Receipt.canonical_message()` /
   `signing_bytes()` is the single source of truth for what gets signed. Any
   change to it bumps `receipt_version` and adds a regression test proving old
   and new receipts can never collide. The encoding is **injective**
   (length-prefixed) — keep it that way.
3. **No new runtime dependencies** without discussion. The verifier must stay
   runnable with only `cryptography`.
4. **Honesty over marketing.** Don't claim a property the code doesn't have
   (byte counts, hardware roots, compliance). `docs/CLAIMS.md` is the
   proves / does-not-prove boundary.

## Setup

```bash
git clone https://github.com/pulkit6732/aetherproof
cd aetherproof
pip install -e ".[dev]"
python -m pytest -q          # full suite must pass
```

## Extension / spec proposals (receipt v1.2+)

AetherProof supports **namespaced signed extensions** — a receipt can commit to
runtime context (agent-chain causal binding, etc.) inside the signature without
breaking v1.1 (see the README "Agent-chain context" section and issue #1).

If you are proposing a new extension namespace or a spec change:

- **Schema** → put JSON Schema files under `schemas/<namespace>/`.
- **Spec text** → put the human-readable spec under `docs/interop/`.
- **Fixtures** → put replay / conformance fixtures under `fixtures/`.
- **Branch** → work on `spec/<short-name>` (e.g. `spec/agent-chain-context`)
  and open a PR against `main`. Reference the tracking issue.
- **Cross-implementation test vector is the real gate** — a vector where one
  implementation's canonicalizer + another's signer produce byte-identical
  preimages. Include it; it matters more than either side's unit tests.

Open extensions are coordinated in GitHub issues before code — file or comment
on an issue first so the namespace and preimage delta are agreed.

## Pull requests

- One logical change per PR; keep the diff reviewable.
- Run `python -m pytest -q` and include the result in the PR description.
- No `Co-Authored-By` trailers in commits.

## License

AetherProof is **Apache 2.0**. By contributing you agree your
contributions are licensed under the same terms.
