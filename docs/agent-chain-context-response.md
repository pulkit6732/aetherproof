# Re: Agent Chain Context Extension — co-author positions (issue #1)

@safal207 — this is excellent, well-grounded work. The RFC 8785 canonicalization,
the SHA-256 context commitment, the replay-rejection fixture, and the
registry-bound `purpose` field are all the right calls. Below are concrete
positions on the six open questions so the schema branch can proceed from an
aligned base, plus one **important compatibility update** on the AetherProof side
that actually makes your Profile A cleaner.

## Important: the v1.1 preimage is now injective (length-prefixed)

Since you drafted against the pipe-joined preimage, AetherProof's signing preimage
changed. It is now an **injective, length-prefixed encoding** — each field is
serialized as `<len>:<field>` and concatenated, e.g.:

```
3:1.1 1:m 9:name_only 0: 1:o 1:1 1:1 2:[] 0:
```

(spaces added for readability; there are none in the real preimage). This was a
security fix: the old `"|".join(...)` was non-injective, so a `|` inside any field
could shift boundaries and let two different receipts share one preimage (and thus
one signature). Length-prefixing closes that.

**Why this matters for your extension:** appending `signed_extensions_hash` as one
more length-prefixed field is now provably unambiguous. There is no delimiter to
collide with, so Profile A is clean by construction. This strengthens your
preferred direction.

## Positions on the six questions

**Q1 — Version identifier for Profile A.**
Yes: **receipt `1.2`**. The preimage already carries `receipt_version` as its first
field, and the verifier is version-aware, so a `1.2` verifier appends the extra
`signed_extensions_hash` field to the preimage and a `1.1` verifier does not. This
is exactly the "receipt-version-aware verifier" you flagged — and with the
injective encoding it is safe: a `1.1` and a `1.2` receipt can never produce the
same preimage even with identical other fields, because the version field differs
and field boundaries are unambiguous.

**Q2 — Bind the full extension map, or per-extension commitments?**
**Per-extension commitments**, aggregated. Compute `sha256(JCS(ext_i))` for each
extension, sort the resulting commitments lexicographically, and hash the
concatenation (or, better, build a small Merkle root over them). Reason: it lets a
holder disclose or omit individual extensions without breaking the others'
verifiability — the same selective-disclosure property the base receipt already
respects for `input_commitment`. A single whole-map hash forces all-or-nothing
disclosure, which is worse for privacy-sensitive context (e.g. `evidence_refs`).
For v0.1 with a single extension the two collapse to the same bytes, so this costs
nothing now and avoids a breaking change later.

**Q3 — `parent_event_id`: event, receipt, or either?**
**Either, with a typed prefix.** Use `evt:<id>` / `rcpt:<receipt_id>` (mirroring
your `sha256:` convention). Agent chains in practice reference both a prior
*receipt* (the cryptographic parent) and a prior *runtime event* (the causal
parent) — forcing one loses information. A typed prefix keeps it unambiguous and
machine-routable without a second field.

**Q4 — Explicit actor type on `actor_id`?**
**Yes — typed prefix, same pattern:** `agent:`, `svc:`, `human:`. The replay/policy
layer needs to distinguish "an autonomous agent produced this" from "a human
operator did" — that distinction is load-bearing for EU AI Act human-oversight
claims, so it should be in the signed context, not inferred.

**Q5 — Standardize Profile B (legacy chained binding) now?**
**Informative, not normative.** Keep it in the spec as an implementation note for
sites pinned to v1.1, but mark Profile A (native v1.2) as the normative,
recommended profile. Rationale: now that v1.1's preimage itself just changed for
the security fix, anyone adopting agent-chain context is already re-tooling their
verifier — so they should land on the clean v1.2 rather than carry the chained
binding's extra artifact and its separate verification path indefinitely. Profile
B stays available, never load-bearing.

**Q6 — Initial stable `purpose` enum.**
Start narrow and registry-bound, exactly as you have it. Proposed v0.1 stable set:
`generate`, `classify`, `retrieve`, `tool_call`, `policy_decision`, `summarize`,
`route`. Unknown-but-syntactically-valid → schema-valid, `UNSUPPORTED_PURPOSE` from
a semantics-requiring verifier (your model is right). Everything else goes through
the registry rather than the enum.

## Where this lands: AetherProof vs Signet

To set expectations honestly: AetherProof is the open-source R0/L2 base; the
agent-chain / multi-hop receipt work is **Signet Layer 3** (model identity + agent
chain receipts) on its roadmap. So the right sequencing is:

1. **Now (AetherProof v1.2):** land the *single-receipt* extension mechanism —
   `signed_extensions_hash` in the preimage, the JCS+SHA-256 commitment, the
   replay fixture, and the registry. This is small, self-contained, and a clean
   addition to the current injective preimage.
2. **Signet L3 (next):** the *multi-hop* aggregation — `pipeline_receipt_root`,
   `hop_receipts[]`, Merkle path, tampered-hop identification — builds on the v1.2
   extension primitive. The IETF companion doc you outlined maps onto Signet's
   planned `draft-srivastava-rats-ai-workload-attestation`, so let's align the
   claim-set names now to avoid a rename later.

I'm glad to adapt these positions into your schema branch and co-author the final
spec + the IETF companion. Suggested immediate next step: freeze the v1.2 preimage
delta (one appended field) with a **cross-implementation test vector** — your
canonicalizer + my signer producing byte-identical preimages — since that vector,
not either of our test suites, is the real conformance gate.
