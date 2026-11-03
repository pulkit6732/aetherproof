[Back to the AetherProof README](../README.md)

# Action reconciliation and checkpoints

A receipt proves a record was not edited. It does not prove that the change an
agent made in another system is the change someone approved: the agent writes its
own log, so a manipulated agent's log agrees with itself. `reconcile` checks the
approval against the record kept by the system that was changed.

## Approve, act, reconcile

```
aetherproof approve --action-id chg-2041 \
    --actor arn:aws:sts::111122223333:assumed-role/agent/session \
    --operation s3:DeleteObject --resource arn:aws:s3:::invoices/2026/1042.pdf \
    --params params.json --approved-by finance-lead --ref CHG-2041 --window 15
```

The agent then assumes its role with `SourceIdentity=chg-2041`
(`aws sts assume-role ... --source-identity chg-2041`). CloudTrail records it as
`userIdentity.sessionContext.sourceIdentity` on every call in that session, which
is how each event is tied to its approval. Then:

```
aetherproof reconcile cloudtrail.json --receipts ~/.aetherproof/receipts \
    --agent arn:aws:sts::111122223333:assumed-role/agent/
```

| Verdict | Meaning |
|---|---|
| matched | one successful event, same operation, resource and every approved parameter, inside the window |
| conflict | the event differs from the approval, ran more than once, or the approval fails verification; also any state-changing event by `--agent`, or tagged with an unknown action id, that no approval covers |
| missing | the window closed with no successful event (a failed attempt is reported with its error code) |
| ambiguous | several untagged events fit, or the window is still open |

Exit code is 0 only when everything matched. `--quiet` prints JSON.

Rules worth knowing:
- Approvals are trusted only under `--pubkey` keys (default: this machine's key), never a `.pub` file next to a receipt.
- Extra parameters a service adds to the event are allowed; every approved parameter must match exactly.
- Events without a `sourceIdentity` can still match on operation + resource + time; the result says `basis: operation+resource+time` so a reviewer knows it is the weaker link. An event tagged with a *different* action id is never used as fallback evidence.
- Read-only events need no approval and are ignored.

CloudTrail input can be `{"Records": [...]}` as delivered to S3, a JSON list, or JSON lines.

## Checkpoints and independent time

The hash chain catches edits in the middle of the log but not deleting the
newest entries. A checkpoint signs the log size and head hash:

```
aetherproof checkpoint create --out checkpoint.json --tsa https://freetsa.org/tsr
aetherproof checkpoint verify checkpoint.json --tsa-root freetsa_cacert.pem
```

Keep the checkpoint somewhere the log's operator cannot change. `verify` reports
`truncated` or `rewritten` if receipts were removed or replaced. `--tsa` adds an
RFC 3161 token (needs `pip install aetherproof[timestamp]`): an independent
authority's signed statement that the checkpoint existed at that time. The token
is checked end to end (imprint, nonce, signed attributes, signing-certificate
binding, signature, timeStamping usage, chain to the root you pass); with no
`--tsa-root` the time is reported as unchecked, never accepted.

## What this does not prove

- Reconciliation is only as complete as the destination's log. CloudTrail data events (S3 object calls) must be enabled to appear at all.
- It detects a mismatch after the fact; it does not stop the action.
- A checkpoint is only as independent as wherever it is stored.
- Each receipt's own `timestamp_ms` is still the signer's clock; the TSA bounds it from above.
