[Back to the AetherProof README](../README.md)

# AetherProof API contract v1

Source of truth for names: `aetherproof/contract.py`. The API, CLI and desktop app use those
constants; a change of meaning is a new contract version.

## Transport and auth

- `aetherproof serve` listens on `127.0.0.1:8787` only. `Host` must be `127.0.0.1:<port>` or `localhost:<port>`.
- `Authorization: Bearer <token>`. Tokens per role in `~/.aetherproof/api_tokens.json` (0600); `api_token` holds the admin token.
- Bodies: JSON objects, at most 1 MiB. Responses: JSON, `Cache-Control: no-store`.
- 10 bad tokens from one client in 60 s: `locked_out` for 60 s. 600 requests per role per 60 s: `rate_limited`.
- Every call is written to `audit.jsonl` (hash-chained; `verify_audit`).

## Routes (`/api/v1`)

| Method | Path | Roles | Purpose |
|---|---|---|---|
| GET | `/status` | admin, signer, executor, auditor | version, key id, key protection, log and audit integrity, counts |
| GET | `/instructions` | admin, signer, auditor | latest 200 instructions |
| POST | `/instructions` | admin, signer | sign one instruction |
| POST | `/verify` | admin, executor | gate decision for one payout request |
| POST | `/payouts/reconcile` | admin, auditor | verify provider records; saves a run |
| GET | `/runs` | admin, auditor | latest 100 runs (summary) |
| GET | `/runs/{run_id}` | admin, auditor | one saved run, full report |
| POST | `/checkpoints` | admin, signer | sign the log head (optional `tsa_url`) |
| GET | `/checkpoints/verify` | admin, auditor | verify every stored checkpoint |
| POST | `/demo` | admin | seed synthetic DEMO data (labelled) |

Unversioned `/api/...` paths call the same handlers for 0.5.x clients and return the legacy error shape `{"error": "<message>"}`.

## Errors

```json
{"error": {"code": "invalid_amount", "message": "amount must be positive with at most 2 decimals"}, "contract_version": "1"}
```

Codes and HTTP status: `invalid_request` 400, `missing_field` 400, `invalid_amount` 400, `invalid_currency` 400,
`invalid_beneficiary` 400, `invalid_window` 400, `unknown_source` 400, `unreadable_input` 400, `unauthenticated` 401,
`forbidden` 403, `bad_host` 403, `not_found` 404, `unknown_instruction` 404, `unknown_run` 404, `too_large` 413,
`rate_limited` 429, `locked_out` 429, `internal` 500. Branch on `code`, never on `message`.

## Requests

`POST /instructions`
```json
{"amount": "48500.00", "currency": "INR", "beneficiary_token": "fa_123",
 "reference": "LN-2026-1041", "approval_ref": "SAN-7701", "approved_by": "credit-ops",
 "purpose": "loan_disbursal", "policy": "disbursal-v3", "valid_minutes": 15}
```
Amount: decimal string, at most 2 places, converted to integer minor units (never a float in comparisons).
Beneficiary: `beneficiary_token`, or both `ifsc` and `account_number` (digits kept exactly; leading zeros significant).

`POST /verify`
```json
{"instruction_id": "ins_...", "amount": "48500.00", "currency": "INR",
 "beneficiary_token": "fa_123", "reference": "ins_..."}
```
→ `{"decision": {"verdict": "allow|reject|review", "instruction_id": "...", "reasons": [...]}}`

`POST /payouts/reconcile`: `{"source": "razorpayx|generic", "payouts": [...]}` or `{"source": ..., "path": "<file>"}`
→ `{"run_id": "run_...", "replayed": false, "payouts": 6, "report": {"counts": {...}, "results": [...], "at_risk_minor": 0, "verified_minor": 0}}`

## Verdicts and decisions

| Name | Meaning |
|---|---|
| matched | required evidence agrees with the signed authorisation |
| conflict | a defined contradiction or hard policy violation is established |
| missing | an expected outcome is absent after its deadline, or failed/reversed |
| ambiguous | evidence incomplete or not yet decidable; never treated as fraud |
| allow | gate: authorised, unchanged, in window, first use; the instruction is consumed |
| reject | gate: a hard check failed; not consumed |
| review | gate: every hard check passed but the payout carries no reference to tie it back; not consumed |

## Idempotency and runs

A reconcile run's id is a SHA-256 over the sorted instruction digests, the sorted raw payout record
hashes and the source. The same inputs return the stored run with `replayed: true`; a run file is
written atomically. A gate ALLOW is single-use by the replay store's primary key; a repeated request
gets `reject` with reason `instruction already used (replay)`.

## Not in v1

Live provider connectors, bank-statement settlement evidence, multi-tenant isolation, KMS/HSM keys,
evidence-package export. These are planned and will be added as new routes, not by changing these.
