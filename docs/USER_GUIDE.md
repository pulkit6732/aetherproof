[Back to the AetherProof README](../README.md)

# AetherProof user guide

For the payments-operations or risk lead who checks that disbursals went out exactly as
approved, and the engineer who installs it. Twenty minutes, start to finish.

## What AetherProof answers

For every payout: **was this exact payment approved, and did exactly that payment happen?**

| Step | Question | Where |
|---|---|---|
| 1. Sign | Credit ops approved ₹48,500 to borrower X for loan LN-1041. Record that as a signed instruction. | Instructions |
| 2. Gate | Before the payout call: does this request match a signed, unexpired, unused instruction? | Payment gate |
| 3. Verify | Afterwards: does the provider's record match the instruction, once, to the same beneficiary? | Payouts |
| 4. Settle | Does the **bank statement** show the money actually left? | Payouts (bank statement) |
| 5. Prove | Hand an auditor a sealed file they can check without trusting you. | Investigation, Evidence |

What it catches, each with a test:
- **No instruction behind a payout:** a stolen API key was used to send money.
- **Wrong amount:** the amount was changed after approval.
- **Wrong beneficiary:** the account was swapped to a mule.
- **Paid twice:** the same approval was paid out twice.
- **Instruction reused:** the same approval was replayed later.
- **Forged success:** the provider says "processed", but the bank never debited the money.
- **Unexplained debit:** the bank shows money leaving that no payout explains.

What it does **not** do today:
- It reads files you export. Live RazorpayX, Cashfree or bank APIs are not connected.
- It runs on one machine for one team; there is no multi-tenant hosting.
- The signing key is sealed with Windows DPAPI, not held in an HSM or cloud KMS.
- It has not had an external security audit.

## 1. Install and start

You need Windows 10/11, Python 3.11+ and, for the desktop app, Rust 1.99.1 (pinned in `app/rust-toolchain.toml`).

```powershell
cd aetherproof-v2\repo
python -m venv ..\.venv
..\.venv\Scripts\pip install -e ".[timestamp]"
..\.venv\Scripts\aetherproof serve            # local API on 127.0.0.1:8787; leave this running
```

In a second window:

```powershell
cd aetherproof-v2\repo\app
cargo run --release
```

The first `serve` does three things:
- creates your originator signing key in `%USERPROFILE%\.aetherproof\`
- seals the key's passphrase with Windows DPAPI, so only your Windows account can unseal it
- writes one access token per role to `api_tokens.json`

The app reads the admin token from there. If the left rail says **API not reachable**, `serve` is not running.

## 2. Try the demo (three minutes)

On **Overview**, press **Run the DEMO replay**. Everything it creates is synthetic and every screen shows a **DEMO DATA** stamp. It seeds:
- 5 signed disbursal instructions
- a RazorpayX-style payout export of 7 records
- a bank statement

Open **Payouts**. You should see **1 matched, 5 conflicts**:

| Line | Finding | Attack it represents |
|---|---|---|
| ₹48,500.00 | MATCHED, settlement confirmed | normal disbursal |
| ₹1,25,000.00 | paid to a different beneficiary | account swapped to a mule |
| ₹30,000.00 | paid 35,000.00, authorised 30,000.00 | amount altered after approval |
| ₹75,000.00 | authorised once, paid 2 times | duplicate payout |
| ₹99,000.00 | paid out with no valid signed instruction | stolen API credential (CERT-In 2026 advisories) |
| ₹60,000.00 | provider says processed, bank shows no debit | forged success status (the Razorpay 2022 pattern) |

Click any line to open **Investigation**. It shows:
- what the verdict means
- the signed instruction (who approved it, under which policy, its validity window, its key and digest)
- every provider record behind it in time order, with each record's hash
- the settlement state from the bank statement

The last line is the one to show a risk committee. Without the bank statement it reads **MATCHED**, because the provider's own record looks perfect.

## 3. Daily workflow

### 3.1 Sign each approved disbursal (Instructions)

Enter the following fields:
- amount (rupees and paise, e.g. `48500.00`)
- beneficiary: the provider's fund-account token, or IFSC plus account number
- loan reference, approval reference, approver, policy
- validity in minutes (default 15)

AetherProof stores the instruction and returns its **instruction id**. Your payout system must send that id as the provider reference (RazorpayX: `reference_id`, at most 40 characters). The id is what ties the payout back to its approval.

Amounts are stored as whole paise and never as decimals. Account numbers keep their leading zeros, and only a salted hash of the account is stored.

### 3.2 Gate each payout before it is sent (Payment gate)

Your executor, or you by hand, submits:
- the instruction id
- amount, currency and beneficiary
- the reference it will send

| Decision | Meaning | Instruction |
|---|---|---|
| **ALLOW** | everything matches, in window, first use | consumed: a second ALLOW is impossible |
| **REJECT** | a hard check failed (amount, beneficiary, signature, expired, already used) | not consumed |
| **REVIEW** | everything matches but no provider reference is set, so the outcome could not be matched later | not consumed; set the reference and retry |

The screen is a sandbox on this machine. In production the same check runs as `aetherproof instruction verify` (exit 0 = allow) or `POST /api/v1/verify`, called by your payout service.

### 3.3 Verify payouts and settlement (Payouts)

1. Export payouts from your provider for the period.
   - RazorpayX: the payouts JSON as the API returns it (`{"items": [...]}`).
   - Any other provider: the generic CSV below.
2. Export the bank statement for the same period, plus a couple of days. The settlement grace period is 2 days by default.
3. Paste both paths and press **Verify payouts**.

Each run is saved under a run id derived from its inputs. Running the same files again reopens the same run; it never creates a second, different answer.

### 3.4 Investigate and export evidence (Investigation)

Click a line, read the findings, and press **Export signed evidence package**. The package is written to `%USERPROFILE%\.aetherproof\evidence\<run>.evidence.json`. It contains:
- the whole run: every verdict, reason, instruction summary and record hash
- a signature over all of it

### 3.5 Give the evidence to an auditor

Send the package and your **public** key, `%USERPROFILE%\.aetherproof\signing_key.pub`. Never send `signing_key.pem`, which is the private key. The auditor runs:

```powershell
aetherproof evidence verify run_01bb...evidence.json --pubkey signing_key.pub
```

`INTACT` (exit 0) means the content has not changed since export and you signed it. If anyone edits a verdict, an amount or a count, it fails with exit 1. It also fails if they recompute the hash, because the signature no longer matches. The auditor should get your public key through a channel other than the package itself.

## 4. File formats

### Payouts, generic CSV

```csv
payout_id,reference,amount_minor,currency,status,time,beneficiary_token,utr
pout_0001,ins_7c1e0b9a44d2f6e101a3,4850000,INR,processed,2026-11-11T10:01:00Z,fa_borrower_01,UTR0001
```

- `amount_minor` is a whole number of paise. `48500.00` is refused, so that no rounding ever happens silently.
- Use `beneficiary_token`, or the `ifsc` plus `account_number` columns instead.
- `status` values:
  - success: processed, success, completed, settled
  - failure: failed, rejected, cancelled, reversed
  - in progress: queued, pending, processing, scheduled, initiated
- `time` is ISO 8601 or unix seconds or milliseconds.
- Repeated rows for one `payout_id` (webhook retries, status changes) are fine. The latest one counts.
- Every successful payout row must have a `time` and a `currency`. A row missing either cannot
  be checked against its approval, so it is a CONFLICT, never assumed correct.
- The largest accepted amount is 10^15 minor units (₹10 lakh crore). Negative payout amounts are refused.

### Bank statement, CSV or JSON

```csv
entry_id,utr,amount_minor,currency,direction,time,narration
stmt_0001,UTR0001,4850000,INR,debit,2026-11-11T10:01:30Z,IMPS/pout_0001
```

- `direction` is `debit` or `credit`. Only debits settle payouts.
- A debit is matched to a payout by UTR. If the UTR is blank, it falls back to the payout id appearing in the narration.
- Each debit settles one payout only.

## 5. Reading the results

| Verdict | Meaning | Action |
|---|---|---|
| **MATCHED** | paid once, exactly as signed (and, with a statement, the bank debit is there) | none |
| **CONFLICT** | a contradiction is established: amount, beneficiary, paid twice, no instruction, or no bank debit | stop and investigate; the money at risk is shown |
| **MISSING** | the approved payout failed, was reversed, or never happened before expiry | re-issue or close the loan record |
| **AMBIGUOUS** | evidence still arriving (payout processing, debit not yet posted inside grace) | re-run later; never treated as fraud |

The settlement column reads:
- **confirmed:** the bank debit was found
- **mismatch:** the bank debited a different amount
- **absent:** no debit after the grace period
- **pending:** no debit yet, still inside the grace period
- **returned:** a reversed payout's debit came back as a credit
- **not checked:** no statement was given

A payout the provider calls **reversed** must show its money coming back. If the statement has the debit but no return credit after the grace period, it is a CONFLICT.

## 6. Roles and access

The API listens on `127.0.0.1` only. Each role has its own token in `%USERPROFILE%\.aetherproof\api_tokens.json`.

| Role | Can |
|---|---|
| admin | everything, including the DEMO seed |
| signer | sign instructions, write checkpoints |
| executor | gate decisions only |
| auditor | read instructions and runs, verify payouts, export and verify evidence, verify checkpoints |

Ten wrong tokens in a minute lock that client out for a minute. Every call is written to a hash-chained `audit.jsonl`; **Settings & security** shows whether the chain is intact.

## 7. When something goes wrong

| Message | Cause | Fix |
|---|---|---|
| `API not reachable` | `aetherproof serve` not running | start it |
| `invalid_request: ... amount must be an integer` | a file has `48500.00` where paise are expected | export amounts in paise |
| `unreadable_input: cannot read ...` | wrong path or file locked | check the path; close the file in Excel |
| `unknown_source` | source other than `razorpayx` or `generic` | use one of the two |
| `forbidden` | this role may not call this | use the right role's token |
| `locked_out` | too many wrong tokens | wait 60 s; check which token the client sends |
| every line AMBIGUOUS "settlement not yet visible" | statement covers too short a period | export a later statement, or set `settlement_grace_minutes` for IMPS-only flows |

## 8. Command line equivalents

```powershell
aetherproof instruction sign --amount 48500.00 --currency INR --beneficiary-token fa_123 `
    --reference LN-1041 --approval-ref SAN-7701 --approved-by credit-ops
aetherproof instruction verify <instruction.json> --amount 48500.00 --currency INR `
    --beneficiary-token fa_123 --reference <instruction_id>              # exit 0 = allow
aetherproof payouts reconcile payouts.json --instructions $HOME\.aetherproof\instructions `
    --source razorpayx --statement statement.csv                         # exit 0 = all matched
aetherproof evidence verify <package.json> --pubkey signing_key.pub       # exit 0 = intact
```

The API is specified in [API_CONTRACT.md](API_CONTRACT.md). The instruction format is in [SIGNED-INSTRUCTION-SPEC.md](SIGNED-INSTRUCTION-SPEC.md).
