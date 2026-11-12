//! Sample data for headless scenes only (never shown in a live window): every screen renders
//! without a backend so the Rune harness can snapshot it. All of it is labelled DEMO.

use crate::{App, Job, Page};
use serde_json::{Value, json};

const T: i64 = 1_794_391_200_000; // 2026-11-11 10:00:00 UTC

fn connected(s: &mut App) {
    s.status = Some(json!({"version": "0.5.2", "key_id": "3f9a1c0e7b2d4a55", "key_protection": "dpapi",
                           "audit_entries": 41, "audit_intact": true, "log_entries": 6, "log_intact": true,
                           "instructions": 4, "checkpoints": 2, "home": "C:\\Users\\you\\.aetherproof"}));
    let amounts = [4_850_000_i64, 12_500_000, 3_000_000, 7_500_000];
    s.instructions = (1..=4).map(|i| {
        json!({"instruction_id": format!("ins_7c1e0b9a44d2f6e10{i}a3"), "amount_minor": amounts[i - 1],
               "currency": "INR", "reference": format!("LN-2026-104{i}"), "approved_by": "credit-ops",
               "not_after_ms": T + 900_000})
    }).collect();
    s.runs = vec![json!({"run_id": "run_9d4be1c07a52f3e68b10", "created_at": "2026-11-11T10:20:41+00:00", "source": "razorpayx",
                         "instructions": 4, "payouts": 6, "counts": {"matched": 1, "conflict": 4, "missing": 0, "ambiguous": 0}})];
    s.updated_unix_s = 1_794_392_441;
}

fn ins(i: usize, amount: i64, ben: &str) -> Value {
    json!({"instruction_id": format!("ins_7c1e0b9a44d2f6e10{i}a3"), "amount_minor": amount, "currency": "INR",
           "beneficiary": ben, "purpose": "loan_disbursal", "reference": format!("LN-2026-104{i}"),
           "approval_ref": format!("SAN-770{i}"), "approved_by": "credit-ops", "policy": "disbursal-v3",
           "originator": "demo-lender", "not_before_ms": T, "not_after_ms": T + 900_000,
           "signing_key_id": "3f9a1c0e7b2d4a55", "digest": "a41f09c2e8d75b3016fe9a2cc4d1873e5b0f62a9d17c4e88b3f5a07c2d9e6b14",
           "signature_valid": true})
}

fn ev(id: &str, status: &str, amount: i64, ben: &str, dt: i64) -> Value {
    json!({"payout_id": id, "status": status, "amount_minor": amount, "currency": "INR", "beneficiary": ben,
           "time_ms": T + dt, "utr": "UTR0001", "record_hash": "5be0c1d9a2f47e83c6b1d09e4f2a7c58e3d1b6a9"})
}

fn report(s: &mut App) {
    s.run_id = Some("run_9d4be1c07a52f3e68b10".into());
    s.report = Some(json!({
        "demo": true,
        "counts": {"matched": 1, "conflict": 5, "missing": 0, "ambiguous": 0},
        "at_risk_minor": 38_400_000, "verified_minor": 4_850_000, "settlement_source": "bank_statement",
        "results": [
            {"verdict": "matched", "kind": "approval", "settlement": "confirmed", "action_id": "ins_7c1e0b9a44d2f6e101a3", "amount_minor": 4_850_000, "reasons": [],
             "instruction": ins(1, 4_850_000, "fa_borrower_01"), "events": [ev("pout_0001", "processing", 4_850_000, "fa_borrower_01", 60_000), ev("pout_0001", "processed", 4_850_000, "fa_borrower_01", 62_000)]},
            {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e102a3", "amount_minor": 12_500_000, "reasons": ["paid to a different beneficiary"],
             "instruction": ins(2, 12_500_000, "fa_borrower_02"), "events": [ev("pout_0002", "processed", 12_500_000, "fa_mule_77", 75_000)]},
            {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e103a3", "amount_minor": 3_000_000, "reasons": ["paid 35,000.00 INR, authorised 30,000.00 INR"],
             "instruction": ins(3, 3_000_000, "fa_borrower_03"), "events": [ev("pout_0003", "processed", 3_500_000, "fa_borrower_03", 81_000)]},
            {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e104a3", "amount_minor": 7_500_000, "reasons": ["authorised once, paid 2 times"],
             "instruction": ins(4, 7_500_000, "fa_borrower_04"), "events": [ev("pout_0004", "processed", 7_500_000, "fa_borrower_04", 90_000), ev("pout_0005", "processed", 7_500_000, "fa_borrower_04", 150_000)]},
            {"verdict": "conflict", "kind": "unapproved_event", "action_id": "", "amount_minor": 9_900_000, "reasons": ["99,000.00 INR paid out (pout_0006, processed) with no valid signed instruction"],
             "events": [ev("pout_0006", "processed", 9_900_000, "fa_mule_77", 200_000)]},
            {"verdict": "conflict", "kind": "approval", "settlement": "absent", "action_id": "ins_7c1e0b9a44d2f6e105a3", "amount_minor": 6_000_000,
             "reasons": ["provider reports the payout processed, but the bank statement shows no matching debit"],
             "instruction": ins(5, 6_000_000, "fa_borrower_05"), "events": [ev("pout_0007", "processed", 6_000_000, "fa_borrower_05", 240_000)]}]}));
}

type Scene = (&'static str, fn(&mut App));

pub const SCENES: &[Scene] = &[
    ("offline", |s| {
        s.offline = true;
        s.job = Job::Failed("Backend not reachable on 127.0.0.1:8787. Run: aetherproof serve".into());
    }),
    ("first-run", |s| connected(s)),
    ("overview", |s| { connected(s); report(s); }),
    ("processing", |s| { connected(s); report(s); s.page = Page::Payouts; s.job = Job::Processing("Verifying payouts"); }),
    ("instructions", |s| { connected(s); s.page = Page::Instructions; }),
    ("gate-allow", |s| {
        connected(s);
        s.page = Page::Gate;
        s.g_id.replace_text("ins_7c1e0b9a44d2f6e101a3");
        s.g_reference.replace_text("ins_7c1e0b9a44d2f6e101a3");
        s.g_amount.replace_text("48500.00");
        s.g_beneficiary.replace_text("fa_borrower_01");
        s.decision = Some(json!({"verdict": "allow", "instruction_id": "ins_7c1e0b9a44d2f6e101a3", "reasons": []}));
        s.job = Job::Completed("Gate decision: ALLOW".into());
    }),
    ("gate-reject", |s| {
        connected(s);
        s.page = Page::Gate;
        s.g_id.replace_text("ins_7c1e0b9a44d2f6e101a3");
        s.g_reference.replace_text("ins_7c1e0b9a44d2f6e101a3");
        s.g_amount.replace_text("98500.00");
        s.g_beneficiary.replace_text("fa_mule_77");
        s.decision = Some(json!({"verdict": "reject", "instruction_id": "ins_7c1e0b9a44d2f6e101a3", "reasons": [
            "amount 98,500.00 INR differs from authorised 48,500.00 INR", "beneficiary differs from the authorised one"]}));
    }),
    ("gate-review", |s| {
        connected(s);
        s.page = Page::Gate;
        s.g_id.replace_text("ins_7c1e0b9a44d2f6e101a3");
        s.g_amount.replace_text("48500.00");
        s.g_beneficiary.replace_text("fa_borrower_01");
        s.decision = Some(json!({"verdict": "review", "instruction_id": "ins_7c1e0b9a44d2f6e101a3", "reasons": [
            "payout reference not set: outcome cannot be matched to this instruction"]}));
    }),
    ("payouts", |s| { connected(s); report(s); s.page = Page::Payouts; s.p_path.replace_text("C:\\Users\\you\\.aetherproof\\demo_payouts.json"); }),
    ("investigation-empty", |s| { connected(s); s.page = Page::Investigation; }),
    ("investigation-double", |s| { connected(s); report(s); s.page = Page::Investigation; s.selected = Some(3); }),
    ("investigation-unapproved", |s| { connected(s); report(s); s.page = Page::Investigation; s.selected = Some(4); }),
    ("investigation-forged", |s| { connected(s); report(s); s.page = Page::Investigation; s.selected = Some(5); }),
    ("evidence", |s| {
        connected(s);
        s.page = Page::Evidence;
        s.checkpoints = vec![
            json!({"file": "checkpoint_000006_20261111T101500Z.json", "ok": true, "problems": []}),
            json!({"file": "checkpoint_000004_20261110T180000Z.json", "ok": false, "problems": ["truncated: log has 3 entries, checkpoint recorded 4"]}),
        ];
    }),
    ("integrations", |s| { connected(s); s.page = Page::Integrations; }),
    ("settings", |s| { connected(s); s.page = Page::Settings; }),
];
