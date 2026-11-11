//! Sample data for headless scenes: every screen renders without a backend, so the Rune
//! harness can snapshot and script it (`--scene payouts --snap payouts.png`).

use crate::{App, Page};
use serde_json::json;

fn connected(s: &mut App) {
    s.status = Some(json!({"version": "0.6.0", "key_id": "3f9a1c0e7b2d4a55", "key_protection": "dpapi",
                           "audit_entries": 41, "audit_intact": true, "log_entries": 6, "log_intact": true,
                           "instructions": 4, "checkpoints": 2}));
    let amounts = [4_850_000_i64, 12_500_000, 3_000_000, 7_500_000];
    s.instructions = (1..=4).map(|i| {
        let amount = amounts[i - 1];
        json!({"instruction_id": format!("ins_7c1e0b9a44d2f6e10{i}a3"), "amount_minor": amount,
               "currency": "INR", "reference": format!("LN-2026-104{i}"), "approved_by": "credit-ops"})
    }).collect();
}

fn report(s: &mut App) {
    s.report = Some(json!({
        "counts": {"matched": 1, "conflict": 4, "missing": 0, "ambiguous": 0},
        "at_risk_minor": 32_400_000, "verified_minor": 4_850_000,
        "results": [
            {"verdict": "matched", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e101a3", "amount_minor": 4_850_000, "reasons": []},
            {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e102a3", "amount_minor": 12_500_000, "reasons": ["paid to a different beneficiary"]},
            {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e103a3", "amount_minor": 3_000_000, "reasons": ["paid 35,000.00 INR, authorised 30,000.00 INR"]},
            {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e104a3", "amount_minor": 7_500_000, "reasons": ["authorised once, paid 2 times"]},
            {"verdict": "conflict", "kind": "unapproved_event", "action_id": "", "amount_minor": 9_900_000, "reasons": ["99,000.00 INR paid out (pout_0006, processed) with no valid signed instruction"]}]}));
}

pub const SCENES: &[(&str, fn(&mut App))] = &[
    ("offline", |s| {
        s.offline = true;
        s.notice = Some((false, "Backend not reachable on 127.0.0.1:8787. Run: aetherproof serve".into()));
    }),
    ("first-run", |s| connected(s)),
    ("overview", |s| { connected(s); report(s); }),
    ("instructions", |s| { connected(s); s.page = Page::Instructions; }),
    ("gate-allow", |s| {
        connected(s);
        s.page = Page::Gate;
        s.g_id.replace_text("ins_7c1e0b9a44d2f6e101a3");
        s.g_amount.replace_text("48500.00");
        s.g_beneficiary.replace_text("fa_borrower_01");
        s.decision = Some(json!({"verdict": "allow", "instruction_id": "ins_7c1e0b9a44d2f6e101a3", "reasons": []}));
    }),
    ("gate-reject", |s| {
        connected(s);
        s.page = Page::Gate;
        s.g_id.replace_text("ins_7c1e0b9a44d2f6e101a3");
        s.g_amount.replace_text("98500.00");
        s.g_beneficiary.replace_text("fa_mule_77");
        s.decision = Some(json!({"verdict": "reject", "instruction_id": "ins_7c1e0b9a44d2f6e101a3", "reasons": [
            "amount 98,500.00 INR differs from authorised 48,500.00 INR", "beneficiary differs from the authorised one"]}));
    }),
    ("payouts", |s| { connected(s); report(s); s.page = Page::Payouts; s.p_path.replace_text("~/.aetherproof/demo_payouts.json"); }),
    ("evidence", |s| {
        connected(s);
        s.page = Page::Evidence;
        s.checkpoints = vec![
            json!({"file": "checkpoint_000006_20261111T101500Z.json", "ok": true, "problems": []}),
            json!({"file": "checkpoint_000004_20261110T180000Z.json", "ok": false, "problems": ["truncated: log has 3 entries, checkpoint recorded 4"]}),
        ];
    }),
];
