//! Sample data for headless scenes: every screen renders without a backend, so the Rune
//! harness can snapshot and script it (`--scene payouts --snap payouts.png`).

use crate::{App, Page};
use serde_json::json;

fn connected(s: &mut App) {
    s.status = Some(json!({"version": "0.6.0", "key_id": "3f9a1c0e7b2d4a55", "log_entries": 6, "log_intact": true,
                           "instructions": 4, "checkpoints": 1}));
    let amounts = ["48500.00", "125000.00", "30000.00", "75000.00"];
    s.instructions = (1..=4).map(|i| {
        let amount = amounts[i - 1];
        json!({"instruction_id": format!("ins_7c1e0b9a44d2f6e10{i}a3"), "amount": amount,
               "currency": "INR", "reference": format!("LN-2026-104{i}"), "approved_by": "credit-ops"})
    }).collect();
}

fn report(s: &mut App) {
    s.report = Some(json!({"counts": {"matched": 1, "conflict": 4, "missing": 0, "ambiguous": 0}, "results": [
        {"verdict": "matched", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e101a3", "reasons": []},
        {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e102a3", "reasons": ["paid to a different beneficiary"]},
        {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e103a3", "reasons": ["paid 3500000, authorised 3000000"]},
        {"verdict": "conflict", "kind": "approval", "action_id": "ins_7c1e0b9a44d2f6e104a3", "reasons": ["authorised once, paid 2 times"]},
        {"verdict": "conflict", "kind": "unapproved_event", "action_id": "", "reasons": ["payout pout_0006 (processed, 9900000 INR) has no valid signed instruction"]}]}));
}

pub const SCENES: &[(&str, fn(&mut App))] = &[
    ("offline", |s| {
        s.offline = true;
        s.notice = Some((false, "Backend not reachable on 127.0.0.1:8787. Run: aetherproof serve".into()));
    }),
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
            "amount 9850000 differs from authorised 4850000", "beneficiary differs from the authorised one"]}));
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
