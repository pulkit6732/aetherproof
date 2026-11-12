//! The eight screens. Every control either calls the API or is disabled and labelled planned.

use crate::api::Action;
use crate::look::{self, body, code, display, eyebrow, figures, inr, label, look, money, rule, utc};
use crate::{App, Page, field, key_label, planned, primary, secondary, sheet, stamp_for};
use rune::{Align, Color, El, TextStyle, col, el, row, text};
use serde_json::{Value, json};

fn small() -> TextStyle {
    TextStyle::new(12.0, 450.0)
}

fn reasons(r: &Value) -> String {
    r["reasons"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; "))
        .filter(|w| !w.is_empty()).unwrap_or_else(|| "Paid exactly as authorised".to_owned())
}

/// A long hash cut for display; the full value is in the run file and the API response.
fn short(h: &str, keep: usize) -> String {
    if h.len() > keep { format!("{}…", &h[..keep]) } else { h.to_owned() }
}

fn n(v: &Value) -> i64 {
    v.as_i64().unwrap_or(0)
}

// ------------------------------------------------------------------ ledger

pub fn ledger_head(cols: [&str; 4]) -> El {
    let l = look();
    col().child(row().h(34.0).px(18.0).gap(16.0).center_y()
            .child(text(cols[0]).font(label()).color(l.faint).w(92.0))
            .child(text(cols[1]).font(label()).color(l.faint).w(214.0))
            .child(text(cols[2]).font(label()).color(l.faint).w(130.0).align(Align::End))
            .child(text(cols[3]).font(label()).color(l.faint).grow(1.0)))
        .child(rule())
}

pub fn ledger_line(key: String, verdict: &str, id: &str, amount: Option<i64>, why: &str) -> El {
    let l = look();
    col().key(key)
        .child(row().h(42.0).px(18.0).gap(16.0).center_y().hover(l.paper.alpha(0.7))
            .child(el().w(92.0).child(stamp_for(verdict)))
            .child(text(id.to_owned()).font(code()).color(l.ink).w(214.0).truncate())
            .child(el().w(130.0).child(match amount { Some(a) => money(a, 14.0, l.ink).w_full(), None => text("") }))
            .child(text(why.to_owned()).font(body()).color(l.ink2).grow(1.0).min_w(0.0).truncate()))
        .child(rule())
}

/// Results as a ledger; each line opens the investigation case file.
fn results_ledger(rep: &Value, limit: usize) -> El {
    let mut sheet_ = sheet("ledger").child(ledger_head(["Verdict", "Instruction", "Amount", "Finding  ·  click a line to investigate"]));
    for (i, r) in rep["results"].as_array().cloned().unwrap_or_default().iter().take(limit).enumerate() {
        let who = if r["kind"] == "unapproved_event" { "— no instruction —".to_owned() } else { r["action_id"].as_str().unwrap_or("").to_owned() };
        sheet_ = sheet_.child(
            ledger_line(format!("res{i}"), r["verdict"].as_str().unwrap_or(""), &who, r["amount_minor"].as_i64(), &reasons(r))
                .focusable(true).role("button").label(format!("Investigate {who}"))
                .on_press(move |s: &mut App| { s.selected = Some(i); s.page = Page::Investigation; }),
        );
    }
    sheet_
}

// ------------------------------------------------------------------ overview

pub fn overview(s: &App) -> El {
    let l = look();
    let rep = s.report.clone().unwrap_or_default();
    let c = &rep["counts"];
    let figure = |key: &str, cap: &str, value: String, color: Color| col().key(key).gap(4.0).grow(1.0).min_w(0.0)
        .child(text(cap.to_owned()).font(label()).color(l.faint))
        .child(text(value).font(display(34.0)).color(color));
    let at_risk = n(&rep["at_risk_minor"]);
    let headline = sheet("headline").padding(22.0).gap(16.0)
        .child(row().gap(24.0)
            .child(figure("risk", "Money at risk", inr(at_risk), if at_risk > 0 { l.crimson } else { l.ink }))
            .child(figure("ok", "Verified as authorised", inr(n(&rep["verified_minor"])), l.sage))
            .child(figure("ins", "Signed instructions", s.status.as_ref().map_or("—".into(), |st| st["instructions"].to_string()), l.ink))
            .child(figure("runs", "Verification runs", s.runs.len().to_string(), l.ink)))
        .child(rule())
        .child(row().gap(22.0).center_y()
            .child(text(format!("{} matched", n(&c["matched"]))).font(figures(13.0, 600.0)).color(l.sage))
            .child(text(format!("{} conflicts", n(&c["conflict"]))).font(figures(13.0, 600.0)).color(l.crimson))
            .child(text(format!("{} missing", n(&c["missing"]))).font(figures(13.0, 600.0)).color(l.ink2))
            .child(text(format!("{} needs review", n(&c["ambiguous"]))).font(figures(13.0, 600.0)).color(l.amber))
            .child(el().grow(1.0))
            .child(primary(s, "Run the DEMO replay", |s: &mut App| { s.send(Action::Demo); s.page = Page::Payouts; })));
    let mut page = col().key("overview").gap(16.0).child(headline);
    if rep.is_null() {
        page = page.child(sheet("first-run").padding(22.0).gap(8.0)
            .child(text("Start here").font(display(22.0)).color(l.ink))
            .child(text("1. Sign an instruction (Instructions). 2. Check a payout against it (Payment gate). 3. Verify a provider export (Payouts). Or run the DEMO replay: synthetic, labelled data with the attacks CERT-In described in October and November 2026.").font(body()).color(l.ink2).wrap()));
    } else {
        page = page.child(results_ledger(&rep, 5));
    }
    page
}

// ------------------------------------------------------------------ instructions

pub fn instructions(s: &App) -> El {
    let l = look();
    let form = sheet("sign").padding(20.0).gap(12.0)
        .child(row().gap(14.0)
            .child(field("Amount", &s.amount, |s| &mut s.amount).grow(1.0))
            .child(field("Currency", &s.currency, |s| &mut s.currency).w(104.0))
            .child(field("Beneficiary token", &s.beneficiary, |s| &mut s.beneficiary).grow(1.5)))
        .child(row().gap(14.0)
            .child(field("Loan reference", &s.reference, |s| &mut s.reference).grow(1.0))
            .child(field("Sanction id", &s.approval, |s| &mut s.approval).grow(1.0))
            .child(field("Approved by", &s.approver, |s| &mut s.approver).grow(1.0)))
        .child(row().gap(12.0).center_y()
            .child(primary(s, "Sign instruction", |s: &mut App| {
                let body = json!({"amount": s.amount.text.trim(), "currency": s.currency.text.trim(), "beneficiary_token": s.beneficiary.text.trim(),
                    "reference": s.reference.text.trim(), "approval_ref": s.approval.text.trim(), "approved_by": s.approver.text.trim(),
                    "purpose": "loan_disbursal", "policy": "disbursal-v3"});
                s.send(Action::Sign(body));
            }))
            .child(planned("Import instructions"))
            .child(text("Checked by the server before signing; valid 15 minutes.").font(small()).color(l.faint)));
    let mut list = sheet("list").child(ledger_head(["Signed", "Instruction", "Amount", "Reference · approved by · valid until"]));
    for (i, ins) in s.instructions.iter().take(8).enumerate() {
        list = list.child(ledger_line(format!("r{i}"), "ok", ins["instruction_id"].as_str().unwrap_or(""), ins["amount_minor"].as_i64(),
            &format!("{}  ·  {}  ·  {}", ins["reference"].as_str().unwrap_or(""), ins["approved_by"].as_str().unwrap_or(""), utc(n(&ins["not_after_ms"])))));
    }
    if s.instructions.is_empty() {
        list = list.child(row().px(18.0).py(16.0).child(text("Nothing signed yet.").font(body()).color(l.faint)));
    }
    col().key("instructions").gap(16.0).child(form).child(list)
}

// ------------------------------------------------------------------ gate

pub fn gate(s: &App) -> El {
    let l = look();
    let form = sheet("gate-form").padding(20.0).gap(12.0).grow(1.2).min_w(0.0)
        .child(field("Instruction id", &s.g_id, |s| &mut s.g_id))
        .child(row().gap(14.0)
            .child(field("Amount to pay", &s.g_amount, |s| &mut s.g_amount).grow(1.0))
            .child(field("Pay to (beneficiary token)", &s.g_beneficiary, |s| &mut s.g_beneficiary).grow(1.3)))
        .child(field("Provider reference the payout will carry (normally the instruction id)", &s.g_reference, |s| &mut s.g_reference))
        .child(primary(s, "Check before paying", |s: &mut App| {
            let body = json!({"instruction_id": s.g_id.text.trim(), "amount": s.g_amount.text.trim(), "currency": "INR",
                "beneficiary_token": s.g_beneficiary.text.trim(), "reference": s.g_reference.text.trim()});
            s.send(Action::Verify(body));
        }))
        .child(text("ALLOW consumes the instruction. REJECT and REVIEW do not.").font(small()).color(l.faint));
    let slip = match &s.decision {
        None => sheet("slip").padding(20.0).gap(10.0).grow(1.0).min_w(0.0)
            .child(eyebrow("Decision slip"))
            .child(text("No payout checked yet.").font(display(22.0)).color(l.faint)),
        Some(d) => {
            let v = d["verdict"].as_str().unwrap_or("reject");
            let (head, color) = match v {
                "allow" => ("Release the payment", l.sage),
                "review" => ("Hold for a person to decide", l.amber),
                _ => ("Do not pay", l.crimson),
            };
            let mut slip = sheet("slip").padding(20.0).gap(10.0).grow(1.0).min_w(0.0)
                .child(row().center_y().justify_between().child(eyebrow("Decision slip")).child(stamp_for(v)))
                .child(text(head).font(display(28.0)).color(color))
                .child(text(d["instruction_id"].as_str().unwrap_or("").to_owned()).font(code()).color(l.ink2))
                .child(rule());
            let rs = d["reasons"].as_array().cloned().unwrap_or_default();
            if rs.is_empty() {
                slip = slip.child(text("Signed by a trusted approver, unchanged, inside its window, first use.").font(body()).color(l.ink).wrap());
            }
            for (i, r) in rs.iter().enumerate() {
                slip = slip.child(row().key(format!("why{i}")).gap(10.0).items_start()
                    .child(text("—").font(body()).color(color))
                    .child(text(r.as_str().unwrap_or("").to_owned()).font(body()).color(l.ink).wrap().shrink().min_w(0.0)));
            }
            slip
        }
    };
    row().key("gate").gap(16.0).items_start().child(form).child(slip)
}

// ------------------------------------------------------------------ payouts

pub fn payouts(s: &App) -> El {
    let l = look();
    let form = sheet("p-form").padding(20.0).gap(12.0)
        .child(field("Payout export path (RazorpayX JSON, or generic CSV/JSON)", &s.p_path, |s| &mut s.p_path))
        .child(row().gap(10.0).center_y()
            .child(primary(s, "Verify payouts", |s: &mut App| {
                let path = s.p_path.text.trim().to_owned();
                let src = if path.to_lowercase().ends_with(".csv") { "generic" } else { "razorpayx" };
                s.send(Action::Reconcile(json!({"path": path, "source": src})));
            }))
            .child(secondary(s, "Run the DEMO replay", |s: &mut App| s.send(Action::Demo)))
            .child(text(s.run_id.as_deref().map_or(String::new(), |r| format!("Run {r}"))).font(code()).color(l.faint)));
    let Some(rep) = &s.report else {
        return col().key("payouts").gap(16.0).child(form);
    };
    let c = &rep["counts"];
    let total = (n(&c["matched"]) + n(&c["conflict"]) + n(&c["missing"]) + n(&c["ambiguous"])).max(1) as f32;
    let seg = |key: &str, v: i64, color: Color| el().key(key).h(8.0).grow(v as f32 / total).fill(color);
    let summary = sheet("summary").padding(18.0).gap(10.0)
        .child(row().center_y().justify_between()
            .child(col().gap(2.0).child(text("Money at risk").font(label()).color(l.faint))
                .child(text(inr(n(&rep["at_risk_minor"]))).font(display(32.0)).color(l.crimson)))
            .child(col().gap(2.0).items_end().child(text("Verified").font(label()).color(l.faint))
                .child(text(inr(n(&rep["verified_minor"]))).font(display(24.0)).color(l.sage))))
        .child(row().key("bar").w_full().gap(2.0)
            .child(seg("b-ok", n(&c["matched"]), l.sage)).child(seg("b-bad", n(&c["conflict"]), l.crimson))
            .child(seg("b-miss", n(&c["missing"]), l.ink2)).child(seg("b-pend", n(&c["ambiguous"]), l.amber)))
        .child(text(format!("{} matched · {} conflicts · {} missing · {} needs review", n(&c["matched"]), n(&c["conflict"]), n(&c["missing"]), n(&c["ambiguous"])))
            .font(figures(12.5, 500.0)).color(l.ink2));
    col().key("payouts").gap(16.0).child(form).child(summary).child(results_ledger(rep, 7))
}

// ------------------------------------------------------------------ investigation

fn kv(k: &str, v: String) -> El {
    let l = look();
    row().gap(12.0).py(5.0)
        .child(text(k.to_owned()).font(small()).color(l.faint).w(132.0))
        .child(text(v).font(TextStyle::new(13.0, 470.0)).color(l.ink).grow(1.0).min_w(0.0).wrap())
}

pub fn investigation(s: &App) -> El {
    let l = look();
    let picked = s.report.as_ref().zip(s.selected).and_then(|(rep, i)| rep["results"].get(i).cloned());
    let Some(r) = picked else {
        return sheet("pick").padding(22.0).gap(8.0)
            .child(text("No transaction selected").font(display(22.0)).color(l.ink))
            .child(text("Open Payouts and click any line in the results ledger. Its signed instruction, every provider record behind it and the exact reason for its verdict appear here.").font(body()).color(l.ink2).wrap())
            .child(row().child(secondary(s, "Go to Payouts", |s: &mut App| s.page = Page::Payouts)));
    };
    let verdict = r["verdict"].as_str().unwrap_or("");
    let unapproved = r["kind"] == "unapproved_event";
    let verdict_meaning = match verdict {
        "matched" => "Exactly one successful payout, same amount, currency and beneficiary, inside the signed window.",
        "conflict" if unapproved => "Money moved with no valid signed instruction behind it.",
        "conflict" => "The payout contradicts the signed instruction, or ran more than once.",
        "missing" => "The approved payout failed, was reversed, or never happened before the deadline.",
        _ => "Evidence is incomplete or still arriving; not treated as fraud.",
    };
    let head = sheet("case").padding(20.0).gap(10.0)
        .child(row().gap(12.0).center_y()
            .child(stamp_for(verdict))
            .child(text(if unapproved { "Payout without an instruction".to_owned() } else { r["action_id"].as_str().unwrap_or("").to_owned() }).font(code()).color(l.ink))
            .child(el().grow(1.0))
            .child(money(n(&r["amount_minor"]), 18.0, l.ink)))
        .child(text(verdict_meaning).font(body()).color(l.ink2).wrap())
        .child(rule())
        .child(eyebrow("Findings"))
        .child(text(reasons(&r)).font(TextStyle::new(14.0, 520.0)).color(if verdict == "matched" { l.sage } else { l.ink }).wrap());

    let ins = &r["instruction"];
    let auth = if ins.is_null() {
        sheet("auth").padding(20.0).gap(6.0).grow(1.0).min_w(0.0)
            .child(eyebrow("Authorisation"))
            .child(text("None. No trusted signed instruction carries this payout's reference.").font(body()).color(l.crimson).wrap())
    } else {
        sheet("auth").padding(20.0).gap(0.0).grow(1.0).min_w(0.0)
            .child(row().center_y().justify_between().pb(6.0).child(eyebrow("Signed instruction"))
                .child(stamp_for(if ins["signature_valid"] == true { "ok" } else { "untrusted" })))
            .child(kv("Amount", format!("{} {}", inr(n(&ins["amount_minor"])), ins["currency"].as_str().unwrap_or(""))))
            .child(kv("Beneficiary", ins["beneficiary"].as_str().unwrap_or("").to_owned()))
            .child(kv("Loan reference", ins["reference"].as_str().unwrap_or("").to_owned()))
            .child(kv("Approval", format!("{} by {}", ins["approval_ref"].as_str().unwrap_or(""), ins["approved_by"].as_str().unwrap_or(""))))
            .child(kv("Policy", ins["policy"].as_str().unwrap_or("").to_owned()))
            .child(kv("Valid", format!("{}  →  {}", utc(n(&ins["not_before_ms"])), utc(n(&ins["not_after_ms"])))))
            .child(kv("Signing key", ins["signing_key_id"].as_str().unwrap_or("").to_owned()))
            .child(kv("Digest", short(ins["digest"].as_str().unwrap_or(""), 24)))
    };
    let mut timeline = sheet("timeline").padding(20.0).gap(0.0).grow(1.0).min_w(0.0).child(eyebrow("Provider records, in time order").pb(8.0));
    let events = r["events"].as_array().cloned().unwrap_or_default();
    if events.is_empty() {
        timeline = timeline.child(text("No provider record references this instruction.").font(body()).color(l.faint));
    }
    for (i, e) in events.iter().enumerate() {
        timeline = timeline.child(col().key(format!("ev{i}")).py(8.0).gap(2.0)
            .child(row().gap(10.0).center_y()
                .child(text(utc(n(&e["time_ms"]))).font(figures(12.0, 500.0)).color(l.ink2))
                .child(look::chip(&e["status"].as_str().unwrap_or("").to_uppercase(), if e["status"] == "processed" { l.sage } else { l.ink2 }))
                .child(el().grow(1.0))
                .child(text(format!("{} {}", inr(n(&e["amount_minor"])), e["currency"].as_str().unwrap_or(""))).font(figures(13.0, 600.0)).color(l.ink)))
            .child(text(format!("{}  ·  to {}  ·  record {}", e["payout_id"].as_str().unwrap_or(""), e["beneficiary"].as_str().unwrap_or("?"),
                &e["record_hash"].as_str().unwrap_or("")[..12.min(e["record_hash"].as_str().unwrap_or("").len())])).font(code()).color(l.faint)));
    }
    let evidence = sheet("refs").padding(18.0).gap(4.0)
        .child(eyebrow("Evidence references"))
        .child(kv("Run", s.run_id.clone().unwrap_or_default()))
        .child(kv("Settlement", "No bank-statement source connected. Provider status is taken as reported (see Integrations).".into()))
        .child(row().pt(8.0).gap(10.0)
            .child(secondary(s, "Back to Payouts", |s: &mut App| s.page = Page::Payouts))
            .child(planned("Export evidence package")));
    col().key("investigation").gap(14.0).child(head).child(row().gap(14.0).items_start().child(auth).child(timeline)).child(evidence)
}

// ------------------------------------------------------------------ evidence

pub fn evidence(s: &App) -> El {
    let l = look();
    let st = s.status.clone().unwrap_or_default();
    let fact = |k: &str, cap: &str, v: String, good: bool| sheet(k).padding(16.0).gap(6.0).grow(1.0).min_w(0.0)
        .child(text(cap.to_owned()).font(label()).color(l.faint))
        .child(row().gap(10.0).center_y().child(text(v).font(display(22.0)).color(l.ink)).child(stamp_for(if good { "ok" } else { "check" })));
    let facts = row().gap(14.0)
        .child(fact("f-log", "Receipt log", format!("{} entries", st["log_entries"]), st["log_intact"] == true))
        .child(fact("f-audit", "API audit log", format!("{} calls", st["audit_entries"]), st["audit_intact"] == true))
        .child(fact("f-key", "Signing key", key_label(&st), st["key_protection"] != "file-permissions-only"));
    let actions = sheet("e-actions").padding(18.0).gap(10.0)
        .child(text("A checkpoint signs the log's size and latest entry. Keep the file where this machine cannot change it. A checkpoint proves records were not removed or rewritten after it was made; it does not prove a payout was legitimate.").font(body()).color(l.ink2).wrap())
        .child(row().gap(10.0)
            .child(primary(s, "Create checkpoint", |s: &mut App| s.send(Action::Checkpoint)))
            .child(secondary(s, "Verify all", |s: &mut App| s.send(Action::VerifyCheckpoints)))
            .child(planned("Time stamp with a TSA from the app")));
    let mut list = sheet("cp-list").child(ledger_head(["State", "Checkpoint", "", "Finding"]));
    if s.checkpoints.is_empty() {
        list = list.child(row().px(18.0).py(14.0).child(text("No checkpoints yet.").font(body()).color(l.faint)));
    }
    for (i, cp) in s.checkpoints.iter().take(6).enumerate() {
        let ok = cp["ok"].as_bool().unwrap_or(false);
        let why = cp["problems"].as_array().filter(|p| !p.is_empty())
            .map(|p| p.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; "))
            .unwrap_or_else(|| "Every covered receipt present and unchanged".to_owned());
        list = list.child(ledger_line(format!("cp{i}"), if ok { "intact" } else { "broken" }, cp["file"].as_str().unwrap_or(""), None, &why));
    }
    col().key("evidence").gap(14.0).child(facts).child(actions).child(list)
}

// ------------------------------------------------------------------ integrations

pub fn integrations(s: &App) -> El {
    let l = look();
    let line = |key: &str, name: &str, state: &str, note: &str| {
        let (word, c) = match state {
            "tested" => ("IMPLEMENTED · TESTED", l.sage),
            "agent" => ("IMPLEMENTED · OTHER TRACK", l.navy),
            _ => ("PLANNED", l.faint),
        };
        col().key(key.to_owned())
            .child(row().h(44.0).px(18.0).gap(16.0).center_y()
                .child(text(name.to_owned()).font(TextStyle::new(13.5, 560.0)).color(l.ink).w(250.0))
                .child(el().w(196.0).child(look::chip(word, c)))
                .child(text(note.to_owned()).font(body()).color(l.ink2).grow(1.0).min_w(0.0).truncate()))
            .child(rule())
    };
    let connectors = sheet("connectors")
        .child(line("c1", "RazorpayX payout export (file)", "tested", "JSON collection, list or JSON lines; amount in paise; reference_id = instruction id"))
        .child(line("c2", "Generic payouts (CSV or JSON file)", "tested", "columns payout_id, reference, amount_minor, currency, status, time, beneficiary"))
        .child(line("c3", "AWS CloudTrail (file)", "agent", "agent-action reconciliation; not part of the payout workflow"))
        .child(line("c4", "RazorpayX live API", "planned", "not connected; no credentials stored"))
        .child(line("c5", "Cashfree Payouts", "planned", "mapping not written or tested"))
        .child(line("c6", "Bank statement (settlement evidence)", "planned", "needed to catch a forged provider status"))
        .child(line("c7", "ACH / Nacha, international", "planned", "separate adapters, each validated before release"));
    let mut history = sheet("history").child(ledger_head(["Source", "Run", "Records", "Outcome · time"]));
    if s.runs.is_empty() {
        history = history.child(row().px(18.0).py(14.0).child(text("No imports yet.").font(body()).color(l.faint)));
    }
    for (i, r) in s.runs.iter().take(6).enumerate() {
        let c = &r["counts"];
        let id = r["run_id"].as_str().unwrap_or("").to_owned();
        history = history.child(
            col().key(format!("h{i}"))
                .child(row().h(40.0).px(18.0).gap(16.0).center_y().hover(l.paper.alpha(0.7))
                    .child(text(r["source"].as_str().unwrap_or("").to_owned()).font(small()).color(l.ink).w(92.0))
                    .child(text(id.clone()).font(code()).color(l.ink).w(214.0).truncate())
                    .child(text(format!("{} rows", r["payouts"])).font(figures(13.0, 500.0)).color(l.ink).w(130.0).align(Align::End))
                    .child(text(format!("{} matched, {} conflict  ·  {}", n(&c["matched"]), n(&c["conflict"]), r["created_at"].as_str().unwrap_or("").get(..19).unwrap_or(""))).font(body()).color(l.ink2).grow(1.0).min_w(0.0).truncate()))
                .child(rule())
                .focusable(true).role("button").label(format!("Open run {id}"))
                .on_press(move |s: &mut App| { s.send(Action::OpenRun(id.clone())); s.page = Page::Payouts; }));
    }
    col().key("integrations").gap(14.0)
        .child(eyebrow("Connectors")).child(connectors)
        .child(eyebrow("Import history (click to reopen a run)")).child(history)
}

// ------------------------------------------------------------------ settings

pub fn settings(s: &App) -> El {
    let st = s.status.clone().unwrap_or_default();
    let keys = sheet("keys").padding(20.0).gap(0.0).grow(1.0).min_w(0.0)
        .child(eyebrow("Signing key").pb(6.0))
        .child(kv("Key id", st["key_id"].as_str().unwrap_or("—").to_owned()))
        .child(kv("Protection", key_label(&st)))
        .child(kv("Private key", "Never shown or exported by this app".into()))
        .child(kv("Rotation", "Planned: verification-key history and revocation list".into()))
        .child(kv("Production", "Planned: KMS/HSM custody (not simulated here)".into()));
    let roles = sheet("roles").padding(20.0).gap(0.0).grow(1.0).min_w(0.0)
        .child(eyebrow("API roles").pb(6.0))
        .child(kv("admin", "this app: every route".into()))
        .child(kv("signer", "sign instructions, checkpoints".into()))
        .child(kv("executor", "gate checks only; cannot sign".into()))
        .child(kv("auditor", "read, reconcile, runs; cannot pay or sign".into()))
        .child(kv("Tokens", format!("{} (role tokens beside it)", crate::api::token_path())));
    let data = sheet("data").padding(20.0).gap(0.0)
        .child(eyebrow("Audit and data").pb(6.0))
        .child(kv("Audit log", format!("{} calls, chain {}", st["audit_entries"], if st["audit_intact"] == true { "intact" } else { "needs checking" })))
        .child(kv("Data location", st["home"].as_str().unwrap_or("—").to_owned()))
        .child(kv("Retention", "Kept locally; no automatic deletion yet (planned setting)".into()))
        .child(kv("API", format!("{} · contract v1 · server {}", crate::api::BASE, st["version"].as_str().unwrap_or("—"))))
        .child(kv("Sessions", "Single local user; multi-user sign-in planned".into()));
    col().key("settings").gap(14.0).child(row().gap(14.0).items_start().child(keys).child(roles)).child(data)
}
