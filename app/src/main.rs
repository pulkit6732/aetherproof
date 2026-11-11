//! AetherProof desktop app (Rune). Talks to `aetherproof serve`; scenes render every screen
//! headless with sample data: `aetherproof-app --list-scenes`, `--snap out.png --scene payouts`.

mod api;
mod look;
mod sample;

use api::{Action, Reply};
use look::{body, code, display, eyebrow, figures, inr, label, look, money, rule, stamp};
use rune::{Align, AppSpec, Color, Cx, El, Latest, TextEdit, TextStyle, Tx, Waker, col, el, row, text};
use rune_kit::{Button, ButtonVariant, Field, TextInput};
use serde_json::{Value, json};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Overview,
    Instructions,
    Gate,
    Payouts,
    Evidence,
}

const PAGES: [(Page, &str, &str, &str); 5] = [
    (Page::Overview, "overview", "01", "Overview"),
    (Page::Instructions, "instructions", "02", "Instructions"),
    (Page::Gate, "gate", "03", "Payment gate"),
    (Page::Payouts, "payouts", "04", "Payouts"),
    (Page::Evidence, "evidence", "05", "Evidence"),
];

pub struct App {
    pub page: Page,
    pub status: Option<Value>,
    pub instructions: Vec<Value>,
    pub decision: Option<Value>,
    pub report: Option<Value>,
    pub checkpoints: Vec<Value>,
    pub notice: Option<(bool, String)>,
    pub offline: bool,
    pub net: Latest<Reply>,
    pub amount: TextEdit,
    pub currency: TextEdit,
    pub beneficiary: TextEdit,
    pub reference: TextEdit,
    pub approval: TextEdit,
    pub approver: TextEdit,
    pub g_id: TextEdit,
    pub g_amount: TextEdit,
    pub g_beneficiary: TextEdit,
    pub p_path: TextEdit,
}

fn init() -> App {
    App {
        page: Page::Overview,
        status: None,
        instructions: Vec::new(),
        decision: None,
        report: None,
        checkpoints: Vec::new(),
        notice: None,
        offline: false,
        net: Latest::default(),
        amount: TextEdit::new("48500.00"),
        currency: TextEdit::new("INR"),
        beneficiary: TextEdit::new("fa_borrower_01"),
        reference: TextEdit::new("LN-2026-1041"),
        approval: TextEdit::new("SAN-7701"),
        approver: TextEdit::new("credit-ops"),
        g_id: TextEdit::new(""),
        g_amount: TextEdit::new(""),
        g_beneficiary: TextEdit::new(""),
        p_path: TextEdit::new(""),
    }
}

impl App {
    fn send(&mut self, a: Action) {
        if rune::tooling::headless_run().is_none() {
            self.net.request(a, api::run);
        }
    }
}

fn setup(s: &mut App, waker: Waker) {
    s.net.set_waker(waker);
    s.send(Action::Refresh);
}

fn poll(s: &mut App, _t: f64, _tx: &mut Tx) -> bool {
    let Some(r) = s.net.take() else { return false };
    s.offline = r.offline;
    if let Some(st) = r.status {
        s.status = Some(st);
        s.instructions = r.instructions;
    }
    if let Some(sig) = r.signed {
        s.g_id.replace_text(sig["instruction_id"].as_str().unwrap_or(""));
        s.g_amount.replace_text(&format!("{:.2}", sig["amount_minor"].as_i64().unwrap_or(0) as f64 / 100.0));
        s.g_beneficiary.replace_text(sig["beneficiary"]["value"].as_str().unwrap_or(""));
    }
    if r.decision.is_some() {
        s.decision = r.decision;
    }
    if r.report.is_some() {
        s.report = r.report;
    }
    if let Some(c) = r.checkpoints {
        s.checkpoints = c;
    }
    if r.notice.is_some() {
        s.notice = r.notice;
    }
    true
}

// ------------------------------------------------------------------ frame

fn view(s: &App, _cx: &mut Cx<App>) -> El {
    let l = look();
    let page = match s.page {
        Page::Overview => overview(s),
        Page::Instructions => instructions(s),
        Page::Gate => gate(s),
        Page::Payouts => payouts(s),
        Page::Evidence => evidence(s),
    };
    let body = row().key("app").w_full().h_full().fill(l.paper)
        .child(rail(s))
        .child(col().key("main").grow(1.0).min_w(0.0).h_full().min_h(0.0).pt(34.0).pb(28.0).px(40.0).gap(22.0)
            .child(header(s))
            .child(notice(s))
            .child(page));
    rune_kit::root(body, Vec::new())
}

fn rail(s: &App) -> El {
    let l = look();
    let mut nav = col().key("nav").gap(2.0);
    for (page, key, n, name) in PAGES {
        let on = s.page == page;
        nav = nav.child(
            row().key(key).role("tab").label(name).checked(on).focusable(true).h(36.0).px(12.0).gap(12.0).center_y()
                .radius(6.0)
                .fill(if on { l.rail_hi } else { Color::TRANSPARENT })
                .hover(l.rail_hi.alpha(0.6))
                .on_press(move |s: &mut App| s.page = page)
                .child(text(n).font(figures(11.0, 600.0)).color(if on { l.brass } else { l.faint }))
                .child(text(name).font(nav_style(on)).color(if on { l.rail_text } else { l.rail_text.alpha(0.62) })),
        );
    }
    let st = s.status.clone().unwrap_or_default();
    let line = |k: &str, v: String, good: bool| row().gap(8.0).center_y()
        .child(el().size(6.0, 6.0).radius(3.0).fill(if good { l.sage } else { l.crimson }))
        .child(text(format!("{k}  {v}")).font(TextStyle::new(11.5, 450.0)).color(l.rail_text.alpha(0.7)));
    let mut health = col().key("health").px(12.0).gap(6.0);
    if s.offline {
        health = health.child(line("API", "offline".into(), false));
    } else if !st.is_null() {
        health = health
            .child(line("API", "connected".into(), true))
            .child(line("Key", st["key_protection"].as_str().unwrap_or("?").replace("file-permissions-only", "unsealed").replace("dpapi", "sealed"), st["key_protection"] != "file-permissions-only"))
            .child(line("Audit log", if st["audit_intact"] == true { "intact".into() } else { "check".into() }, st["audit_intact"] == true));
    } else {
        health = health.child(line("API", "connecting".into(), true));
    }
    col().key("rail").w(236.0).h_full().fill(l.rail).pt(30.0).pb(20.0).px(12.0).gap(30.0)
        .child(col().key("mark").px(12.0).gap(4.0)
            .child(text("AetherProof").font(display(27.0)).color(l.rail_text))
            .child(text("Proof of authority for money").font(TextStyle::new(11.5, 450.0)).color(l.rail_text.alpha(0.55))))
        .child(nav)
        .child(el().grow(1.0))
        .child(health)
}

fn nav_style(on: bool) -> TextStyle {
    TextStyle::new(13.5, if on { 600.0 } else { 450.0 }).lh(18.0)
}

fn header(s: &App) -> El {
    let l = look();
    let (eye, title, sub) = match s.page {
        Page::Overview => ("Today", "Every payout, with proof of who authorised it", "Signed at approval, checked before money moves, matched after."),
        Page::Instructions => ("Originator", "Signed instructions", "Your approving system signs exactly the payout it approved."),
        Page::Gate => ("Executor", "Payment gate", "Run this before calling the payout rail. It pays each approval once."),
        Page::Payouts => ("Outcome", "Payout verification", "The provider's own records, matched back to every signed instruction."),
        Page::Evidence => ("Record", "Evidence", "Checkpoints and the audit log make missing or edited records detectable."),
    };
    col().key("header").gap(6.0)
        .child(eyebrow(eye))
        .child(text(title).font(display(36.0)).color(l.ink))
        .child(text(sub).font(body()).color(l.ink2))
}

fn notice(s: &App) -> El {
    let l = look();
    match &s.notice {
        None => el().key("notice"),
        Some((ok, msg)) => {
            let c = if *ok { l.sage } else { l.crimson };
            row().key("notice").gap(10.0).center_y().px(14.0).py(9.0).radius(6.0).fill(c.alpha(0.07)).border(1.0, c.alpha(0.35))
                .child(text(if *ok { "Done" } else { "Attention" }).font(label()).color(c))
                .child(text(msg.clone()).font(body()).color(l.ink))
        }
    }
}

fn sheet(key: &str) -> El {
    let l = look();
    col().key(key).radius(8.0).fill(l.card).border(1.0, l.rule).shadow(1.0, 2.0, l.ink.alpha(0.04))
}

fn field(label_: &str, edit: &TextEdit, get: fn(&mut App) -> &mut TextEdit) -> El {
    let k = look::kit();
    Field::new().label(label_).control(TextInput::new(edit).width(None).on_edit(get).build(k)).build(k).min_w(0.0)
}

fn primary(label_: &str, f: impl Fn(&mut App) + 'static) -> El {
    Button::new(label_).variant(ButtonVariant::Contrast).on_press(f).build(look::kit())
}

fn secondary(label_: &str, f: impl Fn(&mut App) + 'static) -> El {
    Button::new(label_).on_press(f).build(look::kit())
}

// ------------------------------------------------------------------ ledger rows

/// One ruled ledger line: stamp | id | amount (tabular, right) | reason.
fn ledger_line(key: String, verdict: &str, id: &str, amount: Option<i64>, why: &str) -> El {
    let l = look();
    col().key(key)
        .child(row().h(44.0).px(18.0).gap(16.0).center_y().hover(l.paper.alpha(0.7))
            .child(el().w(92.0).child(stamp(verdict)))
            .child(text(id.to_owned()).font(code()).color(l.ink).w(214.0).truncate())
            .child(el().w(130.0).child(match amount { Some(a) => money(a, 14.0, l.ink).w_full(), None => text("") }))
            .child(text(why.to_owned()).font(body()).color(l.ink2).grow(1.0).min_w(0.0).truncate()))
        .child(rule())
}

fn ledger_head(cols: [&str; 4]) -> El {
    let l = look();
    col().child(row().h(36.0).px(18.0).gap(16.0).center_y()
            .child(text(cols[0]).font(label()).color(l.faint).w(92.0))
            .child(text(cols[1]).font(label()).color(l.faint).w(214.0))
            .child(text(cols[2]).font(label()).color(l.faint).w(130.0).align(Align::End))
            .child(text(cols[3]).font(label()).color(l.faint).grow(1.0)))
        .child(rule())
}

fn results_ledger(rep: &Value, limit: usize) -> El {
    let mut sheet_ = sheet("ledger").child(ledger_head(["Verdict", "Instruction", "Amount", "Finding"]));
    for (i, r) in rep["results"].as_array().cloned().unwrap_or_default().iter().take(limit).enumerate() {
        let who = if r["kind"] == "unapproved_event" { "— no instruction —".to_owned() } else { r["action_id"].as_str().unwrap_or("").to_owned() };
        let why = r["reasons"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; "))
            .filter(|w| !w.is_empty()).unwrap_or_else(|| "Paid exactly as authorised".to_owned());
        sheet_ = sheet_.child(ledger_line(format!("res{i}"), r["verdict"].as_str().unwrap_or(""), &who, r["amount_minor"].as_i64(), &why));
    }
    sheet_
}

// ------------------------------------------------------------------ pages

fn overview(s: &App) -> El {
    let l = look();
    let rep = s.report.clone().unwrap_or_default();
    let at_risk = rep["at_risk_minor"].as_i64().unwrap_or(0);
    let verified = rep["verified_minor"].as_i64().unwrap_or(0);
    let c = &rep["counts"];
    let n = |v: &Value| v.as_i64().unwrap_or(0);
    let figure = |key: &str, cap: &str, value: String, color: Color| col().key(key).gap(4.0).grow(1.0).min_w(0.0)
        .child(text(cap.to_owned()).font(label()).color(l.faint))
        .child(text(value).font(display(40.0)).color(color));
    let headline = sheet("headline").padding(24.0).gap(18.0)
        .child(row().gap(28.0)
            .child(figure("risk", "Money at risk", inr(at_risk), if at_risk > 0 { l.crimson } else { l.ink }))
            .child(figure("ok", "Verified as authorised", inr(verified), l.sage))
            .child(figure("ins", "Signed instructions", s.status.as_ref().map_or("—".into(), |st| st["instructions"].to_string()), l.ink)))
        .child(rule())
        .child(row().gap(22.0).center_y()
            .child(text(format!("{} matched", n(&c["matched"]))).font(figures(13.0, 600.0)).color(l.sage))
            .child(text(format!("{} conflicts", n(&c["conflict"]))).font(figures(13.0, 600.0)).color(l.crimson))
            .child(text(format!("{} missing", n(&c["missing"]))).font(figures(13.0, 600.0)).color(l.ink2))
            .child(text(format!("{} pending", n(&c["ambiguous"]))).font(figures(13.0, 600.0)).color(l.amber))
            .child(el().grow(1.0))
            .child(primary("Run the Crafty Falcon replay", |s: &mut App| { s.send(Action::Demo); s.page = Page::Payouts; })));
    let mut page = col().key("overview").gap(18.0).child(headline);
    if rep.is_null() {
        page = page.child(sheet("empty").padding(24.0).gap(8.0)
            .child(text("No verification run yet").font(display(22.0)).color(l.ink))
            .child(text("The replay seeds four approved disbursals and six payouts, including the attacks CERT-In described in October and November 2026: payouts with no approval, a changed beneficiary, a changed amount and a double payment.").font(body()).color(l.ink2).wrap()));
    } else {
        page = page.child(results_ledger(&rep, 6));
    }
    page
}

fn instructions(s: &App) -> El {
    let l = look();
    let form = sheet("sign").padding(22.0).gap(14.0)
        .child(row().gap(14.0)
            .child(field("Amount", &s.amount, |s| &mut s.amount).grow(1.0))
            .child(field("Currency", &s.currency, |s| &mut s.currency).w(104.0))
            .child(field("Beneficiary token", &s.beneficiary, |s| &mut s.beneficiary).grow(1.5)))
        .child(row().gap(14.0)
            .child(field("Loan reference", &s.reference, |s| &mut s.reference).grow(1.0))
            .child(field("Sanction id", &s.approval, |s| &mut s.approval).grow(1.0))
            .child(field("Approved by", &s.approver, |s| &mut s.approver).grow(1.0)))
        .child(row().gap(12.0).center_y()
            .child(primary("Sign instruction", |s: &mut App| {
                let body = json!({"amount": s.amount.text, "currency": s.currency.text, "beneficiary_token": s.beneficiary.text,
                    "reference": s.reference.text, "approval_ref": s.approval.text, "approved_by": s.approver.text,
                    "purpose": "loan_disbursal", "policy": "disbursal-v3"});
                s.send(Action::Sign(body));
            }))
            .child(text("Valid 15 minutes. Signed with the key sealed to this machine.").font(TextStyle::new(12.0, 450.0)).color(l.faint)));
    let mut list = sheet("list").child(ledger_head(["Signed", "Instruction", "Amount", "Reference · approved by"]));
    for (i, ins) in s.instructions.iter().take(8).enumerate() {
        let minor = ins["amount_minor"].as_i64().or_else(|| ins["amount"].as_str().and_then(|a| a.parse::<f64>().ok()).map(|a| (a * 100.0).round() as i64));
        list = list.child(ledger_line(format!("r{i}"), "ok", ins["instruction_id"].as_str().unwrap_or(""), minor,
            &format!("{}  ·  {}", ins["reference"].as_str().unwrap_or(""), ins["approved_by"].as_str().unwrap_or(""))));
    }
    if s.instructions.is_empty() {
        list = list.child(row().px(18.0).py(16.0).child(text("Nothing signed yet.").font(body()).color(l.faint)));
    }
    col().key("instructions").gap(18.0).child(form).child(list)
}

fn gate(s: &App) -> El {
    let l = look();
    let form = sheet("gate-form").padding(22.0).gap(14.0).grow(1.2).min_w(0.0)
        .child(field("Instruction id", &s.g_id, |s| &mut s.g_id))
        .child(row().gap(14.0)
            .child(field("Amount to pay", &s.g_amount, |s| &mut s.g_amount).grow(1.0))
            .child(field("Pay to (beneficiary token)", &s.g_beneficiary, |s| &mut s.g_beneficiary).grow(1.3)))
        .child(primary("Check before paying", |s: &mut App| {
            let body = json!({"instruction_id": s.g_id.text, "amount": s.g_amount.text, "currency": "INR",
                "beneficiary_token": s.g_beneficiary.text, "reference": s.g_id.text});
            s.send(Action::Verify(body));
        }))
        .child(text("A second attempt, or any change to amount or payee, is refused.").font(TextStyle::new(12.0, 450.0)).color(l.faint));
    let slip = match &s.decision {
        None => sheet("slip").padding(22.0).gap(10.0).grow(1.0).min_w(0.0)
            .child(eyebrow("Decision slip"))
            .child(text("Awaiting a payout to check.").font(display(22.0)).color(l.faint)),
        Some(d) => {
            let allow = d["verdict"] == "allow";
            let mut slip = sheet("slip").padding(22.0).gap(12.0).grow(1.0).min_w(0.0)
                .child(row().center_y().justify_between().child(eyebrow("Decision slip")).child(stamp(if allow { "allow" } else { "reject" })))
                .child(text(if allow { "Release the payment" } else { "Do not pay" }).font(display(30.0)).color(if allow { l.sage } else { l.crimson }))
                .child(text(d["instruction_id"].as_str().unwrap_or("").to_owned()).font(code()).color(l.ink2))
                .child(rule());
            let reasons = d["reasons"].as_array().cloned().unwrap_or_default();
            if reasons.is_empty() {
                slip = slip.child(text("Signed by a trusted approver, unchanged, inside its window, first use.").font(body()).color(l.ink).wrap());
            }
            for (i, r) in reasons.iter().enumerate() {
                slip = slip.child(row().key(format!("why{i}")).gap(10.0).items_start()
                    .child(text("—").font(body()).color(l.crimson))
                    .child(text(r.as_str().unwrap_or("").to_owned()).font(body()).color(l.ink).wrap().shrink().min_w(0.0)));
            }
            slip
        }
    };
    row().key("gate").gap(18.0).items_start().child(form).child(slip)
}

fn payouts(s: &App) -> El {
    let l = look();
    let form = sheet("p-form").padding(22.0).gap(14.0)
        .child(field("Payout export — RazorpayX JSON, or a generic CSV/JSON path", &s.p_path, |s| &mut s.p_path))
        .child(row().gap(10.0)
            .child(primary("Verify payouts", |s: &mut App| {
                let src = if s.p_path.text.ends_with(".csv") { "generic" } else { "razorpayx" };
                s.send(Action::Reconcile(json!({"path": s.p_path.text, "source": src})));
            }))
            .child(secondary("Run the replay", |s: &mut App| s.send(Action::Demo))));
    let Some(rep) = &s.report else {
        return col().key("payouts").gap(18.0).child(form);
    };
    let c = &rep["counts"];
    let n = |k: &str| c[k].as_i64().unwrap_or(0);
    let total = (n("matched") + n("conflict") + n("missing") + n("ambiguous")).max(1) as f32;
    let seg = |key: &str, v: i64, color: Color| el().key(key).h(8.0).grow(v as f32 / total).fill(color);
    let summary = sheet("summary").padding(20.0).gap(12.0)
        .child(row().center_y().justify_between()
            .child(col().gap(2.0)
                .child(text("Money at risk").font(label()).color(l.faint))
                .child(text(inr(rep["at_risk_minor"].as_i64().unwrap_or(0))).font(display(34.0)).color(l.crimson)))
            .child(col().gap(2.0).items_end()
                .child(text("Verified").font(label()).color(l.faint))
                .child(text(inr(rep["verified_minor"].as_i64().unwrap_or(0))).font(display(26.0)).color(l.sage))))
        .child(row().key("bar").w_full().radius(4.0).gap(2.0)
            .child(seg("b-ok", n("matched"), l.sage)).child(seg("b-bad", n("conflict"), l.crimson))
            .child(seg("b-miss", n("missing"), l.ink2)).child(seg("b-pend", n("ambiguous"), l.amber)))
        .child(text(format!("{} matched · {} conflicts · {} missing · {} pending", n("matched"), n("conflict"), n("missing"), n("ambiguous")))
            .font(figures(12.5, 500.0)).color(l.ink2));
    col().key("payouts").gap(18.0).child(form).child(summary).child(results_ledger(rep, 8))
}

fn evidence(s: &App) -> El {
    let l = look();
    let st = s.status.clone().unwrap_or_default();
    let fact = |k: &str, cap: &str, v: String, good: bool| sheet(k).padding(18.0).gap(6.0).grow(1.0).min_w(0.0)
        .child(text(cap.to_owned()).font(label()).color(l.faint))
        .child(row().gap(10.0).center_y().child(text(v).font(display(24.0)).color(l.ink)).child(stamp(if good { "ok" } else { "check" })));
    let facts = row().gap(14.0)
        .child(fact("f-log", "Receipt log", format!("{} entries", st["log_entries"]), st["log_intact"] == true))
        .child(fact("f-audit", "API audit log", format!("{} calls", st["audit_entries"]), st["audit_intact"] == true))
        .child(fact("f-key", "Signing key", st["key_protection"].as_str().unwrap_or("—").replace("file-permissions-only", "unsealed").replace("dpapi", "sealed (DPAPI)"),
            st["key_protection"] != "file-permissions-only"));
    let actions = sheet("e-actions").padding(20.0).gap(12.0)
        .child(text("A checkpoint signs the log's size and latest entry. Keep the file where this machine cannot change it: with your auditor, or emailed to yourself.").font(body()).color(l.ink2).wrap())
        .child(row().gap(10.0)
            .child(primary("Create checkpoint", |s: &mut App| s.send(Action::Checkpoint)))
            .child(secondary("Verify all", |s: &mut App| s.send(Action::VerifyCheckpoints))));
    let mut list = sheet("cp-list").child(ledger_head(["State", "Checkpoint", "", "Finding"]));
    if s.checkpoints.is_empty() {
        list = list.child(row().px(18.0).py(16.0).child(text("No checkpoints yet.").font(body()).color(l.faint)));
    }
    for (i, cp) in s.checkpoints.iter().take(8).enumerate() {
        let ok = cp["ok"].as_bool().unwrap_or(false);
        let why = cp["problems"].as_array().filter(|p| !p.is_empty())
            .map(|p| p.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; "))
            .unwrap_or_else(|| "Every covered receipt present and unchanged".to_owned());
        list = list.child(ledger_line(format!("cp{i}"), if ok { "intact" } else { "broken" }, cp["file"].as_str().unwrap_or(""), None, &why));
    }
    col().key("evidence").gap(18.0).child(facts).child(actions).child(list)
}

const FONTS: &[&[u8]] = &[
    rune_theme_opencode::FONTS[0],
    rune_theme_opencode::FONTS[1],
    rune_theme_opencode::FONTS[2],
    include_bytes!("../assets/InstrumentSerif-Regular.ttf"),
];

fn main() {
    rune::run(AppSpec {
        scenes: sample::SCENES,
        fonts: FONTS,
        families: rune_theme_opencode::FAMILIES,
        setup: Some(setup),
        poll: Some(poll),
        min_size: Some((980.0, 640.0)),
        ..AppSpec::new("AetherProof", (1180.0, 760.0), init, view)
    });
}
