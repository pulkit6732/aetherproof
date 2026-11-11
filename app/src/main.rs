//! AetherProof desktop app (Rune). Talks to `aetherproof serve`; scenes render every screen
//! headless with sample data: `aetherproof-app --list-scenes`, `--snap out.png --scene payouts`.

mod api;
mod sample;

use api::{Action, Reply};
use rune::{AppSpec, Color, Cx, El, Latest, TextEdit, Tx, Waker, col, el, row, text};
use rune_kit::{Button, ButtonVariant, Field, Kit, TextInput};
use serde_json::{Value, json};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Overview,
    Instructions,
    Gate,
    Payouts,
    Evidence,
}

const PAGES: [(Page, &str, &str); 5] = [
    (Page::Overview, "overview", "Overview"),
    (Page::Instructions, "instructions", "Instructions"),
    (Page::Gate, "gate", "Payment gate"),
    (Page::Payouts, "payouts", "Payouts"),
    (Page::Evidence, "evidence", "Evidence"),
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
    // sign form
    pub amount: TextEdit,
    pub currency: TextEdit,
    pub beneficiary: TextEdit,
    pub reference: TextEdit,
    pub approval: TextEdit,
    pub approver: TextEdit,
    // gate form
    pub g_id: TextEdit,
    pub g_amount: TextEdit,
    pub g_beneficiary: TextEdit,
    // payouts form
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
        // hand the new instruction to the gate form, as an executor would receive it
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

// ------------------------------------------------------------------ view

fn view(s: &App, cx: &mut Cx<App>) -> El {
    let k = rune_theme_opencode::kit(cx.system_dark());
    let body = row()
        .key("app")
        .w_full()
        .h_full()
        .fill(k.c.page)
        .child(sidebar(s, k))
        .child(
            col().key("main").grow(1.0).min_w(0.0).h_full().min_h(0.0).pt(28.0).pb(24.0).px(32.0).gap(20.0)
                .child(header(s, k))
                .child(notice(s, k))
                .child(match s.page {
                    Page::Overview => overview(s, k),
                    Page::Instructions => instructions(s, k),
                    Page::Gate => gate(s, k),
                    Page::Payouts => payouts(s, k),
                    Page::Evidence => evidence(s, k),
                }),
        );
    rune_kit::root(body, Vec::new())
}

fn sidebar(s: &App, k: &Kit) -> El {
    let mut nav = col().key("nav").gap(2.0);
    for (page, key, label) in PAGES {
        let on = s.page == page;
        nav = nav.child(
            row().key(key).role("tab").label(label).checked(on).focusable(true).h(32.0).px(12.0).center_y()
                .radius(k.radius.md)
                .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
                .hover(k.c.hover)
                .press(k.c.pressed)
                .on_press(move |s: &mut App| s.page = page)
                .child(text(label).font(if on { k.ty.ui_medium } else { k.ty.ui }).color(if on { k.c.text_base } else { k.c.text_muted })),
        );
    }
    let (dot, state) = if s.offline { (k.c.danger.icon, "Backend offline") } else if s.status.is_some() { (k.c.success.icon, "Connected") } else { (k.c.text_faint, "Connecting") };
    col().key("sidebar").w(220.0).h_full().fill(k.c.bg_base).border(1.0, k.c.border_muted).pt(24.0).pb(16.0).px(12.0).gap(24.0)
        .child(
            col().key("brand").px(12.0).gap(2.0)
                .child(text("AetherProof").font(k.ty.body_medium).color(k.c.text_base))
                .child(text("Proof of authority for money").font(k.ty.caption()).color(k.c.text_faint)),
        )
        .child(nav)
        .child(el().grow(1.0))
        .child(
            row().key("conn").px(12.0).gap(8.0).center_y()
                .child(el().size(8.0, 8.0).radius(4.0).fill(dot))
                .child(text(state).font(k.ty.caption()).color(k.c.text_muted)),
        )
}

fn header(s: &App, k: &Kit) -> El {
    let (title, sub) = match s.page {
        Page::Overview => ("Overview", "Every payout should carry proof of who authorised it."),
        Page::Instructions => ("Signed instructions", "The approving system signs exactly what it authorised."),
        Page::Gate => ("Payment gate", "The executor checks the proof before any money moves."),
        Page::Payouts => ("Payout verification", "Did the rail pay what was authorised, and nothing else?"),
        Page::Evidence => ("Evidence", "Signed checkpoints make deleted or rewritten records detectable."),
    };
    col().key("header").gap(4.0)
        .child(text(title).font(rune::TextStyle::new(22.0, 600.0).lh(28.0)).color(k.c.text_base))
        .child(text(sub).font(k.ty.ui).color(k.c.text_muted))
}

fn notice(s: &App, k: &Kit) -> El {
    match &s.notice {
        None => el().key("notice"),
        Some((ok, msg)) => {
            let c = if *ok { k.c.success } else { k.c.danger };
            row().key("notice").px(12.0).py(8.0).radius(k.radius.md).fill(c.bg).border(1.0, c.border)
                .child(text(msg.clone()).font(k.ty.ui).color(c.fg))
        }
    }
}

fn card(k: &Kit, key: &str) -> El {
    col().key(key).padding(20.0).gap(14.0).radius(k.radius.lg).fill(k.c.bg_base).border(1.0, k.c.border_muted)
}

fn pill(k: &Kit, verdict: &str) -> El {
    let c = match verdict {
        "matched" | "allow" | "ok" => k.c.success,
        "ambiguous" | "review" => k.c.warning,
        _ => k.c.danger,
    };
    el().px(8.0).py(2.0).radius(k.radius.sm).fill(c.bg).border(1.0, c.border)
        .child(text(verdict.to_uppercase()).font(k.ty.small_medium).color(c.fg))
}

fn stat(k: &Kit, key: &str, value: String, label: &str) -> El {
    card(k, key).grow(1.0).min_w(0.0).gap(4.0)
        .child(text(value).font(rune::TextStyle::new(26.0, 600.0).lh(32.0)).color(k.c.text_base))
        .child(text(label).font(k.ty.caption()).color(k.c.text_muted))
}

fn field(k: &Kit, label: &str, edit: &TextEdit, get: fn(&mut App) -> &mut TextEdit) -> El {
    // width(None): the input fills its column, so a row of fields shares the card width
    Field::new().label(label).control(TextInput::new(edit).width(None).on_edit(get).build(k)).build(k).min_w(0.0)
}

fn overview(s: &App, k: &Kit) -> El {
    let st = s.status.clone().unwrap_or_default();
    let n = |f: &str| st[f].as_i64().map_or("–".to_owned(), |v| v.to_string());
    let intact = match st["log_intact"].as_bool() { Some(true) => "Intact", Some(false) => "Broken", None => "–" };
    let counts = s.report.as_ref().map(|r| r["counts"].clone()).unwrap_or_default();
    col().key("overview").gap(16.0)
        .child(row().gap(12.0)
            .child(stat(k, "s-ins", n("instructions"), "Signed instructions"))
            .child(stat(k, "s-log", n("log_entries"), "Log entries"))
            .child(stat(k, "s-chain", intact.to_owned(), "Hash chain"))
            .child(stat(k, "s-cp", n("checkpoints"), "Checkpoints")))
        .child(card(k, "how")
            .child(text("How it works").font(k.ty.body_medium).color(k.c.text_base))
            .child(step(k, "1", "Sign", "Your loan or payments system signs each payout it approves: amount, beneficiary, validity."))
            .child(step(k, "2", "Gate", "Before money moves, the executor checks the signature and refuses changes and replays."))
            .child(step(k, "3", "Verify", "Afterwards, provider records are matched back. Payouts with no instruction are flagged."))
            .child(row().gap(10.0).pt(6.0)
                .child(Button::new("Run the Crafty Falcon demo").variant(ButtonVariant::Contrast)
                    .on_press(|s: &mut App| { s.send(Action::Demo); s.page = Page::Payouts; }).build(k))
                .child(text(if counts.is_null() { "Seeds 4 approvals and 6 payouts, two of them attacks.".to_owned() }
                        else { format!("Last run: {} matched, {} conflict", counts["matched"], counts["conflict"]) })
                    .font(k.ty.caption()).color(k.c.text_muted))))
}

fn step(k: &Kit, n: &str, title: &str, body: &str) -> El {
    row().gap(12.0).items_start()
        .child(el().size(22.0, 22.0).radius(11.0).fill(k.c.layer_02).center().child(text(n.to_owned()).font(k.ty.small_medium).color(k.c.text_base)))
        .child(col().min_w(0.0).shrink().gap(2.0)
            .child(text(title.to_owned()).font(k.ty.ui_medium).color(k.c.text_base))
            .child(text(body.to_owned()).font(k.ty.ui).color(k.c.text_muted).wrap()))
}

fn instructions(s: &App, k: &Kit) -> El {
    let form = card(k, "sign")
        .child(row().gap(12.0)
            .child(field(k, "Amount", &s.amount, |s| &mut s.amount).grow(1.0))
            .child(field(k, "Currency", &s.currency, |s| &mut s.currency).w(110.0))
            .child(field(k, "Beneficiary token", &s.beneficiary, |s| &mut s.beneficiary).grow(1.4)))
        .child(row().gap(12.0)
            .child(field(k, "Loan reference", &s.reference, |s| &mut s.reference).grow(1.0))
            .child(field(k, "Sanction id", &s.approval, |s| &mut s.approval).grow(1.0))
            .child(field(k, "Approved by", &s.approver, |s| &mut s.approver).grow(1.0)))
        .child(row().child(Button::new("Sign instruction").variant(ButtonVariant::Contrast)
            .on_press(|s: &mut App| {
                let body = json!({"amount": s.amount.text, "currency": s.currency.text, "beneficiary_token": s.beneficiary.text,
                    "reference": s.reference.text, "approval_ref": s.approval.text, "approved_by": s.approver.text,
                    "purpose": "loan_disbursal", "policy": "disbursal-v3"});
                s.send(Action::Sign(body));
            }).build(k)));
    let mut list = card(k, "list").gap(0.0).padding(0.0)
        .child(table_row(k, "head", ["Instruction", "Amount", "Reference", "Approved by"], true));
    for (i, ins) in s.instructions.iter().take(10).enumerate() {
        list = list.child(table_row(k, &format!("r{i}"), [
            ins["instruction_id"].as_str().unwrap_or(""),
            &format!("{} {}", ins["amount"].as_str().unwrap_or(""), ins["currency"].as_str().unwrap_or("")),
            ins["reference"].as_str().unwrap_or(""),
            ins["approved_by"].as_str().unwrap_or(""),
        ], false));
    }
    if s.instructions.is_empty() {
        list = list.child(row().p_empty(k, "No instructions yet. Sign one above or run the demo."));
    }
    col().key("instructions").gap(16.0).child(form).child(list)
}

trait Empty {
    fn p_empty(self, k: &Kit, msg: &str) -> El;
}
impl Empty for El {
    fn p_empty(self, k: &Kit, msg: &str) -> El {
        self.px(16.0).py(14.0).child(text(msg.to_owned()).font(k.ty.ui).color(k.c.text_faint))
    }
}

fn table_row(k: &Kit, key: &str, cells: [&str; 4], head: bool) -> El {
    let style = if head { k.ty.small_medium } else { k.ty.ui };
    let color = if head { k.c.text_faint } else { k.c.text_base };
    let mut r = row().key(key).h(if head { 34.0 } else { 38.0 }).px(16.0).gap(12.0).center_y();
    if !head {
        r = r.border(0.0, k.c.border_muted).hover(k.c.hover);
    }
    for (i, c) in cells.iter().enumerate() {
        r = r.child(text((*c).to_owned()).font(if i == 0 && !head { k.ty.mono } else { style }).color(color).truncate()
            .grow(if i == 0 { 1.6 } else { 1.0 }).min_w(0.0));
    }
    r
}

fn gate(s: &App, k: &Kit) -> El {
    let form = card(k, "gate-form")
        .child(field(k, "Instruction id", &s.g_id, |s| &mut s.g_id))
        .child(row().gap(12.0)
            .child(field(k, "Amount to pay", &s.g_amount, |s| &mut s.g_amount).grow(1.0))
            .child(field(k, "Pay to (beneficiary token)", &s.g_beneficiary, |s| &mut s.g_beneficiary).grow(1.4)))
        .child(row().gap(10.0)
            .child(Button::new("Check before paying").variant(ButtonVariant::Contrast).on_press(|s: &mut App| {
                let body = json!({"instruction_id": s.g_id.text, "amount": s.g_amount.text, "currency": "INR",
                    "beneficiary_token": s.g_beneficiary.text, "reference": s.g_id.text});
                s.send(Action::Verify(body));
            }).build(k))
            .child(text("Try it twice, or change the amount: the second attempt is refused.").font(k.ty.caption()).color(k.c.text_faint)));
    let result = match &s.decision {
        None => card(k, "decision").child(text("No check yet.").font(k.ty.ui).color(k.c.text_faint)),
        Some(d) => {
            let verdict = d["verdict"].as_str().unwrap_or("reject");
            let mut c = card(k, "decision")
                .child(row().gap(10.0).center_y().child(pill(k, verdict))
                    .child(text(d["instruction_id"].as_str().unwrap_or("").to_owned()).font(k.ty.mono).color(k.c.text_muted)));
            let reasons = d["reasons"].as_array().cloned().unwrap_or_default();
            if reasons.is_empty() {
                c = c.child(text("Authorised, unchanged and first use. Safe to send to the payout rail.").font(k.ty.ui).color(k.c.text_base));
            }
            for (i, r) in reasons.iter().enumerate() {
                c = c.child(text(format!("• {}", r.as_str().unwrap_or(""))).key(format!("why{i}")).font(k.ty.ui).color(k.c.text_base).wrap());
            }
            c
        }
    };
    col().key("gate").gap(16.0).child(form).child(result)
}

fn payouts(s: &App, k: &Kit) -> El {
    let form = card(k, "p-form")
        .child(field(k, "Payout export (RazorpayX JSON or generic CSV/JSON path)", &s.p_path, |s| &mut s.p_path))
        .child(row().gap(10.0)
            .child(Button::new("Verify payouts").variant(ButtonVariant::Contrast).on_press(|s: &mut App| {
                let src = if s.p_path.text.ends_with(".csv") { "generic" } else { "razorpayx" };
                s.send(Action::Reconcile(json!({"path": s.p_path.text, "source": src})));
            }).build(k))
            .child(Button::new("Run demo").on_press(|s: &mut App| s.send(Action::Demo)).build(k)));
    let Some(rep) = &s.report else {
        return col().key("payouts").gap(16.0).child(form)
            .child(card(k, "results").child(text("Run the demo or point at a payout export.").font(k.ty.ui).color(k.c.text_faint)));
    };
    let c = &rep["counts"];
    let mut results = card(k, "results").gap(0.0).padding(0.0)
        .child(row().key("summary").px(16.0).py(12.0).gap(16.0)
            .child(text(format!("{} matched", c["matched"])).font(k.ty.ui_medium).color(k.c.success.fg))
            .child(text(format!("{} conflict", c["conflict"])).font(k.ty.ui_medium).color(k.c.danger.fg))
            .child(text(format!("{} missing", c["missing"])).font(k.ty.ui_medium).color(k.c.text_muted))
            .child(text(format!("{} pending", c["ambiguous"])).font(k.ty.ui_medium).color(k.c.warning.fg)));
    for (i, r) in rep["results"].as_array().cloned().unwrap_or_default().iter().take(12).enumerate() {
        let verdict = r["verdict"].as_str().unwrap_or("");
        let who = if r["kind"] == "unapproved_event" { "No instruction".to_owned() } else { r["action_id"].as_str().unwrap_or("").to_owned() };
        let why = r["reasons"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; ")).filter(|w| !w.is_empty())
            .unwrap_or_else(|| "Paid exactly as authorised".to_owned());
        results = results.child(row().key(format!("res{i}")).px(16.0).py(10.0).gap(12.0).center_y().hover(k.c.hover)
            .child(el().w(96.0).child(pill(k, verdict)))
            .child(text(who).font(k.ty.mono).color(k.c.text_base).w(230.0).truncate())
            .child(text(why).font(k.ty.ui).color(k.c.text_muted).grow(1.0).min_w(0.0).truncate()));
    }
    col().key("payouts").gap(16.0).child(form).child(results)
}

fn evidence(s: &App, k: &Kit) -> El {
    let actions = card(k, "e-actions")
        .child(text("A checkpoint signs the log's size and latest entry. Keep the file somewhere this machine cannot change.").font(k.ty.ui).color(k.c.text_muted).wrap())
        .child(row().gap(10.0)
            .child(Button::new("Create checkpoint").variant(ButtonVariant::Contrast).on_press(|s: &mut App| s.send(Action::Checkpoint)).build(k))
            .child(Button::new("Verify all").on_press(|s: &mut App| s.send(Action::VerifyCheckpoints)).build(k)));
    let mut list = card(k, "cp-list").gap(0.0).padding(0.0);
    if s.checkpoints.is_empty() {
        list = list.child(row().p_empty(k, "No checkpoints yet."));
    }
    for (i, cp) in s.checkpoints.iter().take(10).enumerate() {
        let ok = cp["ok"].as_bool().unwrap_or(false);
        let detail = cp["problems"].as_array().filter(|p| !p.is_empty())
            .map(|p| p.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; "))
            .unwrap_or_else(|| "All covered receipts present and unchanged".to_owned());
        list = list.child(row().key(format!("cp{i}")).px(16.0).py(10.0).gap(12.0).center_y()
            .child(el().w(80.0).child(pill(k, if ok { "ok" } else { "broken" })))
            .child(text(cp["file"].as_str().unwrap_or("").to_owned()).font(k.ty.mono).color(k.c.text_base).w(300.0).truncate())
            .child(text(detail).font(k.ty.ui).color(k.c.text_muted).grow(1.0).min_w(0.0).truncate()));
    }
    col().key("evidence").gap(16.0).child(actions).child(list)
}

fn main() {
    rune::run(AppSpec {
        scenes: sample::SCENES,
        fonts: rune_theme_opencode::FONTS,
        families: rune_theme_opencode::FAMILIES,
        setup: Some(setup),
        poll: Some(poll),
        min_size: Some((900.0, 600.0)),
        ..AppSpec::new("AetherProof", (1120.0, 720.0), init, view)
    });
}
