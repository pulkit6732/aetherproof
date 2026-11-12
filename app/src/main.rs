//! AetherProof desktop app (Rune) over `aetherproof serve` (/api/v1). Scenes render every
//! screen headless with sample data: `aetherproof-app --list-scenes`, `--snap x.png --scene payouts`.

mod api;
mod look;
mod sample;
mod screens;

use api::{Action, Reply};
use look::{body, eyebrow, figures, label, look, stamp};
use rune::{AppSpec, Color, Cx, El, Latest, TextEdit, TextStyle, Tx, Waker, col, el, row, text};
use rune_kit::{Button, ButtonVariant, Field, TextInput};
use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Overview,
    Instructions,
    Gate,
    Payouts,
    Investigation,
    Evidence,
    Integrations,
    Settings,
}

const PAGES: [(Page, &str, &str, &str); 8] = [
    (Page::Overview, "nav-overview", "01", "Overview"),
    (Page::Instructions, "nav-instructions", "02", "Instructions"),
    (Page::Gate, "nav-gate", "03", "Payment gate"),
    (Page::Payouts, "nav-payouts", "04", "Payouts"),
    (Page::Investigation, "nav-investigation", "05", "Investigation"),
    (Page::Evidence, "nav-evidence", "06", "Evidence"),
    (Page::Integrations, "nav-integrations", "07", "Integrations"),
    (Page::Settings, "nav-settings", "08", "Settings & security"),
];

/// The one request in flight, if any. A second action while one runs is refused, so a
/// double click never submits twice and no answer is dropped for a newer one.
#[derive(Clone, Debug, PartialEq)]
pub enum Job {
    Idle,
    Processing(&'static str),
    Completed(String),
    Failed(String),
}

pub struct App {
    pub page: Page,
    pub job: Job,
    pub status: Option<Value>,
    pub instructions: Vec<Value>,
    pub runs: Vec<Value>,
    pub decision: Option<Value>,
    pub report: Option<Value>,
    pub run_id: Option<String>,
    pub selected: Option<usize>,
    pub checkpoints: Vec<Value>,
    pub offline: bool,
    pub updated_unix_s: u64,
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
    pub g_reference: TextEdit,
    pub p_path: TextEdit,
}

fn init() -> App {
    App {
        page: Page::Overview,
        job: Job::Idle,
        status: None,
        instructions: Vec::new(),
        runs: Vec::new(),
        decision: None,
        report: None,
        run_id: None,
        selected: None,
        checkpoints: Vec::new(),
        offline: false,
        updated_unix_s: 0,
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
        g_reference: TextEdit::new(""),
        p_path: TextEdit::new(""),
    }
}

impl App {
    pub fn busy(&self) -> bool {
        matches!(self.job, Job::Processing(_))
    }
    pub fn send(&mut self, a: Action) {
        if self.busy() {
            return; // duplicate-submit guard
        }
        if rune::tooling::headless_run().is_some() {
            return; // headless scenes never touch the network, so nothing is ever in flight
        }
        self.job = Job::Processing(a.label());
        self.net.request(a, api::run);
    }
}

fn setup(s: &mut App, waker: Waker) {
    s.net.set_waker(waker);
    s.send(Action::Refresh);
}

fn poll(s: &mut App, _t: f64, _tx: &mut Tx) -> bool {
    let Some(r) = s.net.take() else { return false };
    s.offline = r.offline;
    s.updated_unix_s = r.at_unix_s;
    if let Some(st) = r.status {
        s.status = Some(st);
        s.instructions = r.instructions;
    }
    if let Some(runs) = r.runs {
        s.runs = runs;
    }
    if let Some(sig) = r.signed {
        s.g_id.replace_text(sig["instruction_id"].as_str().unwrap_or(""));
        s.g_reference.replace_text(sig["instruction_id"].as_str().unwrap_or(""));
        s.g_amount.replace_text(&format!("{:.2}", sig["amount_minor"].as_i64().unwrap_or(0) as f64 / 100.0));
        s.g_beneficiary.replace_text(sig["beneficiary"]["value"].as_str().unwrap_or(""));
    }
    if r.decision.is_some() {
        s.decision = r.decision;
    }
    if r.report.is_some() {
        s.report = r.report;
        s.run_id = r.run_id;
        s.selected = None;
    }
    if let Some(c) = r.checkpoints {
        s.checkpoints = c;
    }
    s.job = match r.outcome {
        None => Job::Idle,
        Some(Ok(m)) => Job::Completed(m),
        Some(Err(e)) => Job::Failed(e),
    };
    true
}

// ------------------------------------------------------------------ frame

fn view(s: &App, _cx: &mut Cx<App>) -> El {
    let l = look();
    let page = match s.page {
        Page::Overview => screens::overview(s),
        Page::Instructions => screens::instructions(s),
        Page::Gate => screens::gate(s),
        Page::Payouts => screens::payouts(s),
        Page::Investigation => screens::investigation(s),
        Page::Evidence => screens::evidence(s),
        Page::Integrations => screens::integrations(s),
        Page::Settings => screens::settings(s),
    };
    let body = row().key("app").w_full().h_full().fill(l.paper)
        .child(rail(s))
        .child(col().key("main").grow(1.0).min_w(0.0).h_full().min_h(0.0).pt(30.0).pb(24.0).px(40.0).gap(18.0)
            .child(header(s))
            .child(job_line(s))
            .child(page));
    rune_kit::root(body, Vec::new())
}

fn rail(s: &App) -> El {
    let l = look();
    let mut nav = col().key("nav").gap(1.0);
    for (page, key, n, name) in PAGES {
        let on = s.page == page;
        nav = nav.child(
            row().key(key).role("tab").label(name).checked(on).focusable(true).h(34.0).px(12.0).gap(12.0).center_y()
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
            .child(line("Key", key_label(&st), st["key_protection"] != "file-permissions-only"))
            .child(line("Audit log", if st["audit_intact"] == true { "intact".into() } else { "check".into() }, st["audit_intact"] == true));
        if s.updated_unix_s > 0 {
            health = health.child(text(format!("Updated {}", look::utc(s.updated_unix_s as i64 * 1000))).font(TextStyle::new(10.5, 450.0)).color(l.rail_text.alpha(0.45)));
        }
    } else {
        health = health.child(line("API", "connecting".into(), true));
    }
    col().key("rail").w(236.0).h_full().fill(l.rail).pt(28.0).pb(18.0).px(12.0).gap(26.0)
        .child(col().key("mark").px(12.0).gap(4.0)
            .child(text("AetherProof").font(look::display(27.0)).color(l.rail_text))
            .child(text("Proof of authority for money").font(TextStyle::new(11.5, 450.0)).color(l.rail_text.alpha(0.55))))
        .child(nav)
        .child(el().grow(1.0))
        .child(health)
}

pub fn key_label(st: &Value) -> String {
    match st["key_protection"].as_str().unwrap_or("?") {
        "dpapi" => "sealed (DPAPI)".into(),
        "passphrase" => "passphrase".into(),
        "file-permissions-only" => "unsealed".into(),
        other => other.into(),
    }
}

fn nav_style(on: bool) -> TextStyle {
    TextStyle::new(13.5, if on { 600.0 } else { 450.0 }).lh(18.0)
}

fn header(s: &App) -> El {
    let l = look();
    let (eye, title, sub) = match s.page {
        Page::Overview => ("Today", "Every payout, with proof of who authorised it", "Signed at approval, checked before money moves, matched after."),
        Page::Instructions => ("Originator", "Signed instructions", "Your approving system signs exactly the payout it approved."),
        Page::Gate => ("Executor · sandbox", "Payment gate", "Runs on this machine. Not deployed in your payment path."),
        Page::Payouts => ("Outcome", "Payout verification", "The provider's records, matched back to every signed instruction."),
        Page::Investigation => ("Case file", "Transaction investigation", "Why a payout was matched, conflicted, missing or pending."),
        Page::Evidence => ("Record", "Evidence", "What each record proves, and what it does not."),
        Page::Integrations => ("Sources", "Integrations", "What is connected and tested, and what is only planned."),
        Page::Settings => ("Controls", "Settings & security", "Keys, roles, audit and data on this machine."),
    };
    let demo = s.report.as_ref().is_some_and(|r| r["demo"] == true);
    let mut title_row = row().gap(12.0).center_y().child(text(title).font(look::display(34.0)).color(l.ink));
    if demo && matches!(s.page, Page::Overview | Page::Payouts | Page::Investigation) {
        title_row = title_row.child(look::chip("DEMO DATA", l.amber));
    }
    col().key("header").gap(5.0).child(eyebrow(eye)).child(title_row).child(text(sub).font(body()).color(l.ink2))
}

/// The request state, always visible: what is running, what finished, what failed.
fn job_line(s: &App) -> El {
    let l = look();
    let (word, msg, c) = match &s.job {
        Job::Idle => return el().key("job"),
        Job::Processing(what) => ("PROCESSING", format!("{what}…"), l.navy),
        Job::Completed(m) => ("COMPLETED", m.clone(), l.sage),
        Job::Failed(m) => ("FAILED", m.clone(), l.crimson),
    };
    row().key("job").gap(10.0).center_y().px(14.0).py(8.0).radius(6.0).fill(c.alpha(0.07)).border(1.0, c.alpha(0.35))
        .child(text(word).font(label()).color(c))
        .child(text(msg).font(body()).color(l.ink).grow(1.0).min_w(0.0).truncate())
}

// ------------------------------------------------------------------ shared widgets

pub fn sheet(key: &str) -> El {
    let l = look();
    col().key(key).radius(8.0).fill(l.card).border(1.0, l.rule).shadow(1.0, 2.0, l.ink.alpha(0.04))
}

pub fn field(label_: &str, edit: &TextEdit, get: fn(&mut App) -> &mut TextEdit) -> El {
    let k = look::kit();
    Field::new().label(label_).control(TextInput::new(edit).width(None).on_edit(get).build(k)).build(k).min_w(0.0)
}

pub fn primary(s: &App, label_: &str, f: impl Fn(&mut App) + 'static) -> El {
    Button::new(label_).variant(ButtonVariant::Contrast).disabled(s.busy()).on_press(f).build(look::kit())
}

pub fn secondary(s: &App, label_: &str, f: impl Fn(&mut App) + 'static) -> El {
    Button::new(label_).disabled(s.busy()).on_press(f).build(look::kit())
}

pub fn planned(label_: &str) -> El {
    Button::new(format!("{label_} · planned")).disabled(true).build(look::kit())
}

pub fn stamp_for(v: &str) -> El {
    stamp(v)
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
        min_size: Some((1040.0, 680.0)),
        ..AppSpec::new("AetherProof", (1240.0, 800.0), init, view)
    });
}
