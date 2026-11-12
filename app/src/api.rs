//! Talks to `aetherproof serve` (`/api/v1`, contract v1) on 127.0.0.1. Every call runs on a
//! `Latest` worker, never on the UI thread. The bearer token is read from the AetherProof
//! home, where the server writes it on start; it is never shown or logged.

use serde_json::{Value, json};
use std::path::PathBuf;

pub const BASE: &str = "http://127.0.0.1:8787/api/v1";

/// What the UI asked for. Each action refreshes status, instructions and runs afterwards,
/// so one answer carries everything the screens need.
#[derive(Clone, Debug)]
pub enum Action {
    Refresh,
    Sign(Value),
    Verify(Value),
    Reconcile(Value),
    OpenRun(String),
    Checkpoint,
    VerifyCheckpoints,
    Demo,
    ExportEvidence(String),
}

impl Action {
    /// The words shown while the action is in flight.
    pub fn label(&self) -> &'static str {
        match self {
            Action::Refresh => "Refreshing",
            Action::Sign(_) => "Signing the instruction",
            Action::Verify(_) => "Checking the payout",
            Action::Reconcile(_) => "Verifying payouts",
            Action::OpenRun(_) => "Opening the run",
            Action::Checkpoint => "Signing a checkpoint",
            Action::VerifyCheckpoints => "Verifying checkpoints",
            Action::Demo => "Seeding the DEMO replay",
            Action::ExportEvidence(_) => "Sealing the evidence package",
        }
    }
}

#[derive(Debug, Default)]
pub struct Reply {
    pub status: Option<Value>,
    pub instructions: Vec<Value>,
    pub runs: Option<Vec<Value>>,
    pub signed: Option<Value>,
    pub decision: Option<Value>,
    pub report: Option<Value>,
    pub run_id: Option<String>,
    pub checkpoints: Option<Vec<Value>>,
    /// Ok(message) or Err(message) for the action itself; None for a plain refresh.
    pub outcome: Option<Result<String, String>>,
    pub offline: bool,
    pub at_unix_s: u64,
}

fn home() -> PathBuf {
    if let Ok(h) = std::env::var("AETHERPROOF_HOME") {
        return PathBuf::from(h);
    }
    let base = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default();
    PathBuf::from(base).join(".aetherproof")
}

/// Shown with the user's home folder as `~`: screenshots of this screen get shared.
pub fn token_path() -> String {
    let full = home().join("api_token").display().to_string();
    match std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        Ok(h) if !h.is_empty() && full.starts_with(&h) => format!("~{}", &full[h.len()..]),
        _ => full,
    }
}

fn token() -> Result<String, String> {
    std::fs::read_to_string(home().join("api_token"))
        .map(|t| t.trim().to_owned())
        .map_err(|_| "No API token. Start the backend: aetherproof serve".to_owned())
}

fn call(method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
    let auth = format!("Bearer {}", token()?);
    let req = ureq::request(method, &format!("{BASE}{path}"))
        .set("Authorization", &auth)
        .timeout(std::time::Duration::from_secs(30));
    let res = match body {
        Some(b) => req.send_json(b.clone()),
        None => req.call(),
    };
    match res {
        Ok(r) => r.into_json::<Value>().map_err(|e| format!("bad reply: {e}")),
        Err(ureq::Error::Status(_, r)) => {
            let v: Value = r.into_json().unwrap_or_default();
            let code = v["error"]["code"].as_str().unwrap_or("error");
            let msg = v["error"]["message"].as_str().unwrap_or("request failed");
            Err(format!("{msg} [{code}]"))
        }
        Err(_) => Err("Backend not reachable on 127.0.0.1:8787. Run: aetherproof serve".to_owned()),
    }
}

/// Runs on a worker thread.
pub fn run(action: Action) -> Reply {
    let mut out = Reply {
        at_unix_s: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
        ..Reply::default()
    };
    let take_run = |v: &Value, out: &mut Reply| {
        out.report = Some(v["report"].clone());
        out.run_id = v["run_id"].as_str().map(str::to_owned);
    };
    let result: Result<Option<String>, String> = match &action {
        Action::Refresh | Action::VerifyCheckpoints => Ok(None),
        Action::Sign(b) => call("POST", "/instructions", Some(b)).map(|v| {
            let id = v["instruction"]["instruction_id"].as_str().unwrap_or("").to_owned();
            out.signed = Some(v["instruction"].clone());
            Some(format!("Signed {id}. Its id is filled into the Payment gate."))
        }),
        Action::Verify(b) => call("POST", "/verify", Some(b)).map(|v| {
            out.decision = Some(v["decision"].clone());
            Some(format!("Gate decision: {}", v["decision"]["verdict"].as_str().unwrap_or("?").to_uppercase()))
        }),
        Action::Reconcile(b) => call("POST", "/payouts/reconcile", Some(b)).map(|v| {
            take_run(&v, &mut out);
            Some(format!("Run {} {}", v["run_id"].as_str().unwrap_or(""), if v["replayed"] == true { "(same inputs: stored run reopened)" } else { "saved" }))
        }),
        Action::OpenRun(id) => call("GET", &format!("/runs/{id}"), None).map(|v| {
            take_run(&v, &mut out);
            Some(format!("Opened {id}"))
        }),
        Action::Checkpoint => call("POST", "/checkpoints", Some(&json!({})))
            .map(|v| Some(format!("Checkpoint of {} entries saved", v["checkpoint"]["log_size"]))),
        Action::ExportEvidence(id) => call("POST", &format!("/runs/{id}/evidence"), Some(&json!({})))
            .map(|v| Some(format!("Evidence package signed and saved: {}", v["path"].as_str().unwrap_or("")))),
        Action::Demo => call("POST", "/demo", Some(&json!({}))).and_then(|seed| {
            let body = json!({"path": seed["payouts_path"], "source": seed["source"], "statement_path": seed["statement_path"],
                              "settlement_grace_minutes": seed["settlement_grace_minutes"]});
            call("POST", "/payouts/reconcile", Some(&body)).map(|v| {
                take_run(&v, &mut out);
                Some("DEMO replay seeded: 5 approved disbursals, 7 payouts, 1 bank statement".to_owned())
            })
        }),
    };
    match result {
        Ok(msg) => out.outcome = msg.map(Ok),
        Err(e) => {
            out.offline = e.starts_with("Backend not reachable") || e.starts_with("No API token");
            out.outcome = Some(Err(e));
            return out;
        }
    }
    if let Ok(s) = call("GET", "/status", None) {
        out.status = Some(s);
    }
    if let Ok(v) = call("GET", "/instructions", None) {
        out.instructions = v["instructions"].as_array().cloned().unwrap_or_default();
    }
    if let Ok(v) = call("GET", "/runs", None) {
        out.runs = v["runs"].as_array().cloned();
    }
    if matches!(action, Action::Checkpoint | Action::VerifyCheckpoints | Action::Refresh)
        && let Ok(v) = call("GET", "/checkpoints/verify", None)
    {
        out.checkpoints = v["checkpoints"].as_array().cloned();
    }
    out
}
