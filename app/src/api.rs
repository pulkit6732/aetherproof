//! Talks to `aetherproof serve` on 127.0.0.1. Every call runs on a `Latest` worker, never
//! on the UI thread. The bearer token is read from the AetherProof home, where the server
//! writes it on start.

use serde_json::{Value, json};
use std::path::PathBuf;

pub const BASE: &str = "http://127.0.0.1:8787";

/// What the UI asked for. Each action refreshes status and the instruction list afterwards,
/// so one answer carries everything the screens need (`Latest` keeps only the newest answer).
#[derive(Clone, Debug)]
pub enum Action {
    Refresh,
    Sign(Value),
    Verify(Value),
    Reconcile(Value),
    Checkpoint,
    VerifyCheckpoints,
    Demo,
}

#[derive(Debug, Default)]
pub struct Reply {
    pub status: Option<Value>,
    pub instructions: Vec<Value>,
    pub signed: Option<Value>,
    pub decision: Option<Value>,
    pub report: Option<Value>,
    pub checkpoints: Option<Vec<Value>>,
    pub notice: Option<(bool, String)>,
    pub offline: bool,
}

fn home() -> PathBuf {
    if let Ok(h) = std::env::var("AETHERPROOF_HOME") {
        return PathBuf::from(h);
    }
    let base = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")).unwrap_or_default();
    PathBuf::from(base).join(".aetherproof")
}

fn token() -> Result<String, String> {
    std::fs::read_to_string(home().join("api_token"))
        .map(|t| t.trim().to_owned())
        .map_err(|_| "No API token. Start the backend: aetherproof serve".to_owned())
}

fn call(method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
    let auth = format!("Bearer {}", token()?);
    let req = ureq::request(method, &format!("{BASE}{path}")).set("Authorization", &auth).timeout(std::time::Duration::from_secs(20));
    let res = match body {
        Some(b) => req.send_json(b.clone()),
        None => req.call(),
    };
    match res {
        Ok(r) => r.into_json::<Value>().map_err(|e| format!("bad reply: {e}")),
        Err(ureq::Error::Status(_, r)) => {
            let v: Value = r.into_json().unwrap_or_default();
            Err(v["error"].as_str().unwrap_or("request failed").to_owned())
        }
        Err(_) => Err("Backend not reachable on 127.0.0.1:8787. Run: aetherproof serve".to_owned()),
    }
}

/// Runs on a worker thread.
pub fn run(action: Action) -> Reply {
    let mut out = Reply::default();
    let result = match &action {
        Action::Refresh => Ok(None),
        Action::Sign(b) => call("POST", "/api/instructions", Some(b)).map(|v| {
            out.signed = Some(v["instruction"].clone());
            Some((true, format!("Signed {}", v["instruction"]["instruction_id"].as_str().unwrap_or(""))))
        }),
        Action::Verify(b) => call("POST", "/api/verify", Some(b)).map(|v| {
            out.decision = Some(v["decision"].clone());
            None
        }),
        Action::Reconcile(b) => call("POST", "/api/payouts/reconcile", Some(b)).map(|v| {
            out.report = Some(v["report"].clone());
            None
        }),
        Action::Checkpoint => call("POST", "/api/checkpoints", Some(&json!({}))).map(|v| {
            Some((true, format!("Checkpoint of {} entries saved", v["checkpoint"]["log_size"])))
        }),
        Action::VerifyCheckpoints => Ok(None),
        Action::Demo => call("POST", "/api/demo", Some(&json!({}))).and_then(|seed| {
            let body = json!({"path": seed["payouts_path"], "source": seed["source"]});
            call("POST", "/api/payouts/reconcile", Some(&body)).map(|v| {
                out.report = Some(v["report"].clone());
                Some((true, "Demo seeded: 4 approved disbursals, 6 payouts".to_owned()))
            })
        }),
    };
    match result {
        Ok(n) => out.notice = n,
        Err(e) => {
            out.offline = e.starts_with("Backend not reachable") || e.starts_with("No API token");
            out.notice = Some((false, e));
            return out;
        }
    }
    if let Ok(s) = call("GET", "/api/status", None) {
        out.status = Some(s);
    }
    if let Ok(v) = call("GET", "/api/instructions", None) {
        out.instructions = v["instructions"].as_array().cloned().unwrap_or_default();
    }
    if matches!(action, Action::Checkpoint | Action::VerifyCheckpoints | Action::Refresh) {
        if let Ok(v) = call("GET", "/api/checkpoints/verify", None) {
            out.checkpoints = v["checkpoints"].as_array().cloned();
        }
    }
    out
}
