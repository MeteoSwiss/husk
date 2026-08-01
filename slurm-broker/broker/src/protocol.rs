//! Wire types for the broker <-> stub protocol. See ../PROTOCOL.md (v1).
//!
//! Every Request field is adversary-controlled (written by the in-sandbox stub,
//! which runs as the agent). Deserialize defensively and validate in `policy`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub version: u32,
    pub id: String,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub submitted_at: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default)]
    pub argv: Vec<String>,
    pub script: Script,
    #[serde(default)]
    pub job_args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct Script {
    pub source: String, // "file" | "wrap" | "stdin"
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub body: String,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub version: u32,
    pub id: String,
    pub status: String, // "submitted" | "ok" | "rejected" | "error"
    pub job_id: Option<u64>,
    pub message: String, // human message / stderr for a query
    pub exit_code: i32,
    #[serde(default)]
    pub stdout: String, // captured stdout for a read-only query ("ok")
}

impl Response {
    pub fn submitted(id: &str, job_id: u64) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            id: id.to_string(),
            status: "submitted".into(),
            job_id: Some(job_id),
            message: String::new(),
            exit_code: 0,
            stdout: String::new(),
        }
    }

    /// Attach advice to an otherwise successful response. The stub writes it to STDERR,
    /// so stdout stays the bare `Submitted batch job N` that tooling parses — the same
    /// split real sbatch uses for its own warnings.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.message = note.into();
        self
    }

    /// A read-only query result (Tier-1 SLURM commands run by the broker).
    pub fn query(id: &str, stdout: String, stderr: String, exit_code: i32) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            id: id.to_string(),
            status: "ok".into(),
            job_id: None,
            message: stderr,
            exit_code,
            stdout,
        }
    }

    pub fn rejected(id: &str, message: impl Into<String>) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            id: id.to_string(),
            status: "rejected".into(),
            job_id: None,
            message: message.into(),
            exit_code: 1,
            stdout: String::new(),
        }
    }

    pub fn error(id: &str, message: impl Into<String>) -> Self {
        Response {
            version: PROTOCOL_VERSION,
            id: id.to_string(),
            status: "error".into(),
            job_id: None,
            message: message.into(),
            exit_code: 1,
            stdout: String::new(),
        }
    }
}
