//! Wire types for the broker <-> stub protocol. See ../PROTOCOL.md (v1).
//!
//! Every Request field is adversary-controlled (written by the in-sandbox stub,
//! which runs as the agent). Deserialize defensively and validate in `policy`.
//!
//! # The wire format is stated four times, and this is only one of them
//!
//! `protocol.rs`, `sbatch-stub.py`, `srun-stub.py`, and `selftest.sh`'s `mkreq`, which writes
//! `req-*.json` directly and is a full independent statement of the schema including the
//! `version` field it parameterises. They agree on every field name and type (measured,
//! `B7-8`); what they did not agree on was who VALIDATES, and nothing asserted any of it —
//! this module had **zero tests**. The tests at the bottom of this file are the assert
//! (`P8`): they read the two stubs as text and compare the tables that must match. They need
//! no python3, deliberately — `main.rs`'s `--print-config` records what a shell helper that
//! assumed a python3 on PATH cost the selftest on Santis.
//!
//! `mkreq` is the fourth statement and is NOT covered here: `selftest.sh` is the round's
//! instrument and is changed last, so nothing in this file reaches it.
//!
//! # Which direction each type travels, and what that makes inert
//!
//! `Request` is **deserialize-only**: it is parsed from bytes the agent wrote. `Response` is
//! **serialize-only**: no Rust code has ever read one, and its single reader is the Python
//! stub at the other end. So a serde *deserialization* attribute on `Response` governs
//! nothing — `#[serde(default)]` sat on `Response::stdout` looking like the deserialization
//! contract a reader would come here for, and removing it left 328 of 328 tests green
//! (`B7-8`). It is gone; this paragraph is what a reader should find instead.
//!
//! # `version`: four writers, and until now one reader
//!
//! `policy.rs:101` refuses a request whose version is not this one. `step.rs` deserializes a
//! `Request` and goes straight to `is_valid_id` — there is no version comparison anywhere in
//! it — so the compute half cannot honour `PROTOCOL.md`'s "bump on any incompatible change",
//! and a v2 `srun-stub.py` against a deployed v1 step broker is misread rather than refused.
//! Both stubs now check the version of the RESPONSE, which closes the reverse direction; the
//! request direction has to be closed in `step.rs`.
//!
//! **Do not close it by validating `version` inside a hand-written `Deserialize` for
//! `Request`.** It is the tempting one-file fix and it is wrong: `step.rs::admit` handles a
//! deserialize error by logging and returning WITHOUT writing a response, and `srun-stub.py`
//! waits for a response with no timeout as long as the broker's heartbeat is fresh. A
//! refusal expressed that way turns a misread step into a job that hangs to its walltime —
//! trading a fidelity bug for an availability one, aimed at the operator. The check belongs
//! in `admit`, next to the `is_valid_id` check, and it must answer with
//! `Response::rejected`, which is also what the existing malformed-request and unsafe-id
//! paths should do.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u32 = 1;

/// One brokered command, as written by a stub inside the cage.
///
/// The fields with no `#[serde(default)]` are the ones a request cannot omit: a missing
/// `version` must not default to 0 and be reported as an unsupported version, and a missing
/// `id` must not default to `""` and pass through the id checks. Absence is a parse error,
/// which the spool answers.
#[derive(Debug, Deserialize)]
pub struct Request {
    pub version: u32,
    pub id: String,
    #[serde(default)]
    pub tool: String,
    /// DIAGNOSTIC ONLY, never a decision. Its one consumer is the `eprintln!` in
    /// `spool.rs:129`. Kept because a log line that says when the agent thinks it submitted
    /// is worth having; named as diagnostic because three of this struct's fields look like
    /// they carry policy and do not (`B7-8`), and a reader cannot otherwise tell which.
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
    /// **Diagnostic only, never a decision** — the only consumer is the log line at
    /// `spool.rs:129`. It reads like the field carrying `PROTOCOL.md`'s load-bearing TOCTOU
    /// choice and it is not: what removes the TOCTOU is that `body` is a snapshot the broker
    /// submits on stdin.
    ///
    /// The legal values are NOT listed here. This comment used to name three of them while
    /// both stubs emitted a fourth (`"none"`, on every read-only query and every srun step),
    /// which is `B7-8` in one line — so the list lives in exactly one place,
    /// `tests::SCRIPT_SOURCES`, and the test beside it is what holds the stubs to it.
    pub source: String,
    /// DIAGNOSTIC ONLY, never a decision — same one log line. The name the agent gave its
    /// script has no bearing on what husk submits.
    #[serde(default)]
    pub name: Option<String>,
    /// The load-bearing one: the agent's script, captured as data at submit time.
    #[serde(default)]
    pub body: String,
}

/// The broker's answer. **Serialize-only** — see the module header. Its only reader is the
/// Python stub, so every field name below is a name a stub greps for, and
/// `every_field_the_stubs_read_out_of_a_response_is_one_the_broker_writes` is what keeps a
/// rename from silently becoming `None` at the other end.
#[derive(Debug, Serialize)]
pub struct Response {
    pub version: u32,
    pub id: String,
    pub status: String, // "submitted" | "ok" | "rejected" | "error"
    pub job_id: Option<u64>,
    pub message: String, // human message / stderr for a query
    pub exit_code: i32,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbatch::{Class, REGISTRY};
    use std::collections::BTreeSet;

    /// A stub, as text.
    ///
    /// The stubs are the other end of this wire and the other statement of every table
    /// checked below. Reading them rather than running them is what keeps these tests
    /// offline and free of a python3 on PATH — the dependency that made a `selftest.sh`
    /// helper fail silently on Santis the same day it was written (`main.rs`,
    /// `--print-config`).
    fn stub_source(name: &str) -> String {
        let dir = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/.."));
        let path = dir.join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "could not read {} ({e}). The stubs ship from the directory above this \
                 crate and install-husk.sh installs them beside the broker; a tree without \
                 them is not one this test can pass over in silence.",
                path.display()
            )
        })
    }

    /// The body of a top-level Python assignment `NAME = {` … `}`.
    fn py_block<'a>(src: &'a str, name: &str) -> &'a str {
        let head = format!("\n{name} = {{\n");
        let start = src
            .find(&head)
            .unwrap_or_else(|| panic!("no top-level `{name} = {{` in the stub"))
            + head.len();
        let len = src[start..]
            .find("\n}\n")
            .unwrap_or_else(|| panic!("`{name}` block is not closed by a `}}` at column 0"));
        &src[start..start + len]
    }

    /// Every double-quoted literal in `block`, and whether a `:` follows it — i.e. whether
    /// it is a dict KEY rather than a set member or a value.
    fn py_strings(block: &str) -> Vec<(String, bool)> {
        let mut out = Vec::new();
        let b: Vec<char> = block.chars().collect();
        let mut i = 0;
        while i < b.len() {
            if b[i] == '"' {
                let mut lit = String::new();
                i += 1;
                while i < b.len() && b[i] != '"' {
                    if b[i] == '\\' && i + 1 < b.len() {
                        i += 1;
                    }
                    lit.push(b[i]);
                    i += 1;
                }
                i += 1; // the closing quote
                let mut j = i;
                while j < b.len() && b[j].is_whitespace() {
                    j += 1;
                }
                out.push((lit, j < b.len() && b[j] == ':'));
            } else {
                i += 1;
            }
        }
        out
    }

    fn py_set(src: &str, name: &str) -> BTreeSet<String> {
        py_strings(py_block(src, name)).into_iter().map(|(s, _)| s).collect()
    }

    fn py_dict_keys(src: &str, name: &str) -> BTreeSet<String> {
        py_strings(py_block(src, name))
            .into_iter()
            .filter(|(_, is_key)| *is_key)
            .map(|(s, _)| s)
            .collect()
    }

    /// The text of a top-level Python `def NAME(`, up to the next top-level `def`.
    ///
    /// Empty when the stub has no such function, so a scan restricted to it is empty rather
    /// than wrong — every caller here has a presence anchor for that.
    fn py_function<'a>(src: &'a str, name: &str) -> &'a str {
        let head = format!("\ndef {name}(");
        let Some(at) = src.find(&head) else { return "" };
        let start = at + 1;
        let len = src[start..].find("\ndef ").unwrap_or(src.len() - start);
        &src[start..start + len]
    }

    /// The `int` a Python module assigns to `NAME` at top level.
    fn py_int(src: &str, name: &str) -> u32 {
        let head = format!("\n{name} = ");
        let start = src
            .find(&head)
            .unwrap_or_else(|| panic!("no top-level `{name} = ` in the stub"))
            + head.len();
        let digits: String = src[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
        digits
            .parse()
            .unwrap_or_else(|e| panic!("`{name}` is not an integer literal: {e}"))
    }

    // ---------------------------------------------------------------------------
    // The wire format
    // ---------------------------------------------------------------------------

    /// The version number is one number, in every file that states it.
    ///
    /// `PROTOCOL.md` makes `version` the compatibility mechanism, and it had four writers.
    /// A stub shipped with a different constant would submit requests `policy.rs` refuses
    /// with `unsupported protocol version`, which names the number and not the file.
    ///
    /// DOES NOT COVER: `selftest.sh`'s `mkreq`, the fourth statement of this schema — it
    /// parameterises `version` deliberately, and the selftest is the round's instrument and
    /// is changed last. Nor the REQUEST direction on the compute side: `step.rs` does not
    /// compare versions at all (`B7-8`), and no test here can make it.
    #[test]
    fn the_wire_version_is_one_number_in_every_file_this_crate_can_read() {
        for stub in ["sbatch-stub.py", "srun-stub.py"] {
            let src = stub_source(stub);
            assert_eq!(
                py_int(&src, "PROTOCOL_VERSION"),
                PROTOCOL_VERSION,
                "{stub} speaks a different protocol version from protocol.rs. Every request \
                 it writes would be refused by policy.rs with `unsupported protocol version`."
            );
        }
    }

    /// Every field a stub reads out of a response is a field the broker writes — and the
    /// response has no field neither stub reads.
    ///
    /// `Response` is serialize-only and no Rust code ever reads one, so nothing in this
    /// crate notices a renamed field: at the other end `resp.get("job_id")` simply becomes
    /// `None` and the stub prints `Submitted batch job None`. Both directions are asserted,
    /// because a field added here and read by nobody is the shape `B7-8` found three of.
    ///
    /// DOES NOT COVER: the VALUES. That a stub reads `status` says nothing about it
    /// understanding `"submitted"` vs `"ok"`; the stub harnesses cover that end to end.
    #[test]
    fn every_field_the_stubs_read_out_of_a_response_is_one_the_broker_writes() {
        let value = serde_json::to_value(Response::submitted("id", 1)).unwrap();
        let written: BTreeSet<String> =
            value.as_object().unwrap().keys().cloned().collect();

        let mut read = BTreeSet::new();
        for stub in ["sbatch-stub.py", "srun-stub.py"] {
            let src = stub_source(stub);
            for pat in ["resp.get(\"", "resp[\""] {
                let mut rest = src.as_str();
                while let Some(at) = rest.find(pat) {
                    rest = &rest[at + pat.len()..];
                    let name: String = rest.chars().take_while(|&c| c != '"').collect();
                    read.insert(name);
                }
            }
        }

        // Presence anchor: an empty haystack must not read as agreement. `B7-1` found
        // twenty arms passing on exactly that.
        assert!(
            read.contains("status") && read.len() >= 5,
            "scanned the stubs for response fields and found {read:?} — the scan is broken, \
             which is not the same as the stubs reading nothing"
        );
        for name in &read {
            assert!(
                written.contains(name),
                "a stub reads `{name}` out of a response and Response does not serialize it; \
                 at the other end that is a silent None, not an error. Fields written: \
                 {written:?}"
            );
        }
        for name in &written {
            assert!(
                read.contains(name),
                "Response serializes `{name}` and neither stub reads it. Add a reader or \
                 remove the field — an unread field on this wire is what `B7-8` found three \
                 of, and a reader cannot tell which of them carry a decision."
            );
        }
    }

    /// A request shaped like the one the stubs write parses, and the fields with no
    /// `#[serde(default)]` really are required.
    ///
    /// `version` and `id` must not be defaultable: a missing `version` defaulting to 0 would
    /// be refused as `unsupported protocol version 0`, blaming the agent's schema for a
    /// serializer bug (`P11`), and a missing `id` defaulting to `""` would walk into the
    /// spool's filename handling.
    ///
    /// DOES NOT COVER: that the stubs actually send these fields. The version constant is
    /// tied above; the rest is the stubs' `.test.sh` and `selftest.sh`.
    #[test]
    fn a_request_shaped_like_the_stubs_write_parses_and_omissions_are_errors() {
        let full = r##"{"version":1,"id":"abc","tool":"sbatch","submitted_at":"2026-08-31T00:00:00Z",
            "cwd":"/w","argv":["--time","00:10:00","job.sh"],
            "script":{"source":"file","name":"job.sh","body":"#!/bin/bash\n"},
            "job_args":["7"],"env":{"SLURM_X":"1"}}"##;
        let req: Request = serde_json::from_str(full).expect("the shipped request shape");
        assert_eq!(req.version, PROTOCOL_VERSION);
        assert_eq!(req.script.source, "file");
        assert_eq!(req.argv.len(), 3);

        for missing in ["\"version\":1,", "\"id\":\"abc\",", "\"script\""] {
            let broken = if missing.starts_with("\"script\"") {
                full.replace("\"script\":", "\"scriptX\":")
            } else {
                full.replace(missing, "")
            };
            assert!(
                serde_json::from_str::<Request>(&broken).is_err(),
                "a request without {missing} parsed; that field must not be defaultable"
            );
        }

        // Forward compatibility is deliberate: an unknown field is ignored, so a newer stub
        // adding a field does not break an older broker that has already agreed on version.
        let extra = full.replace("\"tool\":", "\"future_field\":0,\"tool\":");
        assert!(serde_json::from_str::<Request>(&extra).is_ok());
    }

    /// Every `script.source` the stubs emit is one this module documents.
    ///
    /// The Rust comment named three values (`"file" | "wrap" | "stdin"`) while both stubs
    /// emitted a fourth, `"none"`, for every read-only query and every srun step — so the
    /// one enumerated field on this wire had a legal value its own type did not know
    /// (`B7-8`).
    ///
    /// DOES NOT COVER: `PROTOCOL.md`, the fourth statement of this list, which is prose.
    /// Every legal value of `Script::source`, stated ONCE. Test data rather than a `pub
    /// const`, because nothing in production reads it and a `pub` item with no consumer is
    /// the shape this module reports three of.
    const SCRIPT_SOURCES: &[&str] = &["file", "wrap", "stdin", "none"];

    #[test]
    fn every_script_source_the_stubs_emit_is_one_this_module_documents() {
        let documented: BTreeSet<&str> = SCRIPT_SOURCES.iter().copied().collect();
        let mut emitted = BTreeSet::new();
        for stub in ["sbatch-stub.py", "srun-stub.py"] {
            let src = stub_source(stub);
            // Two shapes, and each is scanned where it lives: the literal dict a stub
            // builds for a request, and the tuples `parse_invocation` returns. Scanning
            // `return ("` over the whole file would also catch the first line of every
            // multi-line message string, which is what the first version of this test did.
            for (region, pat) in [
                (src.as_str(), "\"source\": \""),
                (py_function(&src, "parse_invocation"), "return (\""),
            ] {
                let mut rest = region;
                while let Some(at) = rest.find(pat) {
                    rest = &rest[at + pat.len()..];
                    emitted.insert(rest.chars().take_while(|&c| c != '"').collect::<String>());
                }
            }
        }
        assert!(
            emitted.len() >= SCRIPT_SOURCES.len(),
            "scanned the stubs for script sources and found only {emitted:?} — the scan is \
             broken, which is not the same as the stubs emitting nothing"
        );
        for s in &emitted {
            assert!(
                documented.contains(s.as_str()),
                "a stub emits script.source={s:?} and SCRIPT_SOURCES does not list it: \
                 {documented:?}"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // The stub's option tables, against the registry that decides them
    // ---------------------------------------------------------------------------

    /// The sbatch stub's `VALUE_OPTS` is exactly the registry's value-option column.
    ///
    /// It was **16 spellings short** and said it was aligned (`B3-1`). The stub uses the
    /// table to find the script positional, so a missing value option makes the stub take
    /// the option's VALUE for the script: `sbatch --hint nomultithread job.sh` died inside
    /// the login cage with `unable to read batch script nomultithread`, the request never
    /// reached the broker, and the glued `--hint=nomultithread` worked — so the failure read
    /// as a filesystem problem in the one cage where the real sbatch is not present.
    ///
    /// Both directions: a spelling the stub thinks takes a value and the registry does not
    /// would make the stub eat a real script path.
    ///
    /// DOES NOT COVER: `srun-stub.py`, which has no such table because it forwards argv
    /// whole; nor whether the registry itself is complete — an option husk has never heard
    /// of is refused by name, which is `B3-1`'s sibling and not this test's business.
    #[test]
    fn the_stubs_value_option_table_is_the_registrys_value_option_column() {
        let mut want = BTreeSet::new();
        for s in REGISTRY {
            if s.takes_value {
                want.insert(s.long.to_string());
                if !s.short.is_empty() {
                    want.insert(s.short.to_string());
                }
            }
        }
        let have = py_set(&stub_source("sbatch-stub.py"), "VALUE_OPTS");
        let missing: Vec<_> = want.difference(&have).collect();
        let extra: Vec<_> = have.difference(&want).collect();
        assert!(
            missing.is_empty(),
            "sbatch-stub.py's VALUE_OPTS is missing {} value option(s) the registry accepts: \
             {missing:?}. In the login cage the SEPARATED form of each dies with `unable to \
             read batch script <value>` and never reaches the broker.",
            missing.len()
        );
        assert!(
            extra.is_empty(),
            "sbatch-stub.py's VALUE_OPTS claims {extra:?} take a value and the registry does \
             not; the stub would swallow the script path after one of them."
        );
    }

    /// Every `Class::Ignored` spelling has a disposition in the sbatch stub, and only one.
    ///
    /// An Ignored option is either dropped — and then the caller is told, `UNAPPLIED` — or
    /// honoured by the stub itself, `HONOURED_LOCALLY`. The registry is where the class is
    /// decided and the stub is its **third** consumer, the one
    /// `the_shipped_skill_matches_the_generated_option_contract` cannot reach (`C1-4`,
    /// `C1-5`): before this test, moving an option into `Class::Ignored` left the stub
    /// silent, which is the silent drop that cost a run when `--parsable` was dropped and an
    /// hour when `#SBATCH` resource options were.
    ///
    /// DOES NOT COVER: the REASON strings, which are hand-written; nor the generated skill's
    /// claim that every option in this class announces itself, which is false for `--quiet`
    /// / `-Q` and lives in `option_contract_markdown()` (`C1-5`, see FIX-I).
    #[test]
    fn every_ignored_option_has_a_disposition_in_the_sbatch_stub() {
        let mut ignored = BTreeSet::new();
        for s in REGISTRY {
            if s.class == Class::Ignored {
                ignored.insert(s.long.to_string());
                if !s.short.is_empty() {
                    ignored.insert(s.short.to_string());
                }
            }
        }
        assert!(!ignored.is_empty(), "no Class::Ignored entries — the scan is broken");

        let src = stub_source("sbatch-stub.py");
        let unapplied = py_dict_keys(&src, "UNAPPLIED");
        let honoured = py_dict_keys(&src, "HONOURED_LOCALLY");

        let overlap: Vec<_> = unapplied.intersection(&honoured).collect();
        assert!(
            overlap.is_empty(),
            "{overlap:?} is both dropped-and-announced and honoured-by-the-stub; one option, \
             two dispositions, and the caller gets whichever the code reaches first"
        );

        let covered: BTreeSet<String> = unapplied.union(&honoured).cloned().collect();
        let uncovered: Vec<_> = ignored.difference(&covered).collect();
        assert!(
            uncovered.is_empty(),
            "{uncovered:?} is Class::Ignored in the registry and the stub says nothing about \
             it. Put it in UNAPPLIED with the reason the caller needs, or in \
             HONOURED_LOCALLY with what the stub does instead — a silent drop is the \
             failure both tables exist to prevent (P13)."
        );
        let stale: Vec<_> = covered.difference(&ignored).collect();
        assert!(
            stale.is_empty(),
            "{stale:?} has a disposition in the stub and is no longer Class::Ignored; the \
             stub would announce something that is now forced, allowed or refused"
        );
    }
}
