//! Stamp a BUILD IDENTITY into the binary.
//!
//! The broker is a long-lived per-session daemon: the wrapper spawns it once, when a husk
//! session starts, and it serves every submission until that session ends. Reinstalling husk
//! therefore does NOT affect a session that is already running — the old binary keeps
//! generating cage arguments from memory.
//!
//! That cost a real diagnosis round (Balfrin, 2026-08-05): a cage-killing bug was fixed,
//! reinstalled, and verified green by a selftest that spawns its OWN fresh broker — while the
//! human's live session kept failing every ICON job with the fixed error, because its broker
//! predated the install. Nothing in the broker's own log could distinguish the two: it prints
//! `husk 0.4.0`, the crate version, which does not move between builds.
//!
//! So: the git describe at build time, and the build timestamp. Both go into the session
//! banner, which makes "is this broker current?" a fact you read instead of infer.
//! Best-effort — a build outside a git checkout must still succeed.
use std::process::Command;

fn main() {
    let git = Command::new("git")
        .args(["describe", "--always", "--dirty", "--tags"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    let built = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("cargo:rustc-env=HUSK_BUILD_REV={git}");
    println!("cargo:rustc-env=HUSK_BUILD_UNIX={built}");
    // Re-run when HEAD moves, so the stamp cannot go stale inside an incremental build.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
}
