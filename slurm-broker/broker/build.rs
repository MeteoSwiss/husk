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
//!
//! NO `cargo:rerun-if-*` DIRECTIVE HERE, DELIBERATELY — the whole class, not just
//! `rerun-if-changed`. Emitting even one of them REPLACES cargo's default trigger ("re-run
//! when any file in this package changed") with exactly what the directive names, and
//! `cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH` — the standard reproducible-builds idiom
//! for a file that stamps a timestamp — freezes the stamp just as thoroughly as a path
//! does (`RB-4`, measured). This file used to list `../../.git/HEAD` and `../../.git/index`
//! under the comment "so the stamp cannot go stale inside an incremental build"; measured
//! (`B8-4`, re-measured by `D1`), those two lines were the whole of the defect. Editing a
//! source file changes neither path, so the crate recompiled while both halves of the stamp —
//! including the `--dirty` marker whose only job is to say "this binary is not from a commit" —
//! kept the PREVIOUS build's values. Worse than stale: `git describe --dirty` itself rewrites
//! `.git/index`, so whether the stamp was fresh depended on whether any index-touching git
//! command happened since the last build, with nothing distinguishing the two cases.
//!
//! Cargo's default is exactly the trigger the CODE half of this stamp wants — it re-runs
//! precisely when a package file changed, which is precisely when the binary changed — and
//! it is free: a no-change `cargo build` stays a 0.03 s no-op, measured. It is not the
//! trigger the REPOSITORY half wants: `git commit` and `git tag` change what `git describe`
//! prints without touching one byte of this package, so an ordinary `cargo build` can carry
//! a rev the repository has already moved past. `build-release.sh` touches this file to
//! close that on the release path, and the release gate compares the COMMIT below rather
//! than the describe, because the commit is the same fact on every machine (`RB-3`). Outside a git checkout (release
//! tarball, or a git worktree where `.git` is a file) the default also just works, where the
//! old directives made cargo treat a missing path as always-changed and re-run every time.
//!
//! `build_identity.rs` holds the consumer side and the two tests that keep this honest.
use std::process::Command;

fn git(args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    // WHICH repository is answering? `git` answers about the repo containing the current
    // directory, which is not the same question as "what does git say about THIS package".
    // Unpack a release tarball — which correctly stamps `unknown` on its own — under a home
    // directory that is itself a git repo (a dotfiles repo is enough) and `cargo build`
    // stamps that repo's HEAD: forty hex characters that look exactly like provenance,
    // printed by the session banner this whole stamp exists to make trustworthy. `unknown`
    // is the honest answer there and every consumer already handles it (`RB2-6`, measured;
    // `P15` — a control names a target, check the name resolves to the object you meant).
    //
    // Asking whether the answering repo TRACKS this build script is the cheap form of that
    // question, and it is exactly right in the shapes that matter: true in a clone, a
    // shallow clone, a detached HEAD and a linked worktree; false in an export dropped
    // inside someone else's checkout. install-husk.sh guards its half of the same hazard in
    // the same pass, on `.git` being present in the husk directory itself.
    let this_repo_tracks_this_package =
        git(&["ls-files", "--error-unmatch", "--", "build.rs"]) != "unknown";

    // What a human reads: the nearest tag, how far past it, and whether the tree was dirty.
    //
    // `--dirty=^dirty` rather than `--dirty`, because the marker is a DECISION below and
    // `-dirty` is a string a tag can spell. `git check-ref-format` forbids `^` in a refname,
    // so no tag, no `--always` object-name fallback and no `<tag>-<n>-g<sha>` rendering can
    // produce this suffix; only git appending it can. With the plain marker, a clean tree
    // whose HEAD carried a tag named `v0.5-dirty` stamped `<commit>-dirty`, and
    // make-release.sh then refused the release for uncommitted changes that did not exist,
    // with nothing to stash (`RB2-8`, measured). `rev` is put back into its familiar
    // spelling immediately, so the banner and the release transcript are unchanged.
    let raw = if this_repo_tracks_this_package {
        git(&["describe", "--always", "--dirty=^dirty", "--tags"])
    } else {
        "unknown".to_string()
    };
    let dirty = raw.ends_with("^dirty");
    let rev = match raw.strip_suffix("^dirty") {
        Some(clean) => format!("{clean}-dirty"),
        None => raw.clone(),
    };

    // What a machine compares. `git describe --tags` is resolved against the tags THIS clone
    // happens to hold, so the same commit built on Balfrin and on Santis produces different
    // strings whenever one of them has not fetched the tag yet — and the release gate then
    // refuses a binary that IS this commit, telling the operator to rebuild it, which
    // produces the same stamp again (`RB-3`, measured). An object name is not a matter of
    // local state, so that is what the gate matches on.
    //
    // `-dirty` rides along from the describe above rather than costing a `git status`, so
    // the one field the gate compares also says "built from an uncommitted tree" — but it
    // rides on the unforgeable marker, not on the end of the human string. If the describe
    // could not be produced at all (no git, no checkout, another repo's checkout) we do not
    // claim to know the commit either: the gate must fail closed rather than on half a fact
    // (`P7`).
    //
    // COST, stated because the commit message for `c90cb74` got this wrong (`RB2-12`): this
    // build script runs `git` THREE times — ls-files, describe, rev-parse — where before
    // `RB-3` it ran one. The claim "no second git call" was about not paying a THIRD call
    // for dirtiness, which is true and is still true; the sentence as written was not.
    // Measured cost of the extra processes is a few milliseconds, once per build-script
    // run, and cargo re-runs the build script only when a package file changed.
    let commit = if rev == "unknown" {
        "unknown".to_string()
    } else {
        let head = git(&["rev-parse", "HEAD"]);
        match (dirty, head.as_str()) {
            (_, "unknown") => "unknown".to_string(),
            (true, h) => format!("{h}-dirty"),
            (false, h) => h.to_string(),
        }
    };

    let built = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("cargo:rustc-env=HUSK_BUILD_REV={rev}");
    println!("cargo:rustc-env=HUSK_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=HUSK_BUILD_UNIX={built}");
}
