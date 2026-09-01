//! The consumer side of `build.rs`'s build stamp — and the two tests that keep it honest.
//!
//! `build.rs` explains WHY the stamp exists (Balfrin 2026-08-05: a fixed bug kept failing in a
//! live session because the session's broker predated the install, and nothing in its log could
//! say so). This module decides HOW it is carried, and there is one design decision worth the
//! paragraph:
//!
//! **The stamp is ONE string literal, in a delimited form a release gate can extract from a
//! binary it cannot execute.** `make-release.sh` ships four binaries, two of them for the other
//! architecture, and before this they had no provenance check of any kind — `B8-5` planted
//! binaries that printed `STALE-BINARY-FROM-AN-OLDER-COMMIT` and the release said `[ok]`. A
//! foreign-arch binary cannot be run, so the check has to read the file. `strings`-grepping for
//! a bare `v0.5.0` is a false friend of exactly the class `B8-8` names: it is a substring of
//! `v0.5.0-dirty` and of the crate version, so a dirty binary passes a gate expecting the clean
//! tag. A delimiter makes the match exact.
//!
//! The banner reads its text back OUT of that same literal rather than from a second
//! `env!()` (`P8`): the bytes the release gate greps are the bytes the operator reads at
//! session start, so the two cannot disagree about which build this is.

/// The whole build identity, in one greppable literal:
/// `husk-build-stamp{<unix>|<commit>|<rev>}`.
///
/// * `<unix>` — build time in seconds. Decimal digits, produced here.
/// * `<commit>` — `git rev-parse HEAD`, plus `-dirty` when the tree was not clean, or
///   `unknown`. This is what `make-release.sh` matches on: it is the same string on every
///   machine, where `git describe --tags` is whatever the local clone's tags make it
///   (`RB-3`).
/// * `<rev>` — `git describe --always --dirty --tags`, for humans.
///
/// **The field ORDER is the encoding, and it is what makes the decode total.** The previous
/// layout put the describe first and claimed the delimiters were safe because "git refnames
/// exclude `|` and `}`". They do not: `git check-ref-format` accepts `v0.5|x`, `v0.5}x` and
/// `v0.5{x}`, and a real tag containing `|` truncated `rev()` and sent `built_unix()` to its
/// `0` fallback (`RB-7`, measured). So no claim is made about the describe at all. It is
/// LAST, and the two fields before it cannot contain a delimiter by construction — a
/// decimal timestamp and an object name — so `split_stamp` splits on the two `|` this
/// module wrote and hands the rest, whatever it contains, back verbatim.
///
/// `make-release.sh` matches the fixed prefix `husk-build-stamp{<digits>|<commit>|` and never
/// parses the describe, so it is total for the same reason. If this format is ever changed
/// the gate finds nothing and the release FAILS, rather than passing on a match it never
/// made (`P7`).
pub const STAMP: &str = concat!(
    "husk-build-stamp{",
    env!("HUSK_BUILD_UNIX"),
    "|",
    env!("HUSK_BUILD_COMMIT"),
    "|",
    env!("HUSK_BUILD_REV"),
    "}"
);

const OPEN: &str = "husk-build-stamp{";

/// Total: any `<rev>`, including one holding `|`, `{` or `}`, comes back verbatim.
fn split_stamp(stamp: &str) -> (&str, &str, &str) {
    let Some(inner) = stamp.strip_prefix(OPEN).and_then(|s| s.strip_suffix('}')) else {
        return ("0", "unknown", "unknown");
    };
    // `splitn(3, ..)` stops splitting after the second delimiter, so the describe keeps
    // every `|` it may contain.
    let mut it = inner.splitn(3, '|');
    match (it.next(), it.next(), it.next()) {
        (Some(unix), Some(commit), Some(rev)) => (unix, commit, rev),
        _ => ("0", "unknown", "unknown"),
    }
}

fn fields() -> (&'static str, &'static str, &'static str) {
    split_stamp(STAMP)
}

/// `git describe` at build time — what the session banner prints.
pub fn rev() -> &'static str {
    fields().2
}

/// The commit this binary was built from (`-dirty` if the tree was not clean, or `unknown`)
/// — what the release gate matches, because it does not depend on local tag state.
pub fn commit() -> &'static str {
    fields().1
}

/// Build time, seconds since the epoch; `0` if the stamp could not be produced.
pub fn built_unix() -> u64 {
    fields().0.parse().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn manifest_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// The delimited form the release gate depends on, asserted where it is produced.
    #[test]
    fn the_stamp_round_trips_through_its_delimiters() {
        assert!(
            STAMP.starts_with(OPEN) && STAMP.ends_with('}'),
            "make-release.sh greps for the literal prefix {OPEN:?}; STAMP is {STAMP:?}"
        );
        assert_eq!(rev(), env!("HUSK_BUILD_REV"), "rev() must recover the git describe verbatim");
        assert_eq!(commit(), env!("HUSK_BUILD_COMMIT"), "commit() must recover it verbatim");
        assert_eq!(
            built_unix().to_string(),
            env!("HUSK_BUILD_UNIX"),
            "built_unix() must recover the build timestamp verbatim"
        );
        assert!(!rev().is_empty(), "an empty rev would make the release gate match everything");
        assert!(!commit().is_empty(), "an empty commit would make the release gate match everything");
    }

    /// The field ORDER is the encoding (`RB-7`). Assert the layout, not a claim about git.
    ///
    /// `make-release.sh` extracts `husk-build-stamp{<digits>|<commit>|` with a regex and then
    /// compares a FIXED string. That is only exact while the two leading fields cannot hold a
    /// delimiter — which is true by construction and false for the git describe, since
    /// `git check-ref-format` accepts `|`, `{` and `}` in a tag name. Put the describe last
    /// and the question never arises; put it first, as the original did, and one legitimate
    /// tag silently truncates every consumer.
    #[test]
    fn only_the_last_field_of_the_stamp_may_contain_a_delimiter() {
        let inner = STAMP
            .strip_prefix(OPEN)
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or_else(|| panic!("STAMP is not {OPEN}...}}: {STAMP:?}"));
        let (unix, rest) = inner
            .split_once('|')
            .unwrap_or_else(|| panic!("STAMP has no field separator: {STAMP:?}"));
        assert!(
            !unix.is_empty() && unix.bytes().all(|b| b.is_ascii_digit()),
            "the FIRST field must be the decimal build time, not the git describe: it is the \
             anchor that lets make-release.sh find the stamp without parsing a string git \
             lets a tag fill with '|', '{{' or '}}'. First field is {unix:?} in {STAMP:?}"
        );
        let (commit_field, _describe) = rest
            .split_once('|')
            .unwrap_or_else(|| panic!("STAMP has no second field separator: {STAMP:?}"));
        assert!(
            !commit_field.contains(['|', '{', '}']),
            "the SECOND field is the one the release gate matches on, so it must hold no \
             delimiter: {commit_field:?} in {STAMP:?}"
        );
    }

    /// The decode, exercised over the strings git actually permits — no tag required.
    ///
    /// The original defect was found by creating a real tag `v9.9|rb`, which is an expensive
    /// way to test a pure function and leaves a tag behind. This asserts the same property on
    /// synthetic input, so it runs everywhere and cannot be skipped for want of a tag.
    #[test]
    fn the_stamp_decode_is_total_for_every_describe_git_permits() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        for describe in [
            "v0.5.0",
            "v0.4-429-g4f1c9ed",
            "v0.5.0-dirty",
            "4f1c9ed",
            "unknown",
            "v9.9|rb",   // git check-ref-format: LEGAL
            "v0.5}rc1",  // LEGAL
            "v0.5{rc1}", // LEGAL
            "|}{|",      // the pathological case, still verbatim
        ] {
            let stamp = format!("{OPEN}1788179718|{commit}|{describe}}}");
            let (u, c, r) = split_stamp(&stamp);
            assert_eq!(u, "1788179718", "build time lost decoding {stamp:?}");
            assert_eq!(c, commit, "commit lost decoding {stamp:?}");
            assert_eq!(r, describe, "the release gate and the banner would disagree: {stamp:?}");
        }
        // A stamp that is not a stamp decodes to values no gate can mistake for a match.
        assert_eq!(split_stamp("not a stamp"), ("0", "unknown", "unknown"));
        assert_eq!(split_stamp("husk-build-stamp{1788}"), ("0", "unknown", "unknown"));
    }

    /// `B8-4`, pinned at the level of the defect: the defect WAS these directives.
    ///
    /// This is the deterministic half, and it is the one that survives a clean CI checkout.
    /// `the_stamp_is_not_older_than_the_source_it_was_built_from` below is the functional
    /// half, but it can only fail on a SECOND build — on a fresh clone the first build always
    /// runs the build script, so a CI that clones and builds would stay green with the bug
    /// reinstated. Hence both: this one names the mechanism, that one names the property.
    #[test]
    fn build_rs_emits_no_rerun_if_directive_of_any_spelling() {
        let build_rs = manifest_dir().join("build.rs");
        let src = std::fs::read_to_string(&build_rs)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", build_rs.display()));
        // Ignore the header comment, which explains at length why the directive is absent.
        let offenders: Vec<&str> = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains("rerun-if"))
            .collect();
        assert!(
            offenders.is_empty(),
            "build.rs emits {offenders:?}. Emitting ANY cargo:rerun-if-* directive — \
             rerun-if-changed, rerun-if-env-changed, or a spelling cargo adds later — \
             replaces cargo's default (\"re-run when any package file changed\") with exactly \
             what that directive names, so the stamp freezes across ordinary source edits \
             while the binary is rebuilt, including the -dirty marker that exists to say the \
             binary is not from a commit. That is B8-4. Matching only the one spelling made \
             this gate a denylist of length one (`P5`): the reproducible-builds idiom \
             rerun-if-env-changed=SOURCE_DATE_EPOCH reinstated B8-4 verbatim and this test \
             stayed green (`RB-4`). If a narrower trigger is genuinely needed, it must at \
             minimum include this package's sources, and this test must be rewritten to \
             assert THAT."
        );
    }

    /// The property the stamp claims: it is not older than the code it was built from.
    ///
    /// Cargo re-runs the build script exactly when a package file changed, so after any edit
    /// the stamp must post-date every source file. With the two `rerun-if-changed` lines back
    /// in place this fails on the first `cargo test` after a source edit — measured.
    ///
    /// **It looks at this package's sources and nothing else, and that is the fix for
    /// `RB-2`.** The first version walked `src/` and then the whole manifest directory "for
    /// `build.rs`" — but the walk recurses, so it descended `target/`, where dependency build
    /// scripts write generated `.rs` files. An ordinary `cargo clean -p serde_core` then made
    /// this test red and blamed `B8-4` or a clock skew that did not exist, and because
    /// `make-release.sh` runs this suite as a hard gate, that aborted the release. A check
    /// must not accuse the wrong thing (`P11`) — least of all in the commit that cites `P11`
    /// as its reason for refusing skips.
    ///
    /// `P10`, what it therefore cannot see: a package file outside `src/`, `tests/` and
    /// `build.rs` (a `benches/` or `examples/` dir, were one added) does not move this
    /// check. Cargo still rebuilds and re-stamps on such an edit; it is only the proof that
    /// narrows, and the alternative — trusting a recursive walk not to wander into generated
    /// output — is what produced the false accusation.
    #[test]
    fn the_stamp_is_not_older_than_the_source_it_was_built_from() {
        let root = manifest_dir();
        let mut newest = 0u64;
        let mut newest_path = PathBuf::new();
        let mut seen = 0usize;

        fn consider(p: &Path, newest: &mut u64, newest_path: &mut PathBuf, seen: &mut usize) {
            let Ok(secs) = std::fs::metadata(p).and_then(|m| m.modified()).map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }) else {
                return;
            };
            *seen += 1;
            if secs > *newest {
                *newest = secs;
                *newest_path = p.to_path_buf();
            }
        }

        fn walk(dir: &Path, newest: &mut u64, newest_path: &mut PathBuf, seen: &mut usize) {
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, newest, newest_path, seen);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    consider(&p, newest, newest_path, seen);
                }
            }
        }

        walk(&root.join("src"), &mut newest, &mut newest_path, &mut seen);
        walk(&root.join("tests"), &mut newest, &mut newest_path, &mut seen);
        consider(&root.join("build.rs"), &mut newest, &mut newest_path, &mut seen);

        // P10: say what this harness cannot see. If it found no sources it is measuring
        // nothing, and a test that measures nothing must not report success.
        assert!(seen > 0, "found no .rs files under {} — this test would be vacuous", root.display());

        let stamped = built_unix();
        assert!(
            stamped >= newest,
            "build stamp {stamped} predates {} (mtime {newest}) by {}s, so this binary was \
             compiled from source the stamp does not describe. That file is one of this \
             package's own sources (src/, tests/ or build.rs — generated output under \
             target/ is deliberately not consulted). Either a cargo:rerun-if-* directive is \
             narrowing the build script's trigger again (B8-4), or that file was written \
             after the build — an edit during the test run, or an mtime in the future from \
             clock skew on a network filesystem (check `date` against the file server).",
            newest_path.display(),
            newest - stamped
        );
    }

    // ── the shell gates that consume this stamp ─────────────────────────────
    //
    // The stamp is half a contract: `build.rs` writes it and `make-release.sh` and
    // `install-husk.sh` READ it, out of a binary they cannot execute, with a regex. Every
    // defect in this area so far has been in the reading half, and nothing in the tree
    // looked at it — `RB2-9` found that `4f1c9ed`'s extraction would have refused every
    // correct release binary, and the only reason it does not today is a string-pool
    // layout no test asserts.
    //
    // So the tests below run the REAL shell functions, extracted from the real scripts by
    // name, rather than a Rust re-implementation of what they are believed to do. Two
    // lists of the same thing drift; make one assert the other (`P8`). If a function is
    // renamed or reformatted these go red with a message saying so, which is the correct
    // outcome: this file's claims about those gates would no longer be checked.

    /// Extract one shell function verbatim, by name, from a script in the repo root.
    ///
    /// The convention these scripts follow is `name() {` … `}` with the closing brace in
    /// column 0, which is what makes this possible without a shell parser.
    fn shell_function(script: &str, name: &str) -> String {
        let path = manifest_dir().join("../..").join(script);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "cannot read {}: {e}. These tests assert the behaviour of the release and \
                 install gates that consume this crate's build stamp; if that script moved, \
                 move this test with it rather than deleting it.",
                path.display()
            )
        });
        let open = format!("{name}() {{");
        let start = src.find(&open).unwrap_or_else(|| {
            panic!("{} defines no function {open:?} any more. It is the gate that reads \
                    this crate's build stamp; if it was renamed, rename it here too.",
                   path.display())
        });
        let rest = &src[start..];
        let end = rest.find("\n}\n").unwrap_or_else(|| {
            panic!("cannot find the end of {name} in {} (expected a closing brace in \
                    column 0)", path.display())
        });
        rest[..end + 3].to_string()
    }

    /// Run a snippet under bash and return (exit code, stdout+stderr).
    fn run_bash(script: &str, args: &[&str]) -> (i32, String) {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(script)
            .arg("harness")
            .args(args)
            .output()
            .expect("bash is required to check the shell gates that read this build stamp");
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        (out.status.code().unwrap_or(-1), text)
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("husk-build-identity-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("cannot create a scratch directory");
        dir
    }

    /// `RB2-9` — the release gate must find the stamp it means, not the first thing that
    /// looks like one, in a binary that really does carry the marker twice.
    ///
    /// Measured in a release binary: rustc pools the bare `OPEN` literal from this module
    /// immediately before the `"unknown"` fallback and immediately before `STAMP`, so the
    /// file contains `husk-build-stamp{unknownhusk-build-stamp{<unix>|<commit>|<rev>}`.
    /// The previous extraction — `husk-build-stamp\{[^}]*\}` piped to `head -1` — returned
    /// that concatenation and would have refused every correct release binary. Nothing
    /// noticed, because no test ever looked at a built file.
    ///
    /// The false friend, named: `grep -c` counts LINES and answers 1 for both markers. The
    /// count has to be `grep -o … | wc -l`.
    ///
    /// Mutation that turns this red: put `'husk-build-stamp\{[^}]*\}'` back in
    /// `make-release.sh`, or drop the `match_count` check and take `head -1`.
    #[test]
    fn the_release_gate_reads_the_stamp_out_of_a_binary_that_carries_two_markers() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let dir = scratch("two-markers");

        // The pooled layout, byte for byte as it appears in a release binary.
        let pooled = dir.join("husk-slurm-broker-x86_64");
        let mut bytes: Vec<u8> = b"\x7fELF\x00\x00 padding \x00".to_vec();
        bytes.extend_from_slice(OPEN.as_bytes());
        bytes.extend_from_slice(b"unknown");
        bytes.extend_from_slice(format!("{OPEN}1788184512|{commit}|v0.5.0}}").as_bytes());
        bytes.extend_from_slice(b"\x00./HUSK_LOG\x00");
        std::fs::write(&pooled, &bytes).unwrap();

        let harness = format!(
            "set -uo pipefail\nfail() {{ echo \"error: $*\" >&2; exit 1; }}\n{}\nrequire_build_stamp \"$1\" \"$2\"\necho PASSED\n",
            shell_function("make-release.sh", "require_build_stamp")
        );

        // Two bare markers are present — that is the hazard, asserted, not assumed.
        assert_eq!(
            bytes.windows(OPEN.len()).filter(|w| *w == OPEN.as_bytes()).count(),
            2,
            "this fixture is supposed to reproduce the two-marker layout the release binary has"
        );

        let (rc, out) = run_bash(&harness, &[pooled.to_str().unwrap(), commit]);
        assert_eq!(rc, 0, "the gate refused a CORRECT binary: {out}");
        assert!(out.contains("PASSED"), "{out}");

        let (rc, out) = run_bash(&harness, &[pooled.to_str().unwrap(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]);
        assert_eq!(rc, 1, "the gate accepted a binary from another commit: {out}");
        assert!(out.contains("was not built from the commit"), "{out}");

        // And two ANCHORED stamps must stop it rather than let it choose by luck.
        let ambiguous = dir.join("husk-slurm-broker-ambiguous");
        let mut two = bytes.clone();
        two.extend_from_slice(format!("{OPEN}1788184512|{commit}|v0.5.0}}").as_bytes());
        std::fs::write(&ambiguous, &two).unwrap();
        let (rc, out) = run_bash(&harness, &[ambiguous.to_str().unwrap(), commit]);
        assert_eq!(rc, 1, "two anchored stamps must fail closed, not resolve to the first: {out}");
        assert!(out.contains("carries 2 husk build stamps"), "{out}");
    }

    /// `RB2-1` — the freshness gate must not report success on a search root that is not
    /// there. `find` complains to stderr, the function discards stderr, and an empty result
    /// reads as "no source is newer". The Rust walk above refuses to be vacuous (`seen > 0`);
    /// its shell twin did not, in the same diff that tripled the number of roots.
    ///
    /// Mutation that turns this red: delete the `for root in "$@"` loop from
    /// `require_not_older_than_sources` — the bad-root case then prints nothing and exits 0.
    #[test]
    fn the_release_freshness_gate_refuses_a_source_root_it_cannot_see() {
        let dir = scratch("roots");
        let src = dir.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.rs"), "// source\n").unwrap();
        // The binary must be NEWER than the source, or the real check fires for a real
        // reason and this test would pass for the wrong one (`P9`).
        std::process::Command::new("touch")
            .args(["-d", "@1700000000"])
            .arg(src.join("a.rs"))
            .status()
            .expect("touch is required to date the fixture");
        let bin = dir.join("husk-slurm-wrapper-x86_64");
        std::fs::write(&bin, "binary").unwrap();

        let harness = format!(
            "set -uo pipefail\nfail() {{ echo \"error: $*\" >&2; exit 1; }}\n{}\nrequire_not_older_than_sources \"$@\"\necho PASSED\n",
            shell_function("make-release.sh", "require_not_older_than_sources")
        );

        let (rc, out) = run_bash(&harness, &[bin.to_str().unwrap(), src.to_str().unwrap()]);
        assert_eq!(rc, 0, "the gate refused a correct binary: {out}");
        assert!(out.contains("PASSED"), "{out}");

        // One character wrong in the root — the shape of a directory rename or a typo in a
        // future edit. This must NOT be an [ok].
        let typo = format!("{}X", src.display());
        let (rc, out) = run_bash(&harness, &[bin.to_str().unwrap(), &typo]);
        assert_ne!(rc, 0, "a search root that does not exist made the gate pass: {out}");
        assert!(!out.contains("PASSED"), "{out}");
        assert!(out.contains("cannot see"), "the refusal must name the root it could not find: {out}");
    }

    /// `RB2-3` — the installer must refuse a staged broker built from another commit, and
    /// must not ask the question at all outside a husk checkout.
    ///
    /// The two live paths this closes need no failed build: build at commit A, `git pull`
    /// to B, install (the installer had `[[ -x ]]` and an unconditional `install`); and
    /// `make-release.sh` correctly refusing a stale binary while leaving it staged and
    /// installable.
    ///
    /// What this test stubs, said plainly (`P9`): `git` is a shell function here, so this
    /// asserts the COMPARISON and its four arms, not git's behaviour. The self-disabling
    /// arm is exercised for real — no `.git`, no question asked — because that is the arm
    /// whose failure would be a refusal with no remedy on a tarball install.
    ///
    /// Mutation that turns this red: drop the `require_staged_broker_matches_checkout` call
    /// from the preflight, or make the mismatch arm a `warn` instead of an `exit 1`.
    #[test]
    fn the_installer_refuses_a_staged_broker_built_from_another_commit() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        let other = "fedcba9876543210fedcba9876543210fedcba98";
        let dir = scratch("installer");

        let stamped = |name: &str, commit: &str| -> PathBuf {
            let p = dir.join(name);
            let mut bytes: Vec<u8> = b"\x7fELF\x00".to_vec();
            bytes.extend_from_slice(format!("{OPEN}1788184512|{commit}|v0.5.0}}").as_bytes());
            std::fs::write(&p, &bytes).unwrap();
            p
        };
        let right = stamped("broker-right", head);
        let wrong = stamped("broker-wrong", other);
        let dirty = stamped("broker-dirty", &format!("{head}-dirty"));
        let unstamped = dir.join("broker-unstamped");
        std::fs::write(&unstamped, b"\x7fELF no stamp here").unwrap();

        let checkout = dir.join("checkout");
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        let tarball = dir.join("tarball");
        std::fs::create_dir_all(&tarball).unwrap();

        let harness = format!(
            "set -uo pipefail\n\
             warn() {{ printf '  [warn] %s\\n' \"$*\"; }}\n\
             git() {{ echo '{head}'; }}\n\
             SCRIPT_DIR=\"$2\"\n{}\n\
             require_staged_broker_matches_checkout \"$1\"\necho PASSED\n",
            shell_function("install-husk.sh", "require_staged_broker_matches_checkout")
        );
        let run = |bin: &PathBuf, root: &PathBuf| run_bash(&harness, &[bin.to_str().unwrap(), root.to_str().unwrap()]);

        let (rc, out) = run(&right, &checkout);
        assert_eq!(rc, 0, "the installer refused the binary for this very commit: {out}");

        let (rc, out) = run(&wrong, &checkout);
        assert_eq!(rc, 1, "a broker from another commit was installed: {out}");
        assert!(out.contains("is not this checkout"), "{out}");
        assert!(out.contains(other), "the refusal must name the commit it found: {out}");

        let (rc, out) = run(&unstamped, &checkout);
        assert_eq!(rc, 1, "a broker with no stamp at all was installed: {out}");

        // The edit-build-install loop must keep working, loudly.
        let (rc, out) = run(&dirty, &checkout);
        assert_eq!(rc, 0, "a dirty build of THIS commit is the ordinary dev loop: {out}");
        assert!(out.contains("[warn]"), "a dirty install must say so: {out}");

        // Outside a husk checkout the question cannot be asked, and asking it anyway is how
        // this fix would become the next finding: a release tarball unpacked under a home
        // directory that is a git repo would be refused, with no remedy.
        let (rc, out) = run(&wrong, &tarball);
        assert_eq!(rc, 0, "a tarball install must not be refused by a check it cannot make: {out}");
    }

    /// `RB2-6` and `RB2-8`, pinned where `build_rs_emits_no_rerun_if_directive_of_any_spelling`
    /// pins `B8-4`: in `build.rs`'s text, because the defects are decisions that file makes
    /// and a unit test cannot re-run a build script under six different checkout shapes.
    ///
    /// * `RB2-8`: dirtiness must come from a marker git appends, not from the end of the
    ///   human-facing describe. A tag named `v0.5-dirty` — legal, and `git check-ref-format`
    ///   accepts it — stamped `<commit>-dirty` on a CLEAN tree, and `make-release.sh` then
    ///   refused the release for uncommitted changes with nothing to stash (measured).
    /// * `RB2-6`: an identity may only be claimed from the repository that tracks this
    ///   package. Otherwise a source tree sitting inside any other checkout stamps that
    ///   repo's HEAD, which is worse than `unknown` because it looks like provenance.
    ///
    /// Mutation that turns this red: restore `rev.ends_with("-dirty")` as the decision, or
    /// delete the `ls-files --error-unmatch` guard.
    #[test]
    fn build_rs_asks_git_for_dirtiness_and_for_which_repo_is_answering() {
        let build_rs = manifest_dir().join("build.rs");
        let src = std::fs::read_to_string(&build_rs)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", build_rs.display()));
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !code.contains(r#"ends_with("-dirty")"#),
            "build.rs decides dirtiness by testing whether the git describe ENDS WITH \
             \"-dirty\". That is a property of a string a tag can spell, not a fact about \
             the tree: git check-ref-format accepts a tag named v0.5-dirty, and on a clean \
             tree that stamped <commit>-dirty and made make-release.sh refuse the release \
             for uncommitted changes the operator had no way to stash (RB2-8). Ask git \
             instead — --dirty=^dirty marks the tree with a suffix no refname may contain."
        );
        assert!(
            code.contains(r#""--dirty=^dirty""#),
            "build.rs no longer asks git for an unforgeable dirty marker. If a different \
             marker is used it must be one git check-ref-format REFUSES in a refname \
             (^ ~ : ? * [ \\ space and control characters), or the decision becomes a \
             guess about tag names again (RB2-8)."
        );
        assert!(
            code.contains("ls-files") && code.contains("--error-unmatch"),
            "build.rs claims a build identity without first checking that the repository \
             answering here is the one that TRACKS this package. Dropped inside any other \
             git checkout — a home directory that is a dotfiles repo is enough — it then \
             stamps that repo's HEAD, and the session banner prints forty hex characters of \
             someone else's provenance as husk's (RB2-6). unknown is the honest answer and \
             every consumer already handles it."
        );
    }

}
