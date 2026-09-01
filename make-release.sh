#!/usr/bin/env bash
# make-release.sh — package a release tarball
#
# Run this from the repo root on a tagged commit after building
# seccomp-wrapper on BOTH architectures with seccomp-wrapper/build_and_test.sh:
#
#   On Balfrin (x86_64):
#     cd husk && ./build_and_test.sh
#
#   On Santis (aarch64):
#     cd husk && ./build_and_test.sh
#     scp seccomp-wrapper/seccomp-wrapper-aarch64 balfrin:<path-to-repo>/seccomp-wrapper/
#
# Both arch-tagged binaries (seccomp-wrapper-x86_64, seccomp-wrapper-aarch64)
# must be present in seccomp-wrapper/ before running this script.
#
# If the release includes the SLURM broker (slurm-broker/broker/), its prebuilt
# per-arch binaries (husk-slurm-{broker,wrapper}-{x86_64,aarch64}) must also be
# present in slurm-broker/ — built the same way as seccomp-wrapper:
#   on each arch:  (cd slurm-broker && ./build-release.sh)
#   then scp the foreign-arch binaries onto this machine.
# Releases ship these compiled binaries; vendor/ is never packaged.
#
# Output: husk-<version>.tar.gz and husk-<version>.SHA256SUMS

set -euo pipefail

# --help prints this script's header comment block (single source of truth).
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  sed -n '1d; /^#/!q; s/^#//; s/^ //; p' "$0"
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_X86_64="${REPO_ROOT}/seccomp-wrapper/seccomp-wrapper-x86_64"
BINARY_AARCH64="${REPO_ROOT}/seccomp-wrapper/seccomp-wrapper-aarch64"
CURRENT_ARCH="$(uname -m)"

# ── version ───────────────────────────────────────────────────────────────────

HEAD_TAG="$(git -C "${REPO_ROOT}" describe --tags --exact-match 2>/dev/null || true)"

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
    if [[ -z "${HEAD_TAG}" ]]; then
        echo "error: not on an exact git tag and no version argument given."
        echo "       Tag the commit first (e.g. git tag v0.1) or pass the"
        echo "       version explicitly: ./make-release.sh v0.1"
        exit 1
    fi
    VERSION="${HEAD_TAG}"
elif [[ "${VERSION}" != "${HEAD_TAG}" ]]; then
    # The explicit-version path used to bypass the tag check entirely: on a tree tagged
    # v0.9.9, `./make-release.sh v1.2.3` produced husk-v1.2.3.tar.gz containing HEAD,
    # without a word (`B8-5`). The tarball, its SHA256SUMS and every binary inside then
    # claim a version no commit carries, and there is no later way to find out which
    # source it was. The header of this file has always said "run on a tagged commit";
    # this is that sentence becoming a check rather than a request (`P3`).
    #
    # Branch on the override FIRST. The first version printed the whole `error:` block and
    # only then tested the variable, so an authorised release printed a refusal and then
    # succeeded (`RB-5`) — in the commit titled "stop saying [ok] about things nothing
    # checked". A message and an exit status that disagree are the same defect as an [ok]
    # that checked nothing: the transcript stops being evidence. The rule is `P11` — the
    # operator reads the refusal, forms a theory, and remediates something that was never
    # wrong. This cited `P13` until `RB2-5`: `P13` is husk narrating to the CONFINED AGENT
    # what it silently changed, and a release script has no confined party. A citation
    # names a target too (`P15`).
    if [[ "${HUSK_RELEASE_VERSION_MAY_DIFFER_FROM_TAG:-}" == "1" ]]; then
        echo "  [warn] HUSK_RELEASE_VERSION_MAY_DIFFER_FROM_TAG=1 — '${VERSION}' is not the"
        echo "         tag on HEAD (${HEAD_TAG:-<HEAD is not tagged>}); shipping HEAD"
        echo "         ($(git -C "${REPO_ROOT}" rev-parse --short HEAD)) as '${VERSION}'."
    else
        echo "error: version '${VERSION}' is not the tag on HEAD (${HEAD_TAG:-<HEAD is not tagged>})."
        echo "       A release names the commit it ships. Tag the commit you mean:"
        echo "         git tag ${VERSION} && ./make-release.sh"
        echo "       If you are deliberately building a differently-named artefact from this"
        echo "       exact tree — a release candidate, a one-off for a colleague — say so:"
        echo "         HUSK_RELEASE_VERSION_MAY_DIFFER_FROM_TAG=1 ./make-release.sh ${VERSION}"
        exit 1
    fi
fi

if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+([.][0-9]+)?(-[A-Za-z0-9._-]+)?$ ]]; then
    echo "error: version '${VERSION}' does not match expected format v<major>.<minor>[.<patch>][-<suffix>]"
    echo "       examples: v0.1  v1.2  v0.1.3  v0.1-bugfix3"
    exit 1
fi

ARCHIVE="${REPO_ROOT}/husk-${VERSION}.tar.gz"
PREFIX="husk-${VERSION}"
STAGING="$(mktemp -d)"
trap 'rm -rf "${STAGING}"' EXIT

# ── preflight ─────────────────────────────────────────────────────────────────
#
# THE QUESTION THIS SECTION HAS TO ANSWER is "were these binaries built from the source
# about to be packaged beside them?", and until 2026-08-31 nothing here could. The one
# check that existed, `git diff --quiet HEAD -- seccomp-wrapper/`, tests for UNCOMMITTED
# edits. `B8-5` committed a change to seccomp_wrapper.c, left the binaries alone, and got
# `[ok]` on every line plus a SHA256SUMS attesting to a tarball whose source and binaries
# disagree. `slurm-broker/` — the newer and larger half — had no gate whatsoever: planted
# binaries printing STALE-BINARY-FROM-AN-OLDER-COMMIT were bundled with `[ok]`.
#
# What is available to check with, honestly:
#
#   * The BROKER binaries carry a build stamp (`build.rs`, `src/build_identity.rs`), which
#     is a real answer and works for the foreign arch too, because it is read from the file
#     rather than executed. This is the one strong check here. It matches the COMMIT the
#     binary was built from, not the tag name that commit happens to carry on this machine
#     (`RB-3`).
#   * The C wrapper has no stamp, so it gets the weak one: mtime. That catches the case
#     `B8-5` measured — edit, commit, forget to rebuild — and it does NOT prove provenance;
#     a binary rebuilt from different source has a fresh mtime. Said plainly rather than
#     implied, per `P12`.
#   * `husk-slurm-wrapper` has no stamp either, though it could: it links the lib that
#     defines one and never references it. Giving it a startup line like the broker's is a
#     one-liner in a file this pass does not own; until then it inherits the broker's, on
#     evidence that the two were staged together, and falls back to mtime when they were
#     not. That gap is real and is named here so it stays visible.
#
#     Why inherit rather than measure (`RB2-4`): mtime over git-managed files answers "did
#     the working tree change after this binary was written", and `git checkout`, `git pull`
#     and `git stash pop` all rewrite mtimes without changing one byte of content. Measured:
#     scp the aarch64 pair, run `git checkout -- .`, and this section refused a correct
#     wrapper and told the operator to rebuild it on the other cluster — while the broker
#     BESIDE it, from the same `cargo build`, passed on real provenance. That is `RB-3a`'s
#     class surviving the fix to its instance, and it is the noisiest gate in a section
#     where everything else is exact, which is precisely what makes it believable.

fail() { echo "error: $*" >&2; exit 1; }

# What `git diff --quiet HEAD -- <path>` proves: no uncommitted edits to TRACKED files.
# What it does not: anything about untracked files, or about when a binary was built.
# Untracked files do not reach the tarball (`git archive` ships tracked content only), so
# they are not a shipping hazard — except for a SOURCE file, which would mean the shipped
# tree cannot rebuild the shipped binary. That distinction is the difference between the
# error and the notice below.
require_committed() {
    local path="$1"
    git -C "${REPO_ROOT}" diff --quiet HEAD -- "${path}" || fail \
"${path} has uncommitted changes.
       The binaries may not match the source shipped in the tarball.
       Commit the changes or rebuild first."

    local untracked_src
    untracked_src="$(git -C "${REPO_ROOT}" ls-files --others --exclude-standard -- "${path}" \
        | grep -E '\.(c|h|rs)$' || true)"
    [[ -z "${untracked_src}" ]] || fail \
"${path} contains untracked SOURCE files:
$(sed 's/^/         /' <<<"${untracked_src}")
       git archive ships tracked content only, so the tarball would carry binaries that
       its own source cannot rebuild. Commit them or remove them."

    local untracked_other
    untracked_other="$(git -C "${REPO_ROOT}" ls-files --others --exclude-standard -- "${path}" \
        | grep -vE '\.(c|h|rs)$' || true)"
    if [[ -n "${untracked_other}" ]]; then
        echo "  [note]  untracked files under ${path} (not shipped, not a hazard):"
        sed 's/^/            /' <<<"${untracked_other}"
    fi
}

# ELF magic + e_machine. The foreign-arch binaries have never had any check at all, and
# "scp'd the wrong file into the arch-tagged name" is the cheapest way to ship a release
# that cannot start. Reads bytes, so it works for an architecture we cannot execute.
# (e_machine is a 2-byte field at offset 18, little-endian on both our targets and on
# every machine this script runs on.)
require_elf() {
    local f="$1" want_arch="$2"
    local magic machine want_machine
    case "${want_arch}" in
        x86_64)  want_machine=62  ;;   # EM_X86_64
        aarch64) want_machine=183 ;;   # EM_AARCH64
        *) fail "require_elf: unknown architecture '${want_arch}'" ;;
    esac
    magic="$(od -An -tx1 -N4 "$f" | tr -d ' \n')"
    [[ "${magic}" == "7f454c46" ]] || fail \
"$(basename "$f") is not an ELF binary (magic ${magic}).
       Something other than a compiled binary is sitting under that name."
    machine="$(od -An -tu2 -j18 -N2 "$f" | tr -d ' \n')"
    [[ "${machine}" == "${want_machine}" ]] || fail \
"$(basename "$f") is ELF e_machine ${machine}, expected ${want_machine} (${want_arch}).
       A binary for the wrong architecture is under that name — most likely the wrong
       file was scp'd from the other cluster. It would install and fail to exec."
}

# The weak check, for the binaries that carry no stamp. Says what it proves.
require_not_older_than_sources() {
    local bin="$1"; shift
    local newer root seen
    # ONE statement of what counts as source, used by both walks below (`P8`). Restating it
    # for the counting walk would be two lists of the same thing, and this function exists
    # because such a pair drifted.
    local -a src=( -type f \( -name '*.c' -o -name '*.h' -o -name '*.rs' \
                   -o -name 'Makefile' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) )
    # `RB2-1`, `P10`: a search root that does not exist makes this measure NOTHING and then
    # print [ok]. find writes its complaint to stderr, which the search below sends to
    # /dev/null; the result is empty; the caller reads empty as "no source is newer". The
    # Rust twin of this walk refuses to be vacuous (build_identity.rs asserts seen > 0) and
    # this one did not, in the same diff. One root was hard to get wrong; there are three
    # per call now, each assembled from REPO_ROOT, so a directory rename or a Cargo.lock
    # moved to a workspace root silently converts the whole gate into an [ok] (`P7`).
    for root in "$@"; do
        [[ -e "${root}" ]] || fail \
"the freshness gate cannot see ${root}.
       That path is one of the source roots $(basename "${bin}") is checked against, so
       with it missing this check would look at nothing and report success. Either the
       tree moved and the root list in this script needs updating, or this is not a husk
       checkout. Fix the list rather than the symptom: a gate that measures nothing must
       not print [ok]."
    done
    # `RAB3-B4`: the loop above lands ONE LEVEL ABOVE its own last sentence. It asks whether
    # the roots EXIST; the sentence promises that the gate MEASURED something. Those differ
    # whenever a root exists and holds no matching file — driven: root missing -> rc=1 (the
    # loop works), root present but empty of sources -> rc=0 with nothing measured, which is
    # `RB2-1` reproduced inside its own fix. The `-name` filter is a hardcoded allowlist
    # (`P5`), so the ways in are ordinary: a workspace layout that moves Cargo.lock up, a
    # rename, or a source extension nobody added here. Count what was walked and make the
    # count the [ok], which is exactly what the Rust twin does.
    seen="$(find "$@" "${src[@]}" -print 2>/dev/null | wc -l || true)"
    (( seen > 0 )) || fail \
"the freshness gate matched no source file under: $*
       Every one of those roots exists, so this did not fail on a missing path — it walked
       them and found nothing it recognises as source. $(basename "${bin}") would then be
       declared not-older-than a set of zero files, which is true of any binary of any age.
       The recognised names are *.c *.h *.rs Makefile Cargo.toml Cargo.lock; if the tree now
       spells source some other way, teach this function that spelling. A gate that measures
       nothing must not print [ok]."
    newer="$(find "$@" "${src[@]}" -newer "${bin}" -print 2>/dev/null | head -5 || true)"
    [[ -z "${newer}" ]] || fail \
"$(basename "${bin}") is older than source it is supposed to have been built from:
$(sed "s|^|         |" <<<"${newer}")
       Rebuild it on its own architecture and copy it here again. (This check is mtime,
       not provenance: it catches edit-commit-forget-to-rebuild, which is the case that
       has actually happened, and cannot catch a binary rebuilt from other source.)"
}

# Were these two files written by the same staging event? `install` writes the pair in one
# loop in build-release.sh (3 ms apart, measured) and scp copies them together, so a window
# of two minutes is generous by three orders of magnitude and still far too narrow to span
# two separate builds of a Rust crate. Returns non-zero rather than failing: the caller has
# a weaker check to fall back on, so an unreadable mtime must degrade to the old behaviour
# and not to an [ok] (`P7`).
costaged_with() {
    local bin="$1" reference="$2" window="${3:-120}"
    local a b delta
    a="$(stat -c %Y "${bin}" 2>/dev/null || true)"
    b="$(stat -c %Y "${reference}" 2>/dev/null || true)"
    [[ -n "${a}" && -n "${b}" ]] || return 1
    delta=$(( a > b ? a - b : b - a ))
    (( delta <= window ))
}

# The strong check — the only one here that is provenance rather than mtime.
#
# It matches the COMMIT, not the `git describe`. Those answer different questions and only
# one of them is the same fact on every machine: `git describe --tags` is resolved against
# the tags the BUILD machine's clone happened to hold, so tagging on a laptop and building
# on a cluster that has not fetched the tag yet gives two strings for one commit. The first
# version of this gate compared the describe and then said "That binary is not this commit"
# about a binary that was, with a remedy — rebuild it — that produces the same stamp again
# (`RB-3`, measured; `P11`).
#
# The comparison is a FIXED string, and the stamp's field order is what makes that exact.
# The stamp is `husk-build-stamp{<unix>|<commit>|<describe>}`: the two leading fields cannot
# hold a delimiter by construction (decimal digits, an object name), so the regex below is
# total — while the describe, which git permits a tag to fill with `|`, `{` or `}` (`RB-7`,
# measured with a real tag), is never parsed here at all. A dirty build stamps
# `<commit>-dirty`, which does not match `<commit>`, so this also refuses a binary built
# from an uncommitted tree. Substring matching is still the false friend it always was:
# 'v0.5.0' is a substring of 'v0.5.0-dirty' and of the crate version.
require_build_stamp() {
    local bin="$1" expect="$2"
    local found found_commit hint matches match_count
    matches="$(LC_ALL=C grep -aoE 'husk-build-stamp\{[0-9]+\|[^|]*\|' "${bin}" || true)"
    if [[ -z "${matches}" ]]; then
        fail "$(basename "${bin}") carries no husk build stamp.
       Either it predates the stamp (built before v0.5) or it was not produced by
       slurm-broker/build-release.sh. Rebuild it on its own architecture.
       This gate fails CLOSED on a missing marker on purpose: a release must not pass
       on a check it was unable to make."
    fi
    # EXACTLY one, not the first of N (`RB2-9`). The release binary really does contain the
    # marker TWICE: rustc pools the bare OPEN constant from build_identity.rs immediately
    # before the literal "unknown" and immediately before STAMP, so the file holds
    #   husk-build-stamp{unknownhusk-build-stamp{<unix>|<commit>|<rev>}
    # as well as the stamp itself. Measured. The [0-9]+ anchor above is the only reason the
    # first match is the right one — the previous regex husk-build-stamp\{[^}]*\} plus
    # head -1 returned the concatenation and would have REFUSED every correct release
    # binary. Correctness therefore rested on rustc's string-pool layout, which nothing
    # asserts and no test looks at. Counting makes it structural: if a future layout puts
    # two anchored markers in the file, the gate stops rather than choosing by luck (`P7`).
    # False friend, named because it is the obvious way to write this: grep -c counts LINES
    # and reports 1 for both markers. grep -o prints one match per line, so wc -l counts
    # matches.
    match_count="$(wc -l <<<"${matches}")"
    if [[ "${match_count}" -ne 1 ]]; then
        fail "$(basename "${bin}") carries ${match_count} husk build stamps, not one:
$(sed 's|^|         |' <<<"${matches}")
       This gate identifies a binary by a marker it expects to be unique, so with more
       than one present it cannot say which build this file is. It refuses rather than
       taking the first. If the stamp format or build_identity.rs changed, fix the
       extraction here in the same pass."
    fi
    found="${matches}"
    found_commit="${found#*|}"
    found_commit="${found_commit%|}"
    [[ "${found_commit}" == "${expect}" ]] || {
        case "${found_commit}" in
            "${expect}-dirty")
                hint="       That IS this commit, but the tree it was built from had uncommitted
       changes, so the source in this tarball cannot rebuild that binary. Commit or
       stash on the machine that built it, rebuild, and copy it here again." ;;
            unknown)
                hint="       That binary was built where git could say nothing — a tarball, a
       checkout without git on PATH — so it carries no provenance at all.
       Rebuild it from a clone of this repository." ;;
            *)
                hint="       Rebuild it on its own architecture and copy it here again:
         (cd slurm-broker && ./build-release.sh)
       This gate matches the COMMIT, so a build machine whose clone has not fetched
       the tag is fine; a different commit is not." ;;
        esac
        fail \
"$(basename "${bin}") was not built from the commit this release ships.
         this release ships: ${expect}
         that binary is from: ${found_commit}
${hint}"
    }
}

# A release names the commit it ships, and the stamp in every broker binary records the
# commit it was built from. Those two can only agree if the tree is clean, so ask for that
# first, with a message that explains it, rather than as four confusing stamp mismatches.
# `--dirty='^dirty'`, not `--dirty`: git check-ref-format FORBIDS `^` in a refname, so this
# marker is a suffix no tag, no describe fallback and no abbreviated object name can spell.
# With the plain marker the decision was a suffix test on a human-facing string, and a tag
# legitimately named `v0.5-dirty` made this refuse the whole release for uncommitted changes
# on a clean tree — with nothing to stash and no way to converge (`RB2-8`, measured). Only
# the DECISION changes; HEAD_REV is reassembled in its familiar spelling for the transcript.
HEAD_REV_RAW="$(git -C "${REPO_ROOT}" describe --always --dirty='^dirty' --tags 2>/dev/null || echo unknown)"
if [[ "${HEAD_REV_RAW}" == *'^dirty' ]]; then
    HEAD_DIRTY=1
    HEAD_REV="${HEAD_REV_RAW%'^dirty'}-dirty"
else
    HEAD_DIRTY=0
    HEAD_REV="${HEAD_REV_RAW}"
fi
HEAD_SHA="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)"
# Without this, a run outside a checkout would compare 'unknown' against a binary stamped
# 'unknown' and call it a match — a gate passing on a check it could not make (`P7`).
# 40 for a SHA-1 repository, 64 for a SHA-256 one — the point is that git named a real
# object, not that it used a particular hash.
[[ "${HEAD_SHA}" =~ ^[0-9a-f]{40}$|^[0-9a-f]{64}$ ]] || fail \
"git could not name HEAD in ${REPO_ROOT} (got '${HEAD_SHA}').
       A release names the commit it ships, and every broker binary is stamped with the
       commit it was built from, so both halves of that check need a real checkout."
if [[ ${HEAD_DIRTY} -eq 1 ]]; then
    fail "the working tree has uncommitted changes to tracked files (git describe: ${HEAD_REV}).
       Every broker binary is stamped with the tree state it was built from, so a release
       from a dirty tree cannot say which source it contains. Commit or stash, rebuild,
       and run this again."
fi

echo "==> Preflight"
require_committed seccomp-wrapper/
require_committed slurm-broker/
echo "  [ok]   seccomp-wrapper/ and slurm-broker/ have no uncommitted or untracked source"

# The Rust gate. build-release.sh owns the offline/online decision, so this does not keep
# a second copy of it (`P8`). ~8s. Before this, the entire broker could be built, bundled,
# checksummed and shipped with a red suite (`B8-5`).
if [[ -f "${REPO_ROOT}/slurm-broker/broker/Cargo.toml" ]]; then
    command -v cargo >/dev/null 2>&1 || fail \
"cargo is not on PATH, so the broker's tests cannot be run.
       Run this on the machine that built the broker binaries."
    echo "==> Rust gate (cargo test --release)"
    "${REPO_ROOT}/slurm-broker/build-release.sh" --test-only >/dev/null \
        || fail "the broker's test suite failed — not packaging a release around it.
       Re-run for the detail:  (cd slurm-broker && ./build-release.sh --test-only)"
    echo "  [ok]   broker crate tests pass"
fi

for arch in x86_64 aarch64; do
    bin="${REPO_ROOT}/seccomp-wrapper/seccomp-wrapper-${arch}"
    [[ -x "${bin}" ]] || fail \
"seccomp-wrapper/seccomp-wrapper-${arch} not found.
       Build it on that architecture: cd husk && ./build_and_test.sh"
    require_elf "${bin}" "${arch}"
    require_not_older_than_sources "${bin}" \
        "${REPO_ROOT}/seccomp-wrapper/src" "${REPO_ROOT}/seccomp-wrapper/test"
done
echo "  [ok]   seccomp-wrapper x86_64 + aarch64: right architecture, not older than src/"

# Sanity-check only the binary for the current arch — the other cannot be executed here.
# Note what this does NOT prove: an OLD binary execs 'echo ok' perfectly well. It is a
# corruption check, not a freshness one, which is why the mtime check above exists.
CURRENT_BINARY="${REPO_ROOT}/seccomp-wrapper/seccomp-wrapper-${CURRENT_ARCH}"
echo "==> Sanity check (${CURRENT_ARCH})"
"${CURRENT_BINARY}" echo ok > /dev/null 2>&1 || fail \
"seccomp-wrapper-${CURRENT_ARCH} failed to exec 'echo ok' —
       binary may be corrupt or built for a different kernel."
echo "  [ok]   seccomp-wrapper-${CURRENT_ARCH} functional on this kernel"

# The broker half, which had nothing.
if [[ -f "${REPO_ROOT}/slurm-broker/broker/Cargo.toml" ]]; then
    echo "==> Broker binary provenance (HEAD is ${HEAD_REV}, ${HEAD_SHA})"
    for arch in x86_64 aarch64; do
        for bin_name in husk-slurm-broker husk-slurm-wrapper; do
            bin="${REPO_ROOT}/slurm-broker/${bin_name}-${arch}"
            [[ -x "${bin}" ]] || fail \
"slurm-broker/${bin_name}-${arch} not found.
       Build on each arch: (cd slurm-broker && ./build-release.sh)
       then scp the foreign-arch binaries here before make-release."
            require_elf "${bin}" "${arch}"
            if [[ "${bin_name}" == "husk-slurm-broker" ]]; then
                require_build_stamp "${bin}" "${HEAD_SHA}"
                echo "  [ok]   ${bin_name}-${arch}: built from ${HEAD_SHA:0:12} (${HEAD_REV})"
            else
                # No stamp in this binary — see the section header. Two ways to answer
                # for it, strongest first.
                #
                # 1. INHERIT. build-release.sh produces both binaries from one
                #    `cargo build` and stages them in one loop (measured: 3 ms apart), and
                #    the foreign-arch pair is scp'd together. So when the wrapper's mtime
                #    sits beside the broker's AND that broker carries this commit's stamp,
                #    the wrapper's provenance is the broker's — exact, and immune to the
                #    git operations that rewrite source mtimes (`RB2-4`). The stamp check
                #    is repeated here rather than assumed from the loop order above, so
                #    reordering the loop cannot silently turn this into an unconditional
                #    pass (`P6`: structural, not remembered).
                #
                # 2. Otherwise MEASURE, as before: mtime, over the package's own sources
                #    only — NOT build.rs, which build-release.sh deliberately touches on
                #    every release build, and NOT broker/target/, where dependency build
                #    scripts write generated .rs. Searching the whole of broker/ did both,
                #    so scp'ing a correct foreign-arch binary here and then building this
                #    arch — the order the header documents in reverse — failed with "older
                #    than source it is supposed to have been built from: broker/build.rs",
                #    and the remedy it printed could not converge (`RB-3`).
                #
                # What (1) cannot see, said plainly (`P10`, `P12`): it proves the two files
                # were WRITTEN together, not that they were COMPILED together. Copy a stale
                # wrapper alongside a fresh broker inside the same two minutes and this
                # passes. That is a release-machine mistake by the one operator who also
                # holds the source; it is not something the confined side can reach.
                broker_bin="${REPO_ROOT}/slurm-broker/husk-slurm-broker-${arch}"
                if costaged_with "${bin}" "${broker_bin}" \
                   && require_build_stamp "${broker_bin}" "${HEAD_SHA}"; then
                    echo "  [ok]   ${bin_name}-${arch}: staged with husk-slurm-broker-${arch}, which is built from ${HEAD_SHA:0:12} (no stamp of its own — provenance inherited)"
                else
                    require_not_older_than_sources "${bin}" \
                        "${REPO_ROOT}/slurm-broker/broker/src" \
                        "${REPO_ROOT}/slurm-broker/broker/Cargo.toml" \
                        "${REPO_ROOT}/slurm-broker/broker/Cargo.lock"
                    echo "  [ok]   ${bin_name}-${arch}: right arch, not older than broker/src (no stamp — see BUILD-IDENTITY note)"
                fi
            fi
        done
    done
fi

# ── assemble ──────────────────────────────────────────────────────────────────

echo "==> Assembling ${PREFIX}"

# Export tracked files from git into staging area.
git -C "${REPO_ROOT}" archive --prefix="${PREFIX}/" HEAD \
    | tar xf - -C "${STAGING}"

# Add compiled binaries (not tracked by git).
cp "${BINARY_X86_64}"  "${STAGING}/${PREFIX}/seccomp-wrapper/seccomp-wrapper-x86_64"
cp "${BINARY_AARCH64}" "${STAGING}/${PREFIX}/seccomp-wrapper/seccomp-wrapper-aarch64"

echo "  [ok]   source + x86_64 binary + aarch64 binary"

# Add prebuilt SLURM broker binaries, if this release includes the broker.
# Same model as seccomp-wrapper: built per-arch (slurm-broker/build-release.sh),
# scp'd together, bundled here. vendor/ is NOT shipped. Auto-skips on releases
# that predate the broker (e.g. the broker source is absent from this tag).
if [[ -f "${STAGING}/${PREFIX}/slurm-broker/broker/Cargo.toml" ]]; then
    echo "==> Bundling SLURM broker binaries"
    # Existence, architecture and provenance were all settled in the preflight, so this
    # is now only the copy. Keeping a second existence check here would be a second list.
    for bin in husk-slurm-broker husk-slurm-wrapper; do
        for arch in x86_64 aarch64; do
            cp "${REPO_ROOT}/slurm-broker/${bin}-${arch}" \
               "${STAGING}/${PREFIX}/slurm-broker/${bin}-${arch}"
        done
    done
    echo "  [ok]   broker + wrapper (x86_64 + aarch64)"
fi

# ── pack ──────────────────────────────────────────────────────────────────────
#
# Reproducible tarball: two runs from identical inputs must produce an identical
# SHA256. --sort=name fixes file ordering, --owner/group/mtime strip host
# identity, and gzip -n omits the filename+timestamp from the gzip header.
# tar -z does not pass -n through to gzip, so we pipe explicitly.
# Note: --sort=name is GNU tar only; make-release.sh is Balfrin (Linux) only.

echo "==> Creating ${ARCHIVE}"
tar --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime='@0' \
    -cf - -C "${STAGING}" "${PREFIX}" | gzip -n > "${ARCHIVE}"
echo "  [ok]   $(du -sh "${ARCHIVE}" | cut -f1)  ${ARCHIVE}"

# ── checksums ─────────────────────────────────────────────────────────────────

CHECKSUMS="${REPO_ROOT}/husk-${VERSION}.SHA256SUMS"
(cd "${REPO_ROOT}" && sha256sum "husk-${VERSION}.tar.gz") > "${CHECKSUMS}"
echo "  [ok]   ${CHECKSUMS}"
