# B3 — mount-table construction, the actual enforcement boundary

**Workstream B** (control-coverage) · **code-only, laptop**

## The question

Does the mount table husk constructs enforce what the policy claims? Is there any path
readable or writable inside the cage that the policy says should not be?

## Why this is on the list

**The mount table is the oracle.** Anthropic's own `apply-seccomp` header says it plainly:
*"bwrap's mount table is the only enforcement boundary"* — their filesystem hooks are
telemetry and fail open. Ours is the same: the cage is what the mount arguments say it is, and
nothing else in husk changes that.

We have already shipped one bug of exactly this class: **F18 — an `allowRead` entry re-exposed
the hidden floor.** The policy said homes are hidden; the mount table said otherwise, and the
mount table won.

## What the code does today

`settings::bwrap_args(workdir, kind)` builds the list. Shape: `--ro-bind / /` then `--dev`,
`--proc`, `--tmpfs /tmp`; `HIDDEN_FLOOR = ["/users"]` masked with `--tmpfs`; the workdir bound
writable; `.claude`, `.git/hooks`, `.vscode`, `.idea` masked; selected files re-bound
read-only; `--unshare-net`. `CageKind::Job` additionally gets `--tmpfs /dev/shm` and
`--unshare-pid`; `CageKind::Rank` gets the job's shared `/dev/shm` and the fabric devices
instead.

Two golden snapshots pin the emitted guard: `broker/tests/golden/guard-net-{on,off}.sh`.

## The property that makes this subtle

**bwrap applies mounts in order, and a later mount shadows an earlier one.** So the table is
not a set of independent facts — it is a sequence, and its meaning depends on ordering. A
rule that is correct in isolation can be undone by something that comes after it, and a rule
that looks redundant may be the only thing holding a boundary.

## Starting points

1. Every entry that derives from **user or session input** rather than a constant: the
   workdir, `allowWrite` roots, `allowRead` entries, the uenv mount, the egress socket bind,
   the socat bind. For each: can it name a path that shadows a floor mask?
2. `--ro-bind-try` / `--dev-bind-try` entries — they degrade silently when absent. Is any of
   them load-bearing for a *boundary* rather than for a feature?
3. The `Job` vs `Rank` delta. Rank cages drop the private `/dev/shm` and gain fabric devices;
   confirm nothing else silently differs.
4. Ordering: construct a case where an `allowRead`/`allowWrite` entry is a parent, child, or
   symlink-equivalent of a masked path.
5. `HIDDEN_FLOOR` is `["/users"]` — one entry. Is that the complete set of home-like roots on
   both Balfrin and Santis? A second home root nobody listed is an F18 with no fix.

## What counts as a finding

- Any path readable or writable inside the cage that the policy claims is not.
- An input-derived entry that can shadow a floor mask.
- An ordering dependency that is real but unstated — if correctness depends on position,
  that must be written down, not inferred.
- A `-try` variant whose silent absence removes a boundary rather than a feature.
- A floor that is incomplete for a site we actually run on.

## What a null result looks like

The mount table, annotated: each entry, what it opens or closes, whether it derives from
input, and what it depends on being before or after. If the table is sound, that annotated
listing is the deliverable and it is directly reusable as documentation.

## Out of scope for this item

- Whether bwrap itself is correct. Assume it is; we are auditing what we *ask* it to do.
- seccomp filter contents (B4 touches the CMA-relevant part).
- The network hole — that is A9.

## Verdict

Code-only, but the golden files make demonstration cheap: change an input, regenerate, and
`diff` the emitted table. Any claim about what the table permits should be shown against a
generated table rather than argued from the source.
