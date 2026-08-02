# B5 — guard-script generation, and whether `policy.rs` is auditable

**Workstream B** (control-coverage) · **code-only, laptop** · **two deliverables**

## The questions

1. Can the emitted guard script be made to do something it should not — by any input that
   reaches it?
2. **Is this file auditable?** An explicit verdict is wanted, not an implication.

## Why this is on the list

`policy.rs` generates a shell script that runs **outside** the cage, with the user's identity
and the login environment, and then re-executes itself inside. It is the highest-consequence
string-building in the project.

Our own bug history in it: **4 of 7 shipped guard bugs were quoting, interpolation or
scoping** — a `{socat_q}` leak, literal quotes in the srun bind, `_husk_broker` used before
assignment, `${{...}}` brace escaping. One was plain logic ordering. Two needed *domain*
invariants: the cleanup set missing `net.sock`/socat, and the untrapped `SIGTERM` that meant
none of the cleanup ran on a preempted job.

The second deliverable exists because of a **deferred decision**: whether to build a typed
shell builder instead of `format!`. The argument for deferring was that a reviewer reads the
*emitted* shell, so a builder barely changes the attack surface — and that pre-empting the
review would throw away its independent verdict on auditability. **That verdict is the thing
being asked for here.** Answer it directly.

## What the code does today

Agent bytes are kept out of the guard by **construct-and-re-emit**: husk validates the agent's
value against a boundary and emits *its own* bytes. Values that do flow in come from the
**session and the operator**, not the agent: the workdir, the uenv label and view, the
account, the partition, the socket path, the broker path.

Two golden snapshots pin the output — `broker/tests/golden/guard-net-{on,off}.sh` — and the
suite executes the generated script against a stub to check a hostile command arrives verbatim.

## The question worth asking hardest

Session-derived values are treated as trusted. **Are they?**

- `UENV_LABEL`, `UENV_VIEW`, `HUSK_SLURM_PARTITION`, `HUSK_SLURM_ACCOUNT` are read from the
  broker's environment. The broker runs *outside* the cage, so the agent should not be able to
  set them — verify that, rather than assuming it.
- The workdir is confined, but it is still a string that reaches the script.
- A value that is legal as an sbatch argument is not automatically safe as a **shell** token.

## Starting points

1. Every interpolation site: is the value quoted, and is the quoting correct **for its
   context** (inside single quotes, inside a double-quoted string, inside an array, inside a
   nested script that travels as a variable)?
2. Variables used before assignment, or assigned in a branch and read outside it.
3. The cleanup set: does it name every resource the script creates? (This is where B1 meets
   B5 — a cleanup that enumerates is a denylist.)
4. Signal handling: the trap must cover the paths SLURM actually uses.
5. The `sh_quote` helper — where is it *not* used, and why is that safe?

## What counts as a finding

- Any input that changes the guard's **structure** rather than its values.
- A value reaching the script unquoted whose source is not a compile-time constant.
- A resource created by the guard and not removed by its cleanup, on any exit path.
- A use-before-assignment or a branch-scoped variable read outside its branch.
- For deliverable 2: a concrete statement of what makes the file hard or easy to audit, with
  examples. "It is complex" is not a verdict; "the emitted shell cannot be read without
  simultaneously tracking three levels of quoting, here is a case" is.

## What a null result looks like

For (1): an enumeration of interpolation sites with their quoting context. For (2): a direct
answer — *auditable* or *not*, with the reasoning. **A verdict of "yes, auditable, and here is
why" is a fully valid outcome** and settles the typed-builder question in the other direction.

## Out of scope for this item

- Rewriting the generator. The verdict informs that decision; it does not pre-empt it.
- Shell style preferences.
- `shellcheck` findings on the generated script are welcome as data, but note that it is not
  installed on the laptop — that gap is known.

## Verdict

Regenerate and read. Any claim about what the emitted script does should be shown against
generated output, not argued from the `format!` string — the two have diverged before, and
that divergence is precisely the bug class in question.
