# A3 — the job-script body

**Workstream A** (assumed-breach) · **in-cage on Balfrin** · **verdict from outside**
· bound by the **rules of engagement** in `A-RULES-OF-ENGAGEMENT.md`

> **REWRITTEN 2026-08-03. This brief's original premise no longer exists.** It was built around
> husk forwarding the body verbatim into slurmd's parser, so that two parsers read the same
> bytes. Fix 1 removed that channel entirely: husk submits **its own script on sbatch's stdin**
> and the agent's body is data, run by an interpreter husk names, inside the cage. The
> two-parser seam with slurmd is closed *by construction*, not by better parsing.
>
> Do not spend this run confirming that. It is covered by tests, and the goldens show the
> submitted script contains no agent bytes. **The body is still parsed — by husk — and it still
> becomes a file at a path built from an agent-supplied value. That is what is left, and it is
> what this brief is now about.**
>
> ## ★★ Updated 2026-08-05 — the premise moved a second time
>
> Two changes since the rewrite above, in opposite directions, and they interact:
>
> 1. **The scan narrowed to the header** (`79cd790`). husk now reads `#SBATCH` lines only in
>    the leading comment block, not the whole file. This fixed a false-reject on
>    heredoc-generated inner scripts. It is safe *only* because the body is inert to slurmd —
>    which is a load-bearing claim this review should attack rather than assume (N4 owns it).
> 2. **The parse now feeds husk's argv much more widely** (`da7a6e6`). husk interprets the
>    body's directives and **re-emits the whole resource family** onto sbatch's command line,
>    merged with the CLI by option name. Before this, resource directives were validated and
>    then silently dropped — which was a production outage: `#SBATCH --ntasks=64` got one task
>    and nothing said so.
>
> Together: **husk reads less of the file than it used to, and does more with what it reads.**
> A directive husk fails to see is now a directive that neither gets rejected *nor* re-emitted,
> in a script whose author expected it to take effect.

## The question

The agent authors the body. husk no longer forwards it, but it still **reads** it and still
**writes it to disk**. Can either be steered — can a body make husk emit something on the real
command line that the agent should not be able to set, or make husk write to a path it should
not?

## What the code does today

**The body is never executed as submitted.** `wrap_script` produces a script that is entirely
husk's: `#!/bin/bash`, the guard, and a handoff `exec /bin/bash "$_husk_body" "$@"`. It goes to
sbatch on **stdin**, so there is no file for anyone to substitute and no line the agent
contributed. The agent's `#SBATCH` directives therefore reach slurmd through **no channel at
all** — which also closed `hetjob`, `--mail-*`, and the `Ignored`-class gap that made every
dropped option an ungated body channel.

**But husk still parses the body**, for two purposes that both matter:

1. **Policy.** `body_reject_reason` rejects unknown `#SBATCH` directives, rejects
   `Class::Rejected` ones (`--qos`, `--reservation`), rejects `#BB`/`#DW`, and lets a small
   `dominated`/`dedicated` set through because husk reads their values and re-emits its own.
2. **Emission.** For `--output`, `--error`, `--chdir`, `--partition`, `--uenv`, `--view`, husk
   *takes the value from the directive*, validates and confines it, and puts **its own** option
   on the real command line.
3. ★ **Re-emission of the resource family.** Everything `Class::Allowed` in the registry —
   `--ntasks`, `--cpus-per-task`, `--time`, `--mem`, `--gres`, `--array`, `--distribution`, the
   rest — is now interpreted from the body and re-emitted, unless the CLI supplies the same
   option name. The merge key is the option name, computed by splitting the canonicalised
   token at the first `=` (`policy.rs:414`).

★★ **The tokeniser is BRAND NEW and nobody has attacked it — this is the freshest code on
your surface.** Until 2026-08-05 `sbatch_directives` split on whitespace with no lexing at
all. Two ordinary spellings were consequently refused:

```
#SBATCH --job-name="my run"      → ["--job-name=\"my", "run\""]        → REJECTED
#SBATCH --job-name="myrun"       → ["--job-name=\"myrun\""]            → REJECTED
#SBATCH --job-name=x # a note    → ["--job-name=x","#","a","note"]     → REJECTED
```

All three failed *closed*, on the value grammar rather than on the tokeniser, so none was an
injection. They were fixed anyway, because refusing ordinary run scripts is the same class
of bug as the outage above. **The fix added a real lexer to the most adversarial input path
in the system, and you are the first reviewer to see it.** Rules:

- `'` and `"` group and are stripped; a quote may open mid-token
- an unquoted `#` at a token boundary starts a comment; a `#` mid-token is left alone
- an unterminated quote rejects the submission rather than guessing
- **no continuation-line handling** — a trailing `\` becomes a stray token and rejects

Attack the lexer directly. It runs *before* every gate, so anything that makes it produce
different tokens than the author wrote changes what husk validates and what husk emits.
Specifically: can quote-stripping **fuse** two things into one accepted option, or **split**
one into two? (There is a test claiming the fused case fails closed via default-deny —
break it.) Does the `#` rule swallow something meaningful? What does a lone `"` do, or a
quote inside a quote, or a value that is entirely quotes?

**Two gates, and know which one is load-bearing.** After lexing, every re-emitted value must
pass a per-option charset grammar, and a registry-wide invariant test forbids
`" ' \ ; $ ` < >`, newline and tab for *every* `Allowed` option. That grammar — not the
lexer — is what keeps shell syntax out. So the question to answer is not "can I get a quote
through the lexer" but **"can I reach a grammar that accepts more than I thought"**;
`v_comment` permits spaces, `v_expr` permits `& | ( ) ! *`, `v_dist` permits `=`.

So the parse no longer feeds slurmd — it feeds **husk's own argv**. A misparse is no longer a
parser differential with the scheduler; it is husk emitting the wrong thing under its own name.

**And the body becomes a file.** It is written to
`<write-root>/.husk-body-<req.id>.sh`, where `req.id` is **agent-supplied**, validated by
`is_valid_id`: non-empty, ≤128 bytes, and `[A-Za-z0-9_-]` only. The guard later does
`rm -f "$_husk_body"` on that path.

## Starting points

1. **★ `req.id` decides a filesystem path, twice.** It names the file husk *writes* and the
   file the guard *deletes*. `is_valid_id` is the only thing between an agent-chosen string and
   both operations. It looks tight — no dot, no slash, so no traversal — so attack the edges:
   the length bound, a 128-byte name, a name that collides with something else husk writes into
   that directory (`.husk-step-spool-*`? a `slurm-%j.out`?), two requests racing on one id,
   an id that is a prefix of another. **A collision is as interesting as a traversal**: two
   requests whose body files are the same file is a way to make job A run job B's script.
2. **Steer husk's emission through the parse.** Can a body directive make husk emit an option
   value the agent could not set directly on the CLI? The `dominated`/`dedicated` split is the
   place: those are the options husk *reads from the body*. Malformed spellings, repeated
   directives, a value that passes husk's validator and means something else to SLURM.
3. ★ **Where the directive scan stops — and it stops earlier than it used to.** husk scans
   `#SBATCH` lines in the **header block only**; bash treats them as comments. Since the body
   no longer reaches slurmd this can no longer be a parity bug — but it can still be a *policy*
   bug, and the narrowing widened it: a directive husk does not see is a directive husk neither
   rejects nor re-emits, and a directive husk sees where bash sees a command changes husk's
   emission while the job does something else. Try: leading whitespace of every kind, `\r\n`, a
   BOM, `#SBATCH` after the first command, `#SBATCH` inside a heredoc or a quoted string,
   continuation lines, and specifically **what ends the header** — the first line that is
   neither a comment nor blank. Find a line husk treats as the end of the header that a human
   (or ICON's run-script generator) would not.

   Note the mitigation before you report: `unread_directive_note` warns on `#SBATCH`-looking
   lines husk did *not* read, but only where a human plausibly meant them for this job. A
   directive that lands in the silent gap between "not read" and "not warned about" is the
   finding.
4. **The body file is agent-writable and its path is predictable.** Rewriting it before the job
   runs changes only the agent's own payload — no boundary crossed, so that is not a finding by
   itself. What *would* be: making the guard's `rm -f` remove something else, or making the
   staged write land somewhere it should not.
5. **What the body does at runtime is the job's business.** It runs inside the cage, as the
   job. Do not report "the body can run arbitrary commands" — that is the product working. The
   only interesting runtime question is whether the body can reach *out*, which is A1/A4/A5.

## What counts as a finding

- Any `#SBATCH` spelling that changes what husk **emits** in a way the agent could not achieve
  by asking directly.
- An `id` that makes husk write, or the guard delete, a path other than the intended one —
  including by collision with another request or another husk file.
- A directive husk's scan misses that its policy should have rejected.
- The inverse: a legitimate run script (ICON sets `#SBATCH --output=…`) refused. That is the
  feature failing, and it is a finding.
- Anything that gets agent bytes back into the submitted script.

## What a null result looks like

The enumeration: spellings tried, ids tried, what husk emitted for each. Given the channel to
slurmd is closed by construction, **a thorough negative here is a strong result** — it is the
evidence that the structural fix holds under pressure rather than only in tests, and it is
directly convertible into selftest arms.

## Out of scope

- Re-proving that the body no longer reaches slurmd. It is pinned by tests and visible in the
  goldens; confirm cheaply and move on.
- The `--wrap` path (covered, F27), the step request body (A5), `req.env` (A2).
- Attacking slurmd itself, or anything needing privileges we do not have.

## Verdict

Execution inside; verdict outside. For emission questions the evidence is **what husk actually
put on the command line** — the broker log and the dry-run transcript show it. For path
questions the evidence is a file existing where it should not, seen from outside the cage.
