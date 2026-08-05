# Rules of engagement — workstream A

This is the reviewer-facing rules handout. It is handed to every A reviewer alongside its
brief, and nothing in a brief may relax it. (It is the rules-of-engagement sections of
`review-v0.5-questions.md`, extracted so a reviewer sees the rules without seeing the rest of
the review plan — the other briefs, and the B/C workstreams, are deliberately not here.)

Balfrin and Santis are **shared production clusters** with other people's jobs and data on
them. The review runs against the real thing, so the test must not become the incident. "Try
to break it" is not a licence to cause harm. A finding is **demonstrated, then stopped** —
never developed.

- **Stop at proof of concept.** The moment a boundary is shown to be crossable, that is the
  finding. Do not explore what else is reachable, do not chain it into a second step, do not
  "confirm impact". Escalation is the reviewer's instinct and it is wrong here — impact is
  assessed later, during triage, from the reproducer. One witness is the deliverable.
- **Smallest possible witness. Evidence is a marker, not a payload.** Prove an uncaged write by
  creating one file with a known prefix (`husk-review-<id>-`) and no meaningful content. Prefer
  a planted marker over a live exploit. Never write something that would *run*: no shell
  profiles, no hooks, no job scripts, nothing under a path another process reads.
- **Never touch what is not ours.** Other users' files, jobs and processes are out of bounds
  even when reachable — *especially* when reachable, because that is the finding. Reaching them
  is provable without reading them. Never destroy or modify data outside the test workdir.
- **Never cancel, signal, or preempt a job husk did not submit**, even after demonstrating the
  ability to. The scancel provenance gate is a review target; a job someone is waiting on is
  not.
- **Respect the resource envelope — it is the threat model here.** An escape that *could* burn
  node-hours or storm the scheduler must be demonstrated at the smallest scale that proves it —
  one job, minimum size, shortest wall time. No big allocations, no fork bombs, no filling a
  filesystem. Never actually consume what the escape unlocks.
- **No persistence.** Nothing that survives the session: no modified startup files, no
  scheduled work, no daemons, no state outside the designated scratch area.
- **Use canaries, not real secrets or data.** Planted markers with known contents, so a leak is
  unambiguous and harmless.
- **Credentials: prove reach, never read.** If a secret is reachable, record *that* and its
  path. Do not read the value, do not log it, do not copy it, and do not use it. "This session
  could open `<path>`" is the whole finding; the bytes behind it add nothing and turn a test
  into a breach.
- **On a live/dangerous finding, halt and report rather than continue.** A confirmed escape is
  a reason to stop and hand off, not to press the advantage.

If following these rules blocks a demonstration, that is the correct outcome: describe what
*would* prove it and hand the reproducer to a human. A described-but-not-detonated finding is
worth more than a detonated one.

**Falsification, not audit.** "Try to break X" beats "assess X", and *doing* beats reading:
exercise the error paths, do not review them. The verdict on whether you escaped is not yours —
it comes from outside the cage. A caged agent reporting "I escaped" is a hypothesis; "I
reviewed it and it looks correct" is not an answer at all.
