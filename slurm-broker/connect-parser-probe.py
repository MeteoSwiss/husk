#!/usr/bin/env python3
"""A9's CONNECT-parser battery — finally run against a live egress proxy.

WHY THIS FILE EXISTS
--------------------
A9 (the network-allowlist brief) could not exercise the proxy at all: it found nothing
listening on :3128 and reported an enumerated negative result, leaving "a ready-to-run
parser test table for whoever can run it in a context where the proxy IS reachable".

That empty :3128 was not an architectural property, which is how it read at the time
("the egress channel is not wired up on the client side"). It was the CSCS relay
BLACKOUT — husk's own `denyRead /users` starved the relay of its install under
~/.local/share/claude. Fixed since; the relay works and husk-verify proves egress on
both clusters. So the parser table is simply UNRUN, not inapplicable, and a null result
produced by a broken instrument is the false-friend shape this project keeps meeting.

WHAT IT ASKS
------------
The proxy authorises a NAME and then makes a CONNECTION. Can those come apart? It speaks
RAW BYTES so curl's normalisation cannot hide a differential, and it checks the two
properties the shipped config depends on:

  * the allowlist entry is PORT-SCOPED (`host:443`), so the same host on another port
    must be refused — A9's observation O2 (a port-less entry authorises a generic TCP
    tunnel on EVERY port) does not apply to a scoped entry, but only a live test shows
    that the scoping is actually enforced rather than parsed and dropped;
  * a name that merely CONTAINS the allowed host must not inherit its authorisation.

Every vector carries its EXPECTED disposition, so the run self-evaluates instead of
leaving a table for a human to interpret. A 200 where REFUSE was expected is a finding.

TWO DIFFERENT PROXIES ANSWER ON :3128 — KNOW WHICH ONE YOU TESTED
----------------------------------------------------------------
  * inside a BROKERED JOB  -> socat -> husk's own proxy (`netproxy.rs` + `netallow.rs`).
    This is A9's actual target and the only one whose findings husk can FIX. Run the job
    script beside this file: `slurm-broker/connect-parser-job.sh`.
  * inside the LOGIN cage  -> Anthropic's `srt` proxy (basic-auth user `srt.*`). Worth
    testing because husk's login confidentiality leans on it, but a finding there is an
    UPSTREAM REPORT, not a husk fix.

The probe prints which one it is talking to; do not file a finding without that line.

RUN IT INSIDE A LIVE husk SESSION (the proxy lives in the cage's netns):
    !python3 ~/husk/slurm-broker/connect-parser-probe.py

It reads the proxy address and credential from the environment husk already set; it
never prints the credential. It opens a CONNECT, reads the status line, and closes —
it transfers no payload and exfiltrates nothing.
"""
import base64
import os
import socket
import sys
from urllib.parse import urlparse

ALLOWED_HOST = os.environ.get("HUSK_PROBE_ALLOWED_HOST", "opendatadocs.meteoswiss.ch")
ALLOWED_PORT = os.environ.get("HUSK_PROBE_ALLOWED_PORT", "443")

ALLOW, REFUSE = "ALLOW", "REFUSE"


def proxy_from_env():
    """(host, port, 'user:pass'|None) from the proxy vars husk injects."""
    raw = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    if not raw:
        return None
    u = urlparse(raw)
    auth = f"{u.username}:{u.password}" if u.username else None
    return (u.hostname or "127.0.0.1", u.port or 3128, auth)


def probe(target: bytes, auth):
    """Send one raw CONNECT; return (status_int_or_None, detail)."""
    host, port, cred = auth
    try:
        s = socket.create_connection((host, port), timeout=8)
    except Exception as e:                       # relay down: not a parser verdict
        return None, f"proxy unreachable: {e}"
    hdr = b""
    if cred:
        hdr = b"Proxy-Authorization: Basic " + base64.b64encode(cred.encode()) + b"\r\n"
    try:
        s.sendall(b"CONNECT " + target + b" HTTP/1.1\r\n" + hdr + b"\r\n")
        first = s.recv(256).split(b"\r\n")[0]
    except Exception as e:
        return None, f"send/recv failed: {e}"
    finally:
        s.close()
    parts = first.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1]), first.decode("latin-1", "replace")
    return None, first.decode("latin-1", "replace")


def vectors():
    h = ALLOWED_HOST.encode()
    p = ALLOWED_PORT.encode()
    return [
        # --- the baseline: the one thing that must work ------------------------
        ("baseline-allowed",       h + b":" + p,                    ALLOW),

        # --- PORT SCOPING. The shipped entry is host:443. If the port is parsed
        #     and then ignored, these become a generic TCP tunnel (A9's O2).
        ("scoped-ssh-port",        h + b":22",                      REFUSE),
        ("scoped-postgres-port",   h + b":5432",                    REFUSE),
        ("scoped-slurmctld-port",  h + b":6817",                    REFUSE),
        ("scoped-arbitrary-port",  h + b":47322",                   REFUSE),

        # --- name-vs-authorisation differentials (A9 §1) -----------------------
        ("trailing-dot",           h + b".:" + p,                   REFUSE),
        ("uppercase",              ALLOWED_HOST.upper().encode() + b":" + p, ALLOW),
        ("userinfo-at",            h + b"@evil.example:" + p,       REFUSE),
        ("userinfo-at-reversed",   b"evil.example@" + h + b":" + p, REFUSE),
        ("suffix-append",          h + b".evil.example:" + p,       REFUSE),
        ("prefix-glue",            b"evil-" + h + b":" + p,         REFUSE),
        ("substring-host",         b"not-" + h + b".evil.example:" + p, REFUSE),
        # `:0443` parses as decimal 443, so this IS the allowlisted endpoint. MEASURED
        # 2026-08-26 on Balfrin: gate authorised 443 and dialled 443
        # (`allowed: opendatadocs.meteoswiss.ch:443 -> 185.199.108.153:443`). husk parses
        # ONCE and authorises the value it dials, so a spelling variant cannot come apart
        # from what is reached — the differential this row was hunting is structurally
        # impossible here, and the allowlist compares parsed ports rather than strings,
        # which is the right choice. Expectation corrected from REFUSE; the original was
        # the probe assuming a gap husk's design forecloses.
        ("port-leading-zero",      h + b":0" + p,                   ALLOW),
        ("double-port",            h + b":" + p + b":" + p,         REFUSE),
        ("trailing-colon-junk",    h + b":...",                     REFUSE),
        ("space-before-port",      h + b" :" + p,                   REFUSE),
        ("embedded-tab",           h + b"\t:" + p,                  REFUSE),
        ("embedded-cr",            h + b"\r.evil.example:" + p,     REFUSE),
        ("nonnumeric-port",        h + b":https",                   REFUSE),
        ("absurd-length-host",     b"a" * 300 + b"." + h + b":" + p, REFUSE),

        # --- name vs address (A9 §3): literals for endpoints never allowlisted --
        ("ipv6-loopback",          b"[::1]:" + p,                   REFUSE),
        ("ipv6-mapped-loopback",   b"[::ffff:127.0.0.1]:" + p,      REFUSE),
        ("ip-literal-private",     b"10.0.0.1:22",                  REFUSE),
        ("ip-literal-loopback",    b"127.0.0.1:6817",               REFUSE),

        # --- scheduler ports, refused even under `*` (A9 §5) -------------------
        ("slurmctld-by-name",      b"slurmctld.balfrin:6817",       REFUSE),
        ("slurmd-port",            b"localhost:6818",               REFUSE),

        # --- a plainly unlisted host -------------------------------------------
        ("unlisted-host",          b"github.com:443",               REFUSE),
    ]


def main():
    auth = proxy_from_env()
    if not auth:
        print("connect-parser-probe: no proxy in the environment "
              "(HTTPS_PROXY/HTTP_PROXY unset).")
        print("  Run me INSIDE a live husk session — outside one there is no gate to test.")
        return 2
    host, port, cred = auth
    # Which proxy answered decides who OWNS a finding, so say it before any verdict.
    user = cred.split(":", 1)[0] if cred else ""
    if user.startswith("srt"):
        whose = "Anthropic srt (LOGIN cage) — a finding here is an UPSTREAM report"
    elif cred:
        whose = "unrecognised proxy — identify it before filing anything"
    else:
        whose = "husk netproxy (JOB cage) — a finding here is a husk BUG to fix"
    print(f"connect-parser-probe — proxy {host}:{port}, auth "
          f"{'present' if cred else 'none'}")
    print(f"  talking to: {whose}")
    print(f"  allowlist entry under test: {ALLOWED_HOST}:{ALLOWED_PORT}\n")

    findings, unknown, ok = [], [], 0
    for label, target, expect in vectors():
        status, detail = probe(target, auth)
        if status is None:
            unknown.append((label, detail))
            print(f"  ????   {label:24s} {detail[:70]}")
            continue
        got = ALLOW if status == 200 else REFUSE
        if got == expect:
            ok += 1
            print(f"  ok     {label:24s} {status} ({got.lower()}, as expected)")
        else:
            findings.append((label, target, status, expect, got))
            flag = "FINDING" if expect == REFUSE else "BROKEN "
            print(f"  {flag} {label:24s} {status} -> {got}, expected {expect}")

    print()
    if findings:
        print(f"{len(findings)} DISAGREEMENT(S) between the name and its authorisation:")
        for label, target, status, expect, got in findings:
            print(f"  - {label}: sent {target!r} -> {status} ({got}), expected {expect}")
        print("\nA REFUSE-expected row that returned 200 means the gate authorised a name")
        print("it should not have. Pair it with the proxy's net-proxy.log (what it")
        print("authorised) and the far end (what it dialled) before filing.")
    else:
        print(f"no disagreements: {ok} vectors behaved as expected.")
    if unknown:
        print(f"\n{len(unknown)} vector(s) inconclusive (proxy unreachable / no status line).")
    return 1 if findings else (2 if unknown else 0)


if __name__ == "__main__":
    sys.exit(main())
