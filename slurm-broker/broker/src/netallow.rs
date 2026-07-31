//! The network allowlist: which host and port a caged job may reach.
//!
//! This is the whole security decision of the network phase, so it lives on its own,
//! is a pure function of its inputs, and is tested against the escapes rather than the
//! happy path.
//!
//! # Why an allowlist at all, and why it is not the only wall
//!
//! Opening the network REACTIVATES AV8: a job with a route can reach `slurmctld` and
//! submit work that never passes the broker — the exact bypass husk exists to prevent.
//! Two independent things stop that, and the allowlist is only one of them:
//!
//! * the scheduler is not on the allowlist (enforced here, by construction — see
//!   `SCHEDULER_PORTS`), and
//! * `/run/munge` stays masked in every cage, so a job cannot authenticate to the
//!   scheduler even if it somehow reaches it.
//!
//! The mask is the load-bearing one. AF_UNIX taught us that reachability has to be judged
//! per DESTINATION and that a syscall filter cannot do it; the same reasoning says a
//! host allowlist should not be the only thing between a job and the scheduler.
//!
//! # Where the shape comes from
//!
//! The pattern language matches Anthropic's `sandbox-runtime`, deliberately: it is a
//! shape their users already write, and its three parsing defences are a bug list we get
//! to inherit rather than rediscover (see `split_port`, `matches_host`). The
//! implementation is ours — theirs lives inside the runtime husk removes in v0.6, so
//! building on it would be a dead end, and it would put vendor code on the enforcement
//! path, which the axiom forbids.

/// Ports the scheduler speaks on. An allowlist entry naming one is refused outright,
/// whatever host it names.
///
/// This is belt to the MUNGE mask's braces. It is *not* a claim that these are the only
/// ways to reach a scheduler — a site can move them, and a compromised host on the
/// allowlist could proxy onward — which is exactly why the mask, not this list, is what
/// the guarantee rests on. What this buys is that the obvious mistake (an operator
/// allowing the controller host "so job monitoring works") fails at configuration time
/// with an explanation, rather than silently reopening AV8.
const SCHEDULER_PORTS: &[u16] = &[6817, 6818, 6819, 6820];

/// Why a candidate allowlist entry was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum EntryError {
    Empty,
    TooLong,
    /// A scheme, path, or credentials — an entry is a host, not a URL.
    NotAHost(&'static str),
    /// `*`, `*.com` and friends: broad enough to be indistinguishable from no policy.
    TooBroad,
    /// Names a port the scheduler speaks on (see `SCHEDULER_PORTS`).
    SchedulerPort(u16),
    BadPort,
    BadHostChar,
}

impl std::fmt::Display for EntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryError::Empty => write!(f, "an allowlist entry cannot be empty"),
            EntryError::TooLong => write!(f, "an allowlist entry may be at most 255 characters"),
            EntryError::NotAHost(what) => write!(
                f,
                "an allowlist entry is a host, not a URL: remove the {what}"
            ),
            EntryError::TooBroad => write!(
                f,
                "too broad. A wildcard must have at least two labels after it \
                 (`*.example.com`, not `*.com` or `*`) — an entry that matches most of \
                 the internet is not a policy"
            ),
            EntryError::SchedulerPort(p) => write!(
                f,
                "port {p} is a SLURM daemon port. A caged job that can reach the \
                 scheduler could submit work that never passes the broker (AV8), which is \
                 the bypass husk exists to prevent. Job control goes through the broker."
            ),
            EntryError::BadPort => write!(f, "the :port suffix must be a number in 1-65535"),
            EntryError::BadHostChar => write!(f, "a host may contain only letters, digits, `.`, `-` and `_`"),
        }
    }
}

/// One validated allowlist entry.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Entry {
    host: String,
    /// `None` matches any port.
    port: Option<u16>,
    wildcard: bool,
}

/// Split a trailing `:port`, if there is one.
///
/// **The suffix must be strictly numeric.** `evil.com:443.allowed.com` therefore does NOT
/// split — it stays whole and fails host validation on the remaining `:`. Treating any
/// trailing `:...` as a port would make that string parse as host `evil.com` with a
/// nonsense port, which is a parser differential of exactly the F13/F14 kind: our reading
/// and the connecting code's reading would disagree about which host was authorised.
/// Borrowed from `sandbox-runtime`, which had already worked this out.
fn split_port(s: &str) -> (&str, Option<&str>) {
    match s.rfind(':') {
        None => (s, None),
        Some(i) => {
            let suffix = &s[i + 1..];
            let numeric = !suffix.is_empty()
                && suffix.len() <= 5
                && !suffix.starts_with('0')
                && suffix.bytes().all(|b| b.is_ascii_digit());
            if numeric {
                (&s[..i], Some(suffix))
            } else {
                (s, None)
            }
        }
    }
}

impl Entry {
    /// Validate one operator-supplied entry.
    pub fn parse(raw: &str) -> Result<Entry, EntryError> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(EntryError::Empty);
        }
        if raw.len() > 255 {
            return Err(EntryError::TooLong);
        }
        if raw.contains("://") {
            return Err(EntryError::NotAHost("scheme"));
        }
        if raw.contains('/') {
            return Err(EntryError::NotAHost("path"));
        }
        if raw.contains('@') {
            return Err(EntryError::NotAHost("credentials"));
        }

        let (host, port) = split_port(raw);
        let port = match port {
            None => None,
            Some(p) => match p.parse::<u16>() {
                Ok(0) | Err(_) => return Err(EntryError::BadPort),
                Ok(p) => Some(p),
            },
        };
        if let Some(p) = port {
            if SCHEDULER_PORTS.contains(&p) {
                return Err(EntryError::SchedulerPort(p));
            }
        }

        let (wildcard, base) = match host.strip_prefix("*.") {
            Some(b) => (true, b),
            None => (false, host),
        };
        if base.is_empty() || base.contains('*') || base.contains(':') {
            return Err(EntryError::BadHostChar);
        }
        if !base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        {
            return Err(EntryError::BadHostChar);
        }
        // A wildcard needs at least two labels after it, so `*.com` and `*` are refused.
        // Anything that matches most of the internet is indistinguishable from no policy,
        // and an allowlist nobody can reason about is worse than an honest deny-all.
        if wildcard && base.split('.').filter(|l| !l.is_empty()).count() < 2 {
            return Err(EntryError::TooBroad);
        }
        if !wildcard && host.contains('*') {
            return Err(EntryError::TooBroad);
        }
        Ok(Entry { host: base.to_ascii_lowercase(), port, wildcard })
    }

    /// Does this entry authorise a connection to `host:port`?
    fn matches(&self, host: &str, port: u16) -> bool {
        if let Some(p) = self.port {
            if p != port {
                return false;
            }
        }
        let h = host.to_ascii_lowercase();
        if !self.wildcard {
            return h == self.host;
        }
        // A wildcard never matches an IP literal. Without this,
        // `1.2.3.4%x.allowed.com` — or any name crafted to end with the base — can satisfy
        // a suffix test while the connection is made to the bare address. Suffix matching
        // on something that is not a domain name is not meaningful.
        if is_ip_literal(&h) {
            return false;
        }
        // Strict subdomain only: `*.example.com` does not match `example.com` itself.
        h.len() > self.host.len() + 1
            && h.ends_with(&self.host)
            && h.as_bytes()[h.len() - self.host.len() - 1] == b'.'
    }
}

/// Is this a bare IP address rather than a hostname?
///
/// Deliberately crude and deliberately over-inclusive: it only decides whether wildcard
/// suffix matching applies, and over-inclusion refuses a match rather than granting one.
fn is_ip_literal(h: &str) -> bool {
    h.contains(':') // any IPv6 form, bracketed or not
        || (h.split('.').count() == 4
            && h.split('.').all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit())))
}

/// The compiled policy: what a caged job may reach.
#[derive(Debug, Default, Clone)]
pub struct Allowlist {
    entries: Vec<Entry>,
}

impl Allowlist {
    /// Compile operator-supplied entries. Every rejection carries its reason, because an
    /// allowlist that silently drops an entry is one an operator believes is in force.
    pub fn parse(raw: &[String]) -> Result<Allowlist, String> {
        let mut entries = Vec::new();
        for r in raw {
            match Entry::parse(r) {
                Ok(e) => entries.push(e),
                Err(why) => return Err(format!("network allowlist entry {r:?}: {why}")),
            }
        }
        Ok(Allowlist { entries })
    }

    /// DEFAULT DENY. An empty allowlist permits nothing — it is not "unset, so allow".
    /// This is the direction every mistake should fall in: a missing config file, a typo
    /// in a key name, or a policy that failed to load must leave a job with no egress,
    /// never with all of it.
    pub fn permits(&self, host: &str, port: u16) -> bool {
        if host.is_empty() || !is_valid_request_host(host) {
            return false;
        }
        if SCHEDULER_PORTS.contains(&port) {
            return false;
        }
        self.entries.iter().any(|e| e.matches(host, port))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Is the host in a CONNECT request even well-formed?
///
/// Checked before matching, not after: a request host carrying `%` (an IPv6 zone id), a
/// NUL, or whitespace has no business being compared against a pattern at all, and
/// rejecting it here means no matcher below has to be careful about it.
fn is_valid_request_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 255
        && !h.contains('%')
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_:[]".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(entries: &[&str]) -> Allowlist {
        Allowlist::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn an_empty_allowlist_permits_nothing() {
        // DEFAULT DENY. The direction every failure must fall in: no config, a typo in a
        // key, a policy that failed to load - all leave a job with no egress.
        let a = Allowlist::default();
        assert!(!a.permits("api.anthropic.com", 443));
        assert!(a.is_empty());
    }

    #[test]
    fn exact_and_wildcard_hosts_match_as_written() {
        let a = list(&["api.inference.cscs.ch", "*.example.com"]);
        assert!(a.permits("api.inference.cscs.ch", 443));
        assert!(a.permits("API.INFERENCE.CSCS.CH", 443), "host matching is case-insensitive");
        assert!(!a.permits("evil.api.inference.cscs.ch", 443), "exact means exact");
        assert!(a.permits("a.example.com", 443));
        assert!(a.permits("deep.nested.example.com", 443));
        assert!(!a.permits("example.com", 443), "*.x is a STRICT subdomain match");
        assert!(!a.permits("notexample.com", 443), "suffix matching must respect the dot");
        assert!(!a.permits("example.com.evil.net", 443));
    }

    #[test]
    fn a_port_suffix_restricts_the_entry_and_its_absence_does_not() {
        let a = list(&["api.example.com:443", "any.example.com"]);
        assert!(a.permits("api.example.com", 443));
        assert!(!a.permits("api.example.com", 8080), "the port suffix is a restriction");
        assert!(a.permits("any.example.com", 8080), "no suffix means any port");
    }

    #[test]
    fn a_smuggled_port_suffix_does_not_split() {
        // THE PARSER DIFFERENTIAL. If any trailing `:...` were treated as a port, this
        // would parse as host `evil.com` and authorise it, while the text an operator
        // read says `allowed.com`. The suffix must be strictly numeric, so the string
        // stays whole and then fails host validation on the remaining `:`.
        assert_eq!(split_port("evil.com:443.allowed.com"), ("evil.com:443.allowed.com", None));
        assert!(Entry::parse("evil.com:443.allowed.com").is_err());
        let a = list(&["allowed.com"]);
        assert!(!a.permits("evil.com", 443));
    }

    #[test]
    fn a_wildcard_never_matches_an_ip_literal() {
        // Otherwise a name crafted to end with the base satisfies the suffix test while
        // the connection goes to the bare address. Suffix matching a non-name is not
        // meaningful, so it is refused rather than interpreted.
        let a = list(&["*.example.com"]);
        assert!(!a.permits("1.2.3.4", 443));
        assert!(!a.permits("::ffff:1.2.3.4", 443));
        assert!(!a.permits("1.2.3.4%eth0.example.com", 443), "zone ids are refused outright");
    }

    #[test]
    fn overly_broad_entries_are_refused_at_configuration_time() {
        // An allowlist that matches most of the internet is indistinguishable from no
        // policy - and worse than an honest deny-all, because it reads like a control.
        for bad in ["*", "*.com", "*.", "*.x"] {
            assert!(Entry::parse(bad).is_err(), "must refuse {bad:?}");
        }
        assert!(Entry::parse("*.example.com").is_ok());
    }

    #[test]
    fn an_entry_is_a_host_not_a_url() {
        for (bad, _) in [
            ("https://example.com", "scheme"),
            ("example.com/path", "path"),
            ("user@example.com", "credentials"),
        ] {
            assert!(Entry::parse(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn the_scheduler_cannot_be_allowlisted() {
        // Opening the network reactivates AV8: a job that reaches slurmctld can submit
        // work that never passes the broker. This refuses the obvious operator mistake
        // ("allow the controller so monitoring works") at configuration time with an
        // explanation, rather than silently reopening the bypass.
        //
        // NOT the guarantee - a site can move these ports and an allowed host could
        // proxy onward. The guarantee is the /run/munge mask: a job cannot authenticate
        // to the scheduler even if it reaches it.
        for p in [6817, 6818, 6819, 6820] {
            assert_eq!(
                Entry::parse(&format!("slurmctld.example.com:{p}")),
                Err(EntryError::SchedulerPort(p))
            );
            // ...and an entry with no port suffix must not become a way in either.
            let a = list(&["slurmctld.example.com"]);
            assert!(!a.permits("slurmctld.example.com", p), "port {p} must stay closed");
        }
    }

    #[test]
    fn a_malformed_request_host_is_refused_before_it_is_matched() {
        let a = list(&["example.com", "*.example.com"]);
        for bad in ["", "ex ample.com", "example.com\0", "a%b.example.com"] {
            assert!(!a.permits(bad, 443), "must refuse request host {bad:?}");
        }
    }

    #[test]
    fn a_bad_entry_names_itself_and_its_reason() {
        // An allowlist that silently drops an entry is one the operator believes is in
        // force. Compilation fails loudly instead, naming the entry.
        let err = Allowlist::parse(&["ok.example.com".into(), "*.com".into()]).unwrap_err();
        assert!(err.contains("*.com"), "must name the offending entry: {err}");
        assert!(err.contains("two labels"), "must explain: {err}");
    }
}
