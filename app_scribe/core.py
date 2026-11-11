"""Navi Scribe command core: parse / timeline / flag / report.

Input model (read this before changing anything): Apex hands the
chip the words after its name as one string. Log text is PASTED
after the command, e.g.

    scribe parse auth Nov 10 02:14:01 lab sshd[1]: Failed ...

Multi-line pastes ride through as-is; literal \\n escapes in the
paste are also interpreted as line breaks, because chat boxes
often flatten pasted logs into one line. A `file <path>` form
exists for runner environments that do expose the filesystem;
when the file cannot be read the chip says so in plain words and
stops — it never pretends it read something it did not.
"""

try:
    from . import parsers
except ImportError:  # imported outside the package (should not happen)
    from app_scribe import parsers

VERSION = "1.0.0"
FORMATS = ("auth", "apache", "nginx", "syslog", "auto")
BRUTE_THRESHOLD = 5
OFF_HOURS = range(0, 5)  # 00:00-04:59

USAGE = """Navi Scribe 1.0.0 — log reader & report writer.

  scribe parse <format> <log lines>   structure: counts, IPs, users, events
  scribe timeline [format] <lines>    the events in chronological order
  scribe flag [format] <lines>        the lines that matter, and why
  scribe report [format] <lines>      a findings draft in report language
  scribe <command> file <path>        read the log from a file instead
                                      (only where the runner allows it)
  scribe --test                       self-test on a built-in sample log

  formats: auth (sshd/sudo/PAM), apache, nginx, syslog, auto (default)
  Paste the log lines right after the command; \\n escapes in the
  paste are read as line breaks."""

SAMPLE_LOG = """Nov 10 02:14:01 labhost sshd[1210]: Failed password for invalid user admin from 203.0.113.45 port 51111 ssh2
Nov 10 02:14:04 labhost sshd[1211]: Failed password for invalid user admin from 203.0.113.45 port 51114 ssh2
Nov 10 02:14:07 labhost sshd[1212]: Failed password for root from 203.0.113.45 port 51118 ssh2
Nov 10 02:14:11 labhost sshd[1213]: Failed password for invalid user oracle from 203.0.113.45 port 51121 ssh2
Nov 10 02:14:15 labhost sshd[1214]: Failed password for invalid user test from 203.0.113.45 port 51125 ssh2
Nov 10 02:14:19 labhost sshd[1215]: Failed password for alex from 203.0.113.45 port 51129 ssh2
Nov 10 02:15:02 labhost sshd[1220]: Accepted password for alex from 203.0.113.45 port 51140 ssh2
Nov 10 02:16:10 labhost sudo: alex : TTY=pts/0 ; PWD=/home/alex ; USER=root ; COMMAND=/usr/bin/apt update
Nov 10 02:17:44 labhost useradd[1301]: new user: name=practice, UID=1005, GID=1005, home=/home/practice, shell=/bin/bash
Nov 10 09:02:31 labhost sshd[1402]: Accepted password for alex from 192.168.1.20 port 52210 ssh2
Nov 10 09:03:05 labhost sshd[1403]: Disconnected from 192.168.1.20 port 52210
this line is not a log line at all"""


# ---------------------------------------------------------------- input

def _read_file(path):
    """Return (text, None) or (None, plain-words error)."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read(), None
    except OSError as exc:
        return None, (
            "scribe could not read the file '%s' (%s). The chip "
            "sandbox may not have access to that path — paste the "
            "log lines after the command instead; pasted text is "
            "the supported path." % (path, exc.strerror or exc))


def _extract_input(rest):
    """Split the post-command remainder into (fmt, text, error).

    `rest` is the raw string after the command word. A leading
    format word is consumed when present; `file <path>` switches
    to file input. Literal \\n escapes become line breaks.
    """
    rest = rest.strip()
    fmt = "auto"
    if rest:
        head, _, tail = rest.partition(" ")
        if head.lower() in FORMATS:
            fmt = head.lower()
            rest = tail.strip()
    if rest == "file" or rest.startswith("file ") or rest.startswith("--file"):
        parts = rest.split(None, 1)
        if len(parts) < 2 or not parts[1].strip():
            return fmt, None, "scribe file mode needs a path: scribe parse auth file /path/to/log"
        path = parts[1].strip().strip('"').strip("'").split()[0]
        text, err = _read_file(path)
        return fmt, text, err
    text = rest.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t")
    return fmt, text, None


def _get_records(rest):
    """Shared front door: (fmt, records, error_message)."""
    fmt, text, err = _extract_input(rest)
    if err:
        return fmt, None, err
    if text is None or not text.strip():
        return fmt, None, (
            "scribe needs log lines to work on — paste them after "
            "the command, e.g. `scribe flag auth <lines>`, or use "
            "`scribe --test` to see it work on a built-in sample.")
    return fmt, parsers.parse_text(text, fmt), None


# ---------------------------------------------------------------- helpers

def _counts(records, key):
    out = {}
    for rec in records:
        val = rec.get(key) or ""
        if val:
            out[val] = out.get(val, 0) + 1
    return out


def _ranked(counts):
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _time_range(records):
    dated = [r for r in records if r["sort_key"] is not None]
    if not dated:
        return "no parseable timestamps"
    lo = min(dated, key=lambda r: r["sort_key"])
    hi = max(dated, key=lambda r: r["sort_key"])
    note = ""
    if any(r["ts_note"] for r in dated):
        note = " (syslog stamps carry no year — the year is not in the log)"
    return "%s to %s%s" % (lo["ts_raw"], hi["ts_raw"], note)


def _short(text, limit=110):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _host_of(records):
    hosts = _counts(records, "host")
    return hosts and _ranked(hosts)[0][0] or "[HOST]"


# ---------------------------------------------------------------- commands

def cmd_parse(rest):
    fmt, records, err = _get_records(rest)
    if err:
        print(err)
        return
    parsed = [r for r in records if r["parsed"]]
    unparsed = [r for r in records if not r["parsed"]]
    out = []
    out.append("Navi Scribe — parse (%s)" % fmt)
    out.append("Lines in: %d · parsed: %d · unparsed: %d"
               % (len(records), len(parsed), len(unparsed)))
    out.append("Time range: %s" % _time_range(records))
    ips = _ranked(_counts(records, "ip"))
    users = _ranked(_counts(records, "user"))
    out.append("Unique source IPs (%d): %s" % (
        len(ips), ", ".join("%s (%d)" % kv for kv in ips) or "none found"))
    out.append("Unique users (%d): %s" % (
        len(users), ", ".join("%s (%d)" % kv for kv in users) or "none found"))
    events = _ranked(_counts(parsed, "event"))
    out.append("Events by type:")
    for name, n in events:
        out.append("  - %s: %d" % (name, n))
    if not events:
        out.append("  (none — nothing parsed)")
    out.append("First parsed records (fields, so you can see the structure):")
    shown = 0
    for rec in parsed:
        if shown >= 3:
            break
        out.append("  %d. time=%s | host=%s | process=%s | ip=%s | user=%s | event=%s" % (
            shown + 1, rec["ts_raw"] or "-", rec["host"] or "-",
            rec["process"] or "-", rec["ip"] or "-", rec["user"] or "-",
            rec["event"]))
        out.append("     message: %s" % _short(rec["message"]))
        shown += 1
    if not parsed:
        out.append("  (none parsed — check the format; 'auto' is the forgiving one)")
    if unparsed:
        out.append("Unparsed lines are counted, never hidden: %d line(s) "
                   "did not match the %s shape." % (len(unparsed), fmt))
    print("\n".join(out))


def cmd_timeline(rest):
    fmt, records, err = _get_records(rest)
    if err:
        print(err)
        return
    dated = sorted((r for r in records if r["sort_key"] is not None),
                   key=lambda r: r["sort_key"])
    undated = [r for r in records if r["sort_key"] is None]
    out = ["Navi Scribe — timeline (%s): %d dated event(s)" % (fmt, len(dated))]
    for rec in dated:
        who = " ".join(x for x in (rec["ip"], rec["user"]) if x)
        out.append("  [%s] %-16s %-28s %s" % (
            rec["ts_raw"], rec["event"], who, _short(rec["message"], 80)))
    if undated:
        out.append("Undated lines (no parseable timestamp — listed "
                   "honestly, in input order): %d" % len(undated))
        for rec in undated:
            out.append("  [no time] %s" % _short(rec["raw"], 100))
    if any(r["ts_note"] for r in dated):
        out.append("Note: syslog timestamps carry no year; ordering is "
                   "by month/day/time as written in the log.")
    print("\n".join(out))


def _flag_findings(records):
    """Return a list of (title, detail, why) findings."""
    findings = []
    failed = [r for r in records if r["event"] in ("failed_login", "auth_failure")]
    accepted = [r for r in records if r["event"] == "accepted_login"]
    fail_by_ip = _ranked(_counts(failed, "ip"))
    fail_by_user = _ranked(_counts(failed, "user"))
    for ip, n in fail_by_ip:
        if n >= BRUTE_THRESHOLD:
            findings.append((
                "Brute-force suspicion: %d failed logins from %s" % (n, ip),
                "Failed-login count from one source passed the threshold of %d." % BRUTE_THRESHOLD,
                "Repeated failures from a single IP is the classic password-guessing shape; one success after it can mean the guessing worked."))
        elif n >= 2:
            findings.append((
                "Repeated failures: %d failed logins from %s" % (n, ip),
                "Below the brute-force threshold of %d, but not a one-off." % BRUTE_THRESHOLD,
                "A couple of failures is a typo; a run of them is someone working a list."))
    for user, n in fail_by_user:
        if n >= BRUTE_THRESHOLD:
            findings.append((
                "Targeted account: %d failed logins against user '%s'" % (n, user),
                "Failures concentrate on one account.",
                "Concentration on one name suggests the attacker knows or is hunting a real account."))
    fail_ips = {r["ip"] for r in failed if r["ip"]}
    for rec in accepted:
        if rec["ip"] and rec["ip"] in fail_ips:
            findings.append((
                "SUCCESS AFTER FAILURES from %s: user '%s' logged in at %s"
                % (rec["ip"], rec["user"] or "?", rec["ts_raw"] or "an undated line"),
                "The same source that failed now holds a successful login.",
                "This is the story in the log: guessing that ends in a success is a compromise until you prove it was the owner mistyping."))
    for rec in records:
        if rec["event"] == "sudo":
            findings.append((
                "Sudo used by '%s' at %s" % (rec["user"] or "?", rec["ts_raw"] or "an undated line"),
                _short(rec["message"], 120),
                "Sudo is privilege being exercised; in a report you account for every use, expected or not."))
        if rec["event"] == "useradd":
            findings.append((
                "New user created: '%s' at %s" % (rec["user"] or "?", rec["ts_raw"] or "an undated line"),
                _short(rec["message"], 120),
                "New accounts are persistence-shaped; a user nobody can explain is a finding on its own."))
    for rec in accepted:
        if rec["hour"] is not None and rec["hour"] in OFF_HOURS:
            findings.append((
                "Off-hours successful login: '%s' from %s at %s"
                % (rec["user"] or "?", rec["ip"] or "?", rec["ts_raw"]),
                "Successful login between 00:00 and 04:59 local log time.",
                "Worth a look, not an accusation — plenty of owners work nights, but an unexplained 2 a.m. login is exactly what reviews are for."))
    return findings


def cmd_flag(rest):
    fmt, records, err = _get_records(rest)
    if err:
        print(err)
        return
    findings = _flag_findings(records)
    failed = [r for r in records if r["event"] in ("failed_login", "auth_failure")]
    out = ["Navi Scribe — flag (%s): %d finding(s)" % (fmt, len(findings))]
    out.append("Failed logins: %d total · by IP: %s · by user: %s" % (
        len(failed),
        ", ".join("%s (%d)" % kv for kv in _ranked(_counts(failed, "ip"))) or "none",
        ", ".join("%s (%d)" % kv for kv in _ranked(_counts(failed, "user"))) or "none"))
    if not findings:
        out.append("Nothing flagged. Quiet logs are a result too — "
                   "say so in the report rather than inventing drama.")
    for i, (title, detail, why) in enumerate(findings, 1):
        out.append("%d. %s" % (i, title))
        out.append("   %s" % detail)
        out.append("   Why this matters: %s" % why)
    print("\n".join(out))


def cmd_report(rest):
    fmt, records, err = _get_records(rest)
    if err:
        print(err)
        return
    parsed = [r for r in records if r["parsed"]]
    unparsed_n = len(records) - len(parsed)
    findings = _flag_findings(records)
    events = _ranked(_counts(parsed, "event"))
    host = _host_of(records)
    out = []
    out.append("FINDINGS DRAFT — Navi Scribe (adapt freely; placeholders "
               "mark what the log does not say)")
    out.append("")
    out.append("Title: Log review of %s — %d line(s) examined" % (host, len(records)))
    out.append("Scope: %d pasted log line(s) (%s format), %d parsed, %d unparsed."
               % (len(records), fmt, len(parsed), unparsed_n))
    out.append("Period covered: %s." % _time_range(records))
    out.append("Host: %s. Reviewer: [REVIEWER]." % host)
    out.append("")
    out.append("Summary: The log records %s." % (
        ", ".join("%d %s event(s)" % (n, name) for name, n in events) or "no parseable events"))
    out.append("")
    out.append("Findings:")
    if not findings:
        out.append("  1. No anomalous activity was identified in the lines "
                   "reviewed. All parsed events were routine for this host.")
    for i, (title, detail, why) in enumerate(findings, 1):
        out.append("  %d. %s. %s" % (i, title, detail))
    out.append("")
    out.append("What I'd check next:")
    checks = []
    if any("SUCCESS AFTER FAILURES" in t for t, _, _ in findings):
        checks.append("Confirm with the account owner whether the successful "
                      "login was theirs; if not, treat the account as "
                      "compromised: force a password change and review "
                      "active sessions.")
    if any("Brute-force" in t for t, _, _ in findings):
        checks.append("Check whether the flagged source IP appears anywhere "
                      "else in the full log set, and whether fail2ban or "
                      "an equivalent control is in place.")
    if any("New user" in t for t, _, _ in findings):
        checks.append("Verify the new account against change records — who "
                      "authorised it, and does it still need to exist?")
    if any("Sudo" in t for t, _, _ in findings):
        checks.append("Match each sudo use to a task or ticket; unexplained "
                      "privilege use gets its own line in the final report.")
    if any("Off-hours" in t for t, _, _ in findings):
        checks.append("Ask the account owner about the off-hours login "
                      "before writing it up as anything stronger than an "
                      "observation.")
    checks.append("Widen the window: review the full day's log, not just "
                  "the pasted lines, before finalising these findings.")
    for c in checks:
        out.append("  - %s" % c)
    print("\n".join(out))


# ---------------------------------------------------------------- self-test

def cmd_test():
    records = parsers.parse_text(SAMPLE_LOG, "auth")
    checks = []

    def check(label, ok, detail=""):
        checks.append((label, ok, detail))

    parsed = [r for r in records if r["parsed"]]
    check("sample parses (11 of 12 lines; 1 deliberately unparsed)",
          len(parsed) == 11 and len(records) == 12,
          "%d parsed / %d total" % (len(parsed), len(records)))
    failed = [r for r in records if r["event"] == "failed_login"]
    check("six failed logins counted", len(failed) == 6, "%d" % len(failed))
    findings = _flag_findings(records)
    titles = " | ".join(t for t, _, _ in findings)
    check("brute-force flag raised (>=5 failures from one IP)",
          "Brute-force suspicion" in titles and "203.0.113.45" in titles, titles)
    check("success-after-failures story caught",
          "SUCCESS AFTER FAILURES" in titles, titles)
    check("sudo use flagged", "Sudo used" in titles, titles)
    check("new-user event flagged", "New user created" in titles, titles)
    check("off-hours login flagged (02:15 success)",
          "Off-hours" in titles, titles)
    timeline_records = sorted(
        (r for r in records if r["sort_key"] is not None),
        key=lambda r: r["sort_key"])
    check("timeline sorts the success after the failures",
          timeline_records[5]["event"] == "failed_login"
          and timeline_records[6]["event"] == "accepted_login",
          "%s -> %s" % (timeline_records[5]["event"],
                        timeline_records[6]["event"]))
    web = parsers.parse_text(
        '198.51.100.7 - - [10/Nov/2026:09:00:00 +0000] '
        '"GET /index.html HTTP/1.1" 200 1234 "-" "curl/8"', "auto")
    check("auto-detect reads a web line",
          web and web[0]["parsed"] and web[0]["event"] == "http_2xx",
          web[0]["event"] if web else "no record")
    flood = parsers.parse_text("\n".join("garbage line %d" % i for i in range(50)), "auto")
    check("malformed flood never crashes, all counted unparsed",
          len(flood) == 50 and not any(r["parsed"] for r in flood),
          "%d records" % len(flood))

    passed = 0
    for label, ok, detail in checks:
        print("%s %s%s" % ("PASS" if ok else "FAIL", label,
                           (" — " + detail) if (detail and not ok) else ""))
        passed += 1 if ok else 0
    print("self-test: %d/%d passed" % (passed, len(checks)))


# ---------------------------------------------------------------- dispatch

def run_command(argv_text):
    """Entry from root.py: argv_text is the raw string after the
    chip name (NOT shlex-split — log lines contain quotes)."""
    text = (argv_text or "").strip()
    if not text:
        print(USAGE)
        return
    head, _, rest = text.partition(" ")
    head = head.lower()
    rest = rest.strip()
    # A newline right after the command word also separates.
    if "\n" in head:
        head, _, tail = text.partition("\n")
        head = head.strip().lower()
        rest = tail.strip()
    if head in ("--test", "test") and not rest:
        cmd_test()
    elif head == "parse":
        cmd_parse(rest)
    elif head == "timeline":
        cmd_timeline(rest)
    elif head == "flag":
        cmd_flag(rest)
    elif head == "report":
        cmd_report(rest)
    elif head in ("--help", "help", "-h"):
        print(USAGE)
    else:
        print("scribe doesn't know '%s'. " % head)
        print(USAGE)
