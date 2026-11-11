# Navi Scribe

A log reader and report writer that rides inside a single Apex
chip — built for a cybersecurity student. Paste log lines in and
get four things back: the **structure** (what kind of lines, whose,
from where), the **timeline** (what happened in what order), the
**flags** (the lines that matter, each with a one-line *why*), and
a **report** — a findings draft written in incident-report
language, ready to adapt for a lab write-up.

Standard library only. Part of the Apex school series.

## Using it

In Apex chat, or anywhere the chip runs, paste the log lines right
after the command:

```
scribe parse auth <log lines>     structure: counts, IPs, users, events
scribe timeline [format] <lines>  events in chronological order
scribe flag [format] <lines>      the interesting lines, and why
scribe report [format] <lines>    a findings draft in report language
scribe --test                     self-test on a built-in sample log
```

Formats: `auth` (sshd / sudo / PAM lines from auth.log or secure),
`apache` and `nginx` (combined and common log format), `syslog`
(generic RFC3164-ish), and `auto` — detect per line, and the
default for `timeline`, `flag` and `report`. For `parse`, name the
format: `scribe parse auth ...`.

Literal `\n` escapes in a paste are read as line breaks, because
chat boxes often flatten a multi-line paste into one line.

### Reading from a file

```
scribe parse auth file /path/to/auth.log
```

File reading only works where the runner environment actually
exposes the filesystem — the chip sandbox's file access is limited
by design. When the file can't be read, Scribe says so in plain
words and stops; pasted text is the primary, supported path.

## What `flag` looks for

- **Failed logins**, counted per IP and per user — with a
  brute-force suspicion called out at **5 or more failures from
  one IP**.
- **A successful login after failures from the same IP** — called
  out explicitly, because that's the story in the log.
- **Sudo usage** — every use accounted for.
- **New-user / useradd events** — persistence-shaped until
  explained.
- **Off-hours successful logins** (00:00–04:59) — flagged as
  worth-a-look, never as an accusation.

Every flag carries a one-line "why this matters" — the reasoning
is the lesson, not just the alert.

## What `report` produces

A titled draft: scope (the pasted lines), the period covered,
event counts, findings written as incident-report sentences, and
a "what I'd check next" section. Where the log doesn't say
something, the draft leaves a placeholder like `[HOST]` or
`[REVIEWER]` instead of inventing it.

## Honesty notes

- Classic syslog timestamps carry **no year** (`Nov 10 02:14:01`).
  Scribe orders them by month/day/time and says the year is
  missing — it never invents one.
- Malformed lines are **counted as unparsed**, never hidden and
  never a crash. A 50-line flood of garbage parses as 50 unparsed
  lines.
- Lines without a parseable timestamp appear at the end of the
  timeline, labelled undated, in input order.
- The sample log in `--test` uses documentation addresses
  (203.0.113.0/24, TEST-NET-3) — it is a teaching log, not a real
  incident.
