"""Navi Scribe — log parsers.

Every parser here is defensive: a line it cannot understand comes
back as an unparsed record (or None at the line level) and is
counted, never raised on. Records are plain dicts:

    raw          the original line
    format       auth | apache | nginx | syslog
    parsed       True when the line's structure was understood
    ts_raw       the timestamp exactly as written in the log
    sort_key     a tuple that orders chronologically, or None
    ts_note      honesty note about the timestamp (e.g. no year)
    host, process, ip, user   extracted fields, "" when absent
    event        event type string (failed_login, accepted_login,
                 sudo, useradd, http_2xx, ...)
    message      the message / request portion of the line

Timestamp honesty: classic syslog stamps (``Nov 10 02:14:01``)
carry NO year. They are sorted within the year by month/day/time
and the missing year is stated in output, never invented.
"""

import re
from datetime import datetime

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SYSLOG_HEAD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

ISO_HEAD = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

APACHE_RE = re.compile(
    r"^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+\"(?P<req>[^\"]*)\"\s+"
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r"(?:\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?\s*$"
)

FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for "
    r"(?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
)
AUTHFAIL_RE = re.compile(
    r"authentication failure;.*?(?:rhost=(?P<ip>(?:\d{1,3}\.){3}\d{1,3}))?"
    r"(?:.*?user=(?P<user>\S+))?"
)
SUDO_RE = re.compile(r"\bsudo(?:\[\d+\])?:\s*(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")
SUDO_LOOSE_RE = re.compile(r"\bsudo\b.*?\buser=(?P<user>\S+)")
USERADD_RE = re.compile(r"new user:\s*name=(?P<user>[^,\s]+)")
DISCONNECT_RE = re.compile(
    r"(?:Disconnected from|Connection closed by|Connection reset by)"
    r"(?: authenticating user (?P<user>\S+))?\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})?"
)


def _blank(raw, fmt):
    return {
        "raw": raw, "format": fmt, "parsed": False, "ts_raw": "",
        "sort_key": None, "ts_note": "", "host": "", "process": "",
        "ip": "", "user": "", "event": "unparsed", "message": raw,
        "hour": None,
    }


def _syslog_sort_key(mon_name, day, hh, mm, ss):
    mon = MONTHS.get(mon_name)
    if mon is None:
        return None
    # Year 2000 is a placeholder ONLY for ordering inside one log;
    # the year itself is never claimed (see ts_note).
    return (2000, mon, int(day), int(hh), int(mm), int(ss))


def _iso_sort_key(ts):
    try:
        cleaned = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    except ValueError:
        return None


def _apache_sort_key(ts):
    # 10/Nov/2026:02:14:01 +0000
    try:
        main = ts.split(" ")[0]
        date_part, time_part = main.split(":", 1)
        day, mon_name, year = date_part.split("/")
        hh, mm, ss = time_part.split(":")
        return (int(year), MONTHS[mon_name], int(day),
                int(hh), int(mm), int(ss))
    except (ValueError, KeyError):
        return None


def _classify_auth_message(rec, msg):
    """Fill event/ip/user on a record from an auth-family message."""
    m = FAILED_RE.search(msg)
    if m:
        rec.update(event="failed_login", ip=m.group("ip"), user=m.group("user"))
        return
    m = ACCEPTED_RE.search(msg)
    if m:
        rec.update(event="accepted_login", ip=m.group("ip"), user=m.group("user"))
        return
    if "sudo" in msg or rec["process"].startswith("sudo"):
        m = SUDO_RE.search(rec["raw"]) or SUDO_RE.search(msg)
        if m:
            rec.update(event="sudo", user=m.group("user"))
            return
        if rec["process"].startswith("sudo"):
            # Head-parsed form: the message itself starts with the
            # invoking user — "alex : TTY=... ; COMMAND=...".
            first = msg.split(":", 1)[0].strip().split()
            rec["event"] = "sudo"
            if first and "=" not in first[0]:
                rec["user"] = first[0]
            return
        m = SUDO_LOOSE_RE.search(msg)
        if m:
            rec.update(event="sudo", user=m.group("user"))
            return
    m = USERADD_RE.search(msg)
    if m or "useradd" in rec["process"]:
        rec["event"] = "useradd"
        if m:
            rec["user"] = m.group("user")
        return
    m = AUTHFAIL_RE.search(msg)
    if m:
        rec["event"] = "auth_failure"
        if m.group("ip"):
            rec["ip"] = m.group("ip")
        if m.group("user"):
            rec["user"] = m.group("user")
        return
    m = DISCONNECT_RE.search(msg)
    if m:
        rec["event"] = "disconnect"
        if m.group("ip"):
            rec["ip"] = m.group("ip")
        if m.group("user"):
            rec["user"] = m.group("user")
        return
    if "session opened" in msg:
        rec["event"] = "session_opened"
        return
    if "session closed" in msg:
        rec["event"] = "session_closed"
        return
    if rec["process"].startswith("sshd"):
        rec["event"] = "ssh_event"
        ip = IP_RE.search(msg)
        if ip:
            rec["ip"] = ip.group(0)
        return
    rec["event"] = "other"


def _parse_head(line):
    """Parse a syslog-style or ISO head. Returns (rec, msg) or None."""
    m = SYSLOG_HEAD.match(line)
    if m:
        rec = _blank(line, "syslog")
        rec["parsed"] = True
        rec["ts_raw"] = "%s %s %s:%s:%s" % (
            m.group("mon"), m.group("day"), m.group("hh"),
            m.group("mm"), m.group("ss"))
        rec["ts_note"] = "syslog stamp: no year in the log line"
        rec["sort_key"] = _syslog_sort_key(
            m.group("mon"), m.group("day"),
            m.group("hh"), m.group("mm"), m.group("ss"))
        rec["hour"] = int(m.group("hh"))
        rec["host"] = m.group("host")
        rec["process"] = m.group("proc")
        rec["message"] = m.group("msg")
        return rec, m.group("msg")
    m = ISO_HEAD.match(line)
    if m:
        rec = _blank(line, "syslog")
        rec["parsed"] = True
        rec["ts_raw"] = m.group("ts")
        rec["sort_key"] = _iso_sort_key(m.group("ts"))
        try:
            rec["hour"] = int(m.group("ts")[11:13])
        except (ValueError, IndexError):
            rec["hour"] = None
        rec["host"] = m.group("host")
        rec["process"] = m.group("proc")
        rec["message"] = m.group("msg")
        return rec, m.group("msg")
    return None


def parse_auth_line(line):
    got = _parse_head(line)
    if got is None:
        return None
    rec, msg = got
    rec["format"] = "auth"
    _classify_auth_message(rec, msg)
    return rec


def parse_syslog_line(line):
    got = _parse_head(line)
    if got is None:
        return None
    rec, msg = got
    rec["format"] = "syslog"
    # Generic syslog still recognises the security-shaped messages —
    # a sudo line is a sudo line whatever file it was pasted from.
    _classify_auth_message(rec, msg)
    if rec["event"] in ("other", "unparsed"):
        rec["event"] = "syslog_message"
    return rec


def parse_web_line(line, fmt):
    m = APACHE_RE.match(line)
    if not m:
        return None
    rec = _blank(line, fmt)
    rec["parsed"] = True
    rec["ip"] = m.group("ip")
    rec["user"] = "" if m.group("user") == "-" else m.group("user")
    rec["ts_raw"] = m.group("ts")
    rec["sort_key"] = _apache_sort_key(m.group("ts"))
    try:
        rec["hour"] = int(m.group("ts").split(":", 2)[1])
    except (ValueError, IndexError):
        rec["hour"] = None
    status = m.group("status")
    rec["event"] = "http_" + status[0] + "xx"
    rec["message"] = '%s -> %s (%s bytes)' % (
        m.group("req") or "-", status, m.group("size"))
    return rec


def _looks_auth(line):
    return any(tok in line for tok in (
        "sshd", "sudo", "pam_unix", "useradd", "Failed password",
        "Accepted password", "authentication failure",
    ))


def parse_line(line, fmt):
    """Parse one line under fmt ('auth'|'apache'|'nginx'|'syslog'|
    'auto'). Returns a record dict; never raises."""
    try:
        if fmt == "auth":
            rec = parse_auth_line(line)
            return rec if rec is not None else _blank(line, "auth")
        if fmt in ("apache", "nginx"):
            rec = parse_web_line(line, fmt)
            return rec if rec is not None else _blank(line, fmt)
        if fmt == "syslog":
            rec = parse_syslog_line(line)
            return rec if rec is not None else _blank(line, "syslog")
        # auto: web shape first (it is the most distinctive), then
        # auth-shaped heads, then generic syslog, then unparsed.
        rec = parse_web_line(line, "apache")
        if rec is not None:
            # nginx and apache share the combined/common shape; the
            # per-line format records the family, not the daemon.
            rec["format"] = "web"
            return rec
        if _looks_auth(line):
            rec = parse_auth_line(line)
            if rec is not None:
                return rec
        rec = parse_syslog_line(line)
        if rec is not None:
            return rec
        return _blank(line, "auto")
    except Exception:
        return _blank(line, fmt)


def parse_text(text, fmt):
    """Parse a block of log text into a list of records."""
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(parse_line(line, fmt))
    return records
