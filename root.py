"""Navi Scribe — entry point for the Apex chip runner.

The toolkit lives in the app_scribe package beside this file; this
entry only adapts Apex's run(args) call to it. Apex passes the
words after the chip name as args.text, e.g.:

    scribe flag auth Nov 10 02:14:01 lab sshd[1]: Failed password ...

Unlike a cipher chip, the argument is pasted LOG TEXT: it is handed
to the core raw, never shlex-split — log lines contain quotes and
spacing that tokenising would destroy.
"""

try:
    from app_scribe.core import run_command
except ImportError:  # package-mode runner: the package rides beside us
    try:
        from .app_scribe.core import run_command
    except ImportError:
        run_command = None


def run(args):
    if run_command is None:
        print("error: the app_scribe package did not load with this chip.")
        return
    text = getattr(args, "text", "") or ""
    run_command(text)
