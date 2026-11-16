"""A unit file's words, written as systemd reads them (1.53.1).

The integrator's unit wrote its interpreter's and its database's paths bare. systemd splits `ExecStart=` and
`Environment=` on spaces, so a data folder with a space in its name gave the service `LIMINAL_DB=/home/me/My` and it
opened another database; a `%` in a path was read as one of systemd's specifiers and a `$` in a command as a variable.

What systemd does with a line (systemd.syntax(7), systemd.service(5), systemd.exec(5)):
- `ExecStart=` is split into words on whitespace; double quotes make one word of what they hold, with C-style escapes
  inside them; `%` starts a specifier and `$` a variable, each doubled to stand for itself;
- `Environment=` takes assignments, split and quoted the same way; specifiers are read there too, `$` is not.
A control character (a line break above all) cannot be carried in a unit and is refused.
"""
from __future__ import annotations

import re

PLAIN = re.compile(r"[A-Za-z0-9._/+@:,=-]+")  # what systemd reads as it is written: no quote is needed


def _carried(text) -> str:
    text = str(text)
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError(f"{text!r} cannot be written into a unit: it holds a control character")
    return text


def word(text) -> str:
    """One word of `ExecStart=`: as it is when plain, else in double quotes with `\\`, `"`, `%` and `$` escaped."""
    w = _carried(text)
    if PLAIN.fullmatch(w):
        return w
    return '"' + w.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def command(words) -> str:
    """A command line for `ExecStart=`: each word as `word` writes it."""
    return " ".join(word(w) for w in words)


def assignment(name: str, value) -> str:
    """`NAME=value` for `Environment=`: as it is when the value is plain, else the whole assignment in double quotes
    with `\\`, `"` and `%` escaped (a `$` means nothing there)."""
    v = _carried(value)
    if PLAIN.fullmatch(v):
        return f"{name}={v}"
    return '"' + f"{name}={v}".replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'
