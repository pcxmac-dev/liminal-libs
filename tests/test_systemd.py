"""A unit file's words as systemd reads them (systemd.py, 1.53.1): a path with a space, a `%` or a `$` reaches the
service whole. The reading below is systemd's own rule for a quoted word, written out here to check the round trip."""
from __future__ import annotations

import pytest

from liminal_libs import systemd


def read_exec(line: str) -> list[str]:
    """`ExecStart=`'s words as systemd splits them: whitespace between words, double quotes around one, C-style
    escapes inside the quotes, `%%` a percent sign and `$$` a dollar sign."""
    words, i = [], 0
    while i < len(line):
        if line[i].isspace():
            i += 1
            continue
        out = ""
        if line[i] == '"':
            i += 1
            while line[i] != '"':
                if line[i] == "\\":
                    i += 1
                out += line[i]
                i += 1
            i += 1
        else:
            while i < len(line) and not line[i].isspace():
                out += line[i]
                i += 1
        words.append(out.replace("%%", "%").replace("$$", "$"))
    return words


@pytest.mark.parametrize("text", ["/home/me/liminal/.venv/bin/python", "/home/me/My Data/liminal.db", "100%/a b", "pay$roll",
                                  r"C:\Users\me\liminal.db", 'a "quoted" name', "", "-m", "--port", "8785", "tab-less_name.1"])
def test_a_word_reaches_the_service_as_it_was(text):
    assert read_exec(systemd.word(text)) == [text]


def test_plain_words_are_written_as_they_are_and_a_command_is_its_words():
    assert systemd.word("/usr/bin/python3") == "/usr/bin/python3" and systemd.word("--daemon") == "--daemon"
    assert systemd.word("/home/me/My Data/x") == '"/home/me/My Data/x"'
    line = systemd.command(["/opt/my venv/bin/python", "-m", "liminal_integrator", "service", "run", "--name", "paper"])
    assert line == '"/opt/my venv/bin/python" -m liminal_integrator service run --name paper'
    assert read_exec(line) == ["/opt/my venv/bin/python", "-m", "liminal_integrator", "service", "run", "--name", "paper"]


def test_an_assignment_is_one_word_and_its_percent_is_doubled():
    assert systemd.assignment("LIMINAL_DB", "/home/me/data/liminal.db") == "LIMINAL_DB=/home/me/data/liminal.db"
    spaced = systemd.assignment("LIMINAL_DB", "/home/me/My Data/liminal.db")
    assert spaced == '"LIMINAL_DB=/home/me/My Data/liminal.db"' and len(read_exec(spaced)) == 1
    assert systemd.assignment("X", "50%") == '"X=50%%"'
    assert systemd.assignment("X", "a$b") == '"X=a$b"'  # a dollar sign means nothing in Environment=: left as it is


def test_a_control_character_is_refused():
    for bad in ("two\nlines", "a\tb", "bell\x07"):
        with pytest.raises(ValueError, match="control character"):
            systemd.word(bad)
        with pytest.raises(ValueError, match="control character"):
            systemd.assignment("X", bad)
