"""What `linuxsys` and `machines/linux.py` share (liminal_libs.linuxsys.shared): one copy of sudo's words, the root
scripts' head and the reader of sudo's listing, under the names linux.py always had; sudo-rs's words beside classic
sudo's; a scrub that replaces the whole text; and the cleaner of every word that goes into a file root writes or a
script root runs (the linuxperm critique's S5 and M6)."""
from __future__ import annotations

import pytest

from liminal_libs.linuxsys import shared
from liminal_libs.linuxsys.shared import Refused, clean_user, clean_words, password_problem, scrub, sh_word
from liminal_libs.machines import linux

pytestmark = pytest.mark.usefixtures("no_outside")


def test_machines_linux_has_the_shared_names_as_its_own():
    for name in ("DENIED", "PASSWORD_REFUSED", "ROOT_PATH", "ROOT_HEAD", "GRANT_TAGS", "PASSWORD_MAX", "SUDO_LIST",
                 "why_not_native"):
        assert getattr(linux, name) is getattr(shared, name), name
    assert linux._Listed is shared.Listed and linux._listed is shared.listed
    assert linux._runs_free is shared.runs_free and linux._matches is shared.matches
    # what was there before the move is there still, word for word
    assert shared.ROOT_HEAD == ("exec </dev/null", f"PATH={shared.ROOT_PATH}; export PATH", "LC_ALL=C; export LC_ALL",
                                "umask 077", "cd / || exit 1")
    assert shared.DENIED[:8] == ("a password is required", "a terminal is required", "permission denied",
                                 "must be root", "are you root", "operation not permitted", "need to be root",
                                 "you need root")
    assert shared.PASSWORD_REFUSED[:4] == ("incorrect password", "sorry, try again", "no password was provided",
                                           "1 incorrect password")
    assert shared.SUDO_LIST == ("env", "LC_ALL=C", "sudo", "-n", "-l") and shared.PASSWORD_MAX == 512


def test_sudo_rs_s_words_are_known_beside_classic_sudo_s():
    said = lambda text, words: any(w in text.lower() for w in words)  # noqa: E731 - as Shell.run reads them
    assert said("sudo: interactive authentication is required", shared.DENIED)
    for text in ("sudo: Authentication failed, try again.", "sudo: Authentication required but not attempted",
                 "sudo: maximum 3 incorrect authentication attempts"):
        assert said(text, shared.PASSWORD_REFUSED), text
    for text in ("Sorry, try again.", "sudo: Authentication failed, try again."):
        assert said(text, shared.SUDO_RETRY), text
    assert not said("sudo: 1 incorrect password attempt", shared.SUDO_RETRY)  # the end of the tries, no retry


def test_the_listing_is_read_as_before_the_move():
    text = ("Matching Defaults entries for ada on box:\n    env_reset\n\n"
            "User ada may run the following commands on box:\n"
            "    (ALL : ALL) ALL\n"
            "    (root) NOPASSWD: /usr/local/libexec/liminal/firewall/read \"\"\n")
    rows = shared.listed(text)
    assert [(r.root, r.nopasswd, r.command, r.args) for r in rows] == [
        ("yes", False, None, None), ("yes", True, "/usr/local/libexec/liminal/firewall/read", '""')]
    assert shared.runs_free(rows, ("/usr/local/libexec/liminal/firewall/read",))
    assert not shared.runs_free(rows, ("/bin/sh", "-c", "id"))  # ALL asks for a password
    assert shared.listed("sudo: a password is required") is None and not shared.runs_free(None, ("/bin/sh",))
    # the last match decides: NOPASSWD: ALL after a rule that asks runs anything free
    free = shared.listed("User ada may run the following commands on box:\n    (ALL : ALL) ALL\n"
                         "    (ALL) NOPASSWD: ALL\n")
    assert shared.runs_free(free, ("/bin/sh", "-c", "id"))


def test_a_password_sudo_could_not_read_as_one_line_is_named_before_sudo_is_asked():
    assert password_problem("correct horse") == "" and password_problem("") == ""
    for bad in ("two\nlines", "a\rb", "nul\x00", "x" * 512, "\udcff"):
        assert password_problem(bad) == ("a password with a line break or a NUL in it, or of 512 bytes or more, "
                                         "cannot be handed to sudo: nothing was run")
    assert password_problem("x" * 511) == ""
    with pytest.raises(linux.PasswordRefused) as e:
        linux._check_password("two\nlines")
    assert str(e.value) == password_problem("two\nlines") and "two" not in str(e.value)


def test_a_text_the_password_is_in_is_replaced_whole():
    assert scrub("sudo: 1 incorrect password attempt", "hunter2") == "sudo: 1 incorrect password attempt"
    assert scrub("echo hunter2: not found", "hunter2") == shared.SCRUBBED
    assert "hunter2" not in shared.SCRUBBED and "*" not in shared.SCRUBBED
    # a short password would be told by where its stars fell: nothing of the text is left
    assert scrub("a b c", "b") == shared.SCRUBBED
    assert scrub("anything", None) == "anything" and scrub("anything", "") == "anything"
    assert linux._scrub("boom hunter2 boom", "hunter2") == shared.SCRUBBED


def test_words_for_a_root_s_file_are_one_plain_line():
    assert clean_words("/var/lib/liminal-linux", "a folder") == "/var/lib/liminal-linux"
    # a percent sign and a dollar are plain text where Liminal writes them: printf '%s' and single-quoted words
    assert clean_words("100% of $HOME", "a note") == "100% of $HOME"
    for bad in ("two\nlines", "a\rb", "nul\x00", "back\\slash", "it's", 'say "x"', "a`id`b", "tab\there", "",
                "x" * 121, "\x1b[2J"):
        with pytest.raises(Refused) as e:
            clean_words(bad, "a found path")
        assert str(e.value).startswith("a found path is one line of 1 to 120 printable characters")
        assert str(e.value).endswith("nothing was changed") and "\n" not in str(e.value)
    assert clean_words("x" * 120, "w") == "x" * 120
    with pytest.raises(Refused):
        clean_words(None, "nothing")


def test_a_user_s_name_has_one_shape():
    for good in ("liminal", "ada", "_apt", "www-data", "u1", "a" * 32):
        assert clean_user(good) == good
    for bad in ("", "Ada", "1up", "-rf", "a b", "ada;id", "ada\n", "root$", "a" * 33, "ada.l", "$(id)", "a'b", None):
        with pytest.raises(Refused) as e:
            clean_user(bad)
        assert "a user's name here is a lowercase letter or an underscore" in str(e.value)
        assert "\n" not in str(e.value)


def test_a_script_word_is_single_quoted_and_cannot_be_left():
    assert sh_word("liminal") == "'liminal'"
    assert sh_word("$(id) %s") == "'$(id) %s'"  # inert inside single quotes
    for bad in ("it's", "a\nb", "a\\b"):
        with pytest.raises(Refused):
            sh_word(bad)


def test_a_refusal_is_a_value_error_that_may_name_what_accepts_it():
    r = Refused("the group liminal is here already with alice in it", accept="accept_members")
    assert isinstance(r, ValueError) and r.accept == "accept_members" and str(r).startswith("the group liminal")
    assert Refused("no").accept == ""
