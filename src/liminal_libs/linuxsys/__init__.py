"""Linux as Liminal administers it, plain: this system's facts, a change as a plan, the journal of what Liminal
made, and a stand-in machine for every suite that tests on it (Monday list item 19: Liminal's own `liminal` user and
group, made, changed and removed from the Linux administration plugin's page or by one root command).

Plain means the standard library, this package's own modules and `proctree`, nothing more: no plugin contract, no
app's frame, no process ledger, no `machines/` (whose every module loads all three). The one root command runs from
here (`python -I -B -m liminal_libs.linuxsys`), and it runs no frame as root. tests/test_linuxsys_plain.py holds every
module to it, by its imports and by what loading it brings in.

- `shared`: what this package and `machines/linux.py` both use (sudo's words, the head of every root script, the
  reader of sudo's listing, the cleaner of every word that goes into a root's file or script).
- `kernel`: the Linux kernel, WSL and container facts, from files' texts and the environment alone.
- `facts`: PROBE, one POSIX sh read as the platform's user, and SystemFacts, what it found.
- `plan`: a change as data: its steps, each an Action its tool renders into sh and the stand-in plays; the one script;
  the chain of folders a root's file rests on.
- `journal`: /var/lib/liminal-linux/MADE, a line before each step and one after it, and what they add up to.
- `standin`: a recorded machine that answers PROBE, plays a plan's Actions on a file tree with their tools' side
  effects, and plays sudo's conversation over byte pipes. It runs nothing.
- `recorded/`: the recorded machines, each with its SOURCE.
"""
