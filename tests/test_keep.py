"""The keeper of a boot task's app (liminal_libs.machines.keep, 1.47.0): started again after a failure, waiting longer
while it keeps failing, ended when the app ends well, each start and end in its log; all through stand-ins for the
command and the clock (no process is started, nothing waits)."""
from __future__ import annotations

import ctypes
from pathlib import Path

from liminal_libs.machines import keep as keep_mod
from liminal_libs.machines.keep import DELAY_S, MAX_DELAY_S, keep, main, rotate


class Clock:
    def __init__(self, lasts):
        self.lasts, self.now, self.began = list(lasts), 0.0, False

    def __call__(self):
        if self.began:  # the end of a run: it lasted its time
            self.now += self.lasts.pop(0) if self.lasts else 1.0
        self.began = not self.began
        return self.now


def test_a_failing_command_is_started_again_waiting_longer_each_time(tmp_path):
    log = tmp_path / "logs" / "platform-boot.log"
    codes, waits = [1, 1, 1, 0], []
    assert keep(["pythonw", "-m", "liminal_platform", "serve"], log, run=lambda: codes.pop(0), sleep=waits.append,
                clock=Clock([2, 3, 4, 5])) == 0
    assert waits == [DELAY_S, DELAY_S * 2, DELAY_S * 4] and codes == []
    text = log.read_text(encoding="utf-8")
    assert text.count("keep: starting pythonw -m liminal_platform serve") == 4 and "it ended with 1 after 2 s: started again in 10 s" in text
    assert text.rstrip().endswith("keep: it ended well (exit 0): not started again")


def test_the_wait_comes_back_once_a_run_lasted_and_never_passes_the_longest(tmp_path):
    waits: list[float] = []
    codes = [1] * 9 + [1, 0]
    lasts = [1] * 9 + [700, 1]  # the tenth run lasted (steady): the wait starts again from the first
    keep(["app"], tmp_path / "k.log", run=lambda: codes.pop(0), sleep=waits.append, clock=Clock(lasts))
    assert max(waits) == MAX_DELAY_S and waits[:7] == [10, 20, 40, 80, 160, 320, 600] and waits[-1] == DELAY_S


def test_a_command_that_cannot_start_is_a_failure_and_rounds_end_it(tmp_path):
    def fails():
        raise OSError("no such file")
    log = tmp_path / "k.log"
    assert keep(["missing.exe"], log, run=fails, sleep=lambda s: None, clock=Clock([0]), rounds=2) == 1
    text = log.read_text(encoding="utf-8")
    assert text.count("it could not start: no such file") == 2 and "not started again (2 runs)" in text
    assert keep(["app"], log, run=lambda: 3, sleep=lambda s: None, clock=Clock([0]), rounds=1) == 3


def test_the_log_is_moved_aside_past_its_size(tmp_path):
    log = tmp_path / "k.log"
    log.write_bytes(b"x" * 20)
    rotate(log, most=10)
    assert not log.exists() and (tmp_path / "k.log.1").read_bytes() == b"x" * 20
    rotate(tmp_path / "none.log")  # nothing there: nothing done


def test_the_command_line_names_the_log_and_the_command(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(keep_mod, "keep", lambda command, log, delay: seen.update(command=command, log=log, delay=delay) or 0)
    assert main(["--log", str(tmp_path / "b.log"), "--delay", "5", "--", "pythonw.exe", "-m", "liminal_platform", "serve", "--port", "8775"]) == 0
    assert seen == {"command": ["pythonw.exe", "-m", "liminal_platform", "serve", "--port", "8775"], "log": tmp_path / "b.log", "delay": 5.0}
    assert main(["--log", "x.log"]) == 2 and main(["--log", "x.log", "--"]) == 2  # no command: nothing kept
    assert main(["--log", str(tmp_path / "c.log"), "--delay", "0", "--", "app"]) == 0 and seen["delay"] == 1.0  # never a busy loop


def test_the_job_holding_the_command_is_windows_own_shape():
    """JOBOBJECT_EXTENDED_LIMIT_INFORMATION as Windows lays it out (144 bytes in a 64-bit process): the job that ends the
    app with its keeper is made with it (nothing is made here)."""
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(keep_mod._Extended) == 144 and ctypes.sizeof(keep_mod._Basic) == 64
    assert keep_mod.KILL_ON_JOB_CLOSE == 0x2000 and keep_mod.EXTENDED_LIMITS == 9
    assert keep_mod._hold(None, object()) is False and Path(keep_mod.__file__).name == "keep.py"
