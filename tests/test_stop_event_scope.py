"""A test can never set a running app's stop event (1.88.2)."""
from __future__ import annotations

import os

from liminal_libs import lifecycle


def test_while_a_test_runs_an_apps_stop_event_name_is_the_tests_own():
    assert os.environ.get("PYTEST_CURRENT_TEST")  # pytest sets it for each test
    name = lifecycle.stop_event_name("integrator")
    assert name.startswith("Local\\liminal-stop-integrator-test") and name != "Local\\liminal-stop-integrator"


def test_outside_a_test_the_name_is_the_apps(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert lifecycle.stop_event_name("integrator") == "Local\\liminal-stop-integrator"
