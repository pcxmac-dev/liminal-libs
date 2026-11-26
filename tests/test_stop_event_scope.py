"""A test can never set a running app's stop event (1.88.2): nor can a fixture of a test in the stand-in environment,
which pytest's name for the test is brought into when it is made (1.100.0)."""
from __future__ import annotations

import os

import pytest

from conftest import CURRENT
from liminal_libs import lifecycle

pytestmark = pytest.mark.usefixtures("stand_in_environment")  # its code reads this process's environment


def the_tests_own(phase: str) -> bool:
    """Whether the environment the code reads names this test and `phase` as pytest does, and an app's stop event is
    named for the test by it."""
    named = os.environ.get(CURRENT, "").endswith(f" ({phase})")
    return named and lifecycle.stop_event_name("platform") == f"Local\\liminal-stop-platform-test{os.getpid()}"


@pytest.fixture
def after_the_stand_in(stand_in_environment):
    """A fixture set up after the stand-in, and torn down before it is taken back: whether an app's stop event was
    the test's own in its setup; in its teardown it is asserted here."""
    in_setup = os.environ is stand_in_environment and the_tests_own("setup")
    yield in_setup
    in_teardown = os.environ is stand_in_environment and the_tests_own("teardown")
    assert in_teardown


def test_while_a_test_runs_an_apps_stop_event_name_is_the_tests_own():
    assert os.environ.get("PYTEST_CURRENT_TEST")  # pytest sets it for each test
    name = lifecycle.stop_event_name("integrator")
    assert name.startswith("Local\\liminal-stop-integrator-test") and name != "Local\\liminal-stop-integrator"


def test_outside_a_test_the_name_is_the_apps(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert lifecycle.stop_event_name("integrator") == "Local\\liminal-stop-integrator"


def test_in_the_stand_in_the_name_is_the_tests_own_in_a_fixture_too(after_the_stand_in, stand_in_environment):
    # (1.100.0's review. pytest names the test in this process's own environment before its fixtures, and in whatever
    # os.environ is then for its call and its teardown: a stand-in made without that name held none until the call,
    # so a fixture set up after it would have named, and could have set, a running app's own stop event)
    assert after_the_stand_in  # in a fixture's setup
    in_the_body = os.environ is stand_in_environment and the_tests_own("call")
    assert in_the_body  # (and in the fixture's teardown: asserted there)
