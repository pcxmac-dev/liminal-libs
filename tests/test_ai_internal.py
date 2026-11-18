"""The AI bases' Internal API (liminal-libs 1.63.0 over 1.62.0's AI foundation; C-critique B2, the apilib review's
finding 1): what a model server and a harness say of the interface they share, as the Internal API tab draws it. A
harness asks every model server's `serving` and an instance's `models_of` through the platform, so its tab names
them and a model server's tab names the harness among who asks them; each keeps its pair through the login. On
stand-in subclasses: nothing is called, started or reached."""
from __future__ import annotations

import json

import pytest

from liminal_libs import internal
from liminal_libs.machines.ai import AiPlugin
from liminal_libs.machines.harness import Harness
from liminal_libs.machines.modelserver import ModelServer

pytestmark = pytest.mark.usefixtures("no_outside")


def made(base, name):
    return type(name.title().replace("-", ""), (base,), {"__doc__": "A stand-in.", "name": name, "title": name})()


def rows(got: dict) -> dict:
    return {h["name"]: h for h in got["hooks"]}


def test_a_model_server_and_a_harness_say_what_they_share_and_who_asks_it():
    ollama, vllm, aider = made(ModelServer, "ollama"), made(ModelServer, "vllm"), made(Harness, "aider")
    known = [ollama, vllm, aider]
    for plugin in known:
        assert internal.problems(plugin) == []
    served = internal.internal_of(ollama, known=known)
    by = rows(served)
    # its serving is asked by the other model servers too (a port another one's instance holds), its models by a
    # harness alone
    assert (by["serving"]["users"], by["serving"]["askedBy"], by["serving"]["reads"]) == ("plugins", ["vllm", "aider"],
                                                                                         True)
    assert (by["models_of"]["users"], by["models_of"]["askedBy"], by["models_of"]["reads"]) == ("plugins", ["aider"],
                                                                                             True)
    assert served["keeps"] == [{"variable": "LIMINAL_AI_OLLAMA_INSTANCES", "pair": "liminal-ai-ollama-instances",
                                "about": served["keeps"][0]["about"]}]
    assert any("LIMINAL_AI_<NAME>_<INSTANCE>_KEY" in n for n in served["notes"])
    assert by["choose"]["reads"] and not by["start"]["reads"] and not by["add_instance"]["reads"]  # what its page shows
    asked = internal.internal_of(aider, known=known)
    assert [(a["plugin"], a["hook"], a["here"]) for a in asked["asks"]] == [("", "serving", "2 plugins offer it here"),
                                                                           ("", "models_of", "2 plugins offer it here")]
    assert asked["keeps"][0]["variable"] == "LIMINAL_AI_AIDER_USE"
    assert any("`serving` row" in n and "never on its command line" in n for n in asked["notes"])  # a key read
    by = rows(asked)
    assert by["command"]["reads"] and by["ask_models"]["reads"] and not by["use"]["reads"] and not by["open"]["reads"]
    assert by["refresh"]["reads"] and not by["install"]["reads"] and by["install"]["job"]
    assert json.loads(json.dumps(asked)) == asked


def test_the_ai_bases_are_standard_interfaces_of_their_own():
    got = internal.internal_of(made(Harness, "continue"))
    assert [s["class"] for s in got["standard"]] == ["Harness", "AiPlugin", "MachinePlugin", "Plugin"]
    assert "refresh" in AiPlugin.READ_HOOKS and internal.declared(made(ModelServer, "x"), "SERVICE_HOOKS") == (
        "serving", "models_of")
