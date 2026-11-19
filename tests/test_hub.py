"""Hugging Face's cache and its hf command as the model servers use them (liminal_libs.machines.hub, 1.66.0): a
repository's name and its folder both ways; the cache read from its folders (each file counted once whatever links
show it, a stopped download, the snapshot in use, the caps); a download's progress from the folder's bytes, said by a
thread that ends with it; a delete that stays inside the plugin's folder, with its lock files and the shared store
said; a model's licence, gate, files and size as the Hub's API and hf say them, and the Hub's refusals in words; hf's
whole environment with and without a token; its two command lines word for word; and its dry run's one line read.

hf and the Hub are not here and nothing runs: the folders are made in the test's own, the Hub's answers are written
here as the Hub's API gives them (plugin-platform-vllm's recorded answers), and the shared guard (conftest.py) fails
a test that starts a process or opens a connection."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from liminal_libs import instances
from liminal_libs.machines import download, hub
from liminal_libs.machines.endpoint import EndpointError
from test_ai_boundary import WRITTEN

pytestmark = pytest.mark.usefixtures("no_outside")

HTTPS = "https:" + "//"  # an address's start, put together here: no file names a host whole
WHERE = "hub.example.test"  # the Hub's host as a plugin names it (the library names none)
REPO = "Qwen/Qwen3-0.6B"
PAGE = f"{HTTPS}{WHERE}/{REPO}"  # its page, as the plugin builds it from its own address
SNAPSHOT = "c1899de289a04d12100db370d81485cdf75e47ca"
# the Hub's API's answers, as plugin-platform-vllm recorded them (its tests/data), the addresses put together here
MODEL = {"id": REPO, "gated": False, "sha": SNAPSHOT,
         "cardData": {"library_name": "transformers", "license": "apache-2.0",
                      "license_link": f"{HTTPS}{WHERE}/{REPO}/blob/main/LICENSE", "pipeline_tag": "text-generation"},
         "siblings": [{"rfilename": n} for n in (".gitattributes", "LICENSE", "README.md", "config.json",
                                                 "generation_config.json", "merges.txt", "model.safetensors",
                                                 "tokenizer.json", "tokenizer_config.json", "vocab.json")]}
GATED = {"id": "meta-llama/Llama-3.2-1B", "gated": "manual", "cardData": {"license": "llama3.2", "language": ["en"]},
         "siblings": [{"rfilename": "config.json"}, {"rfilename": "model.safetensors"}]}
OTHER = {"id": "someone/Odd-Model-7B", "gated": False,
         "cardData": {"license": "other", "license_name": "odd-community-licence", "license_link": "LICENSE.md"},
         "siblings": [{"rfilename": "config.json"}, {"rfilename": "model.safetensors"}]}
TREESIZE = {"path": "/", "size": 1519209243}
WHOLE = 726 + 4096 + len(SNAPSHOT)  # what a model's folder frees: its two blobs and its refs/main (a link frees none)


def make_model(cache: Path, repo: str, files: dict[str, int] | None = None, incomplete: bool = False) -> Path:
    """A repository downloaded into the cache, in Hugging Face's layout (blobs, a snapshot whose files are links to
    them where this system lets a link be made, else copies, refs/main), as plugin-platform-vllm's tests make one."""
    folder = cache / ("models--" + repo.replace("/", "--"))
    blobs, snap = folder / "blobs", folder / "snapshots" / SNAPSHOT
    blobs.mkdir(parents=True)
    snap.mkdir(parents=True)
    (folder / "refs").mkdir()
    (folder / "refs" / "main").write_text(snap.name, encoding="utf-8")
    for i, (name, size) in enumerate((files or {"config.json": 726, "model.safetensors": 4096}).items()):
        blob = blobs / f"{i:040x}"
        blob.write_bytes(b"x" * size)
        try:
            os.symlink(os.path.join("..", "..", "blobs", blob.name), snap / name)
        except (OSError, NotImplementedError):
            (snap / name).write_bytes(b"")  # (no link here: an empty stand-in; the blob holds the bytes)
    if incomplete:
        (blobs / ("f" * 40 + ".incomplete")).write_bytes(b"y" * 100)
    return folder


def refusal(call) -> instances.Refusal:
    with pytest.raises(instances.Refusal) as caught:
        call()
    return caught.value


# -- a repository and its folder ---------------------------------------------------------------------------------------
def test_a_repository_is_named_org_slash_name_as_the_hub_has_it():
    assert hub.repository(REPO) == REPO and hub.repository("  Qwen/Qwen3-0.6B ") == REPO
    assert hub.repository("org_1/name.v2-x") == "org_1/name.v2-x"
    for bad in ("qwen3", "a/b/c", "a/../b", "a..b/c", "a--b/c", "a/b--c", "../x", "-a/b", "a/-b", "a b/c", "", None,
                "a/" + "b" * 97):
        assert "named org/name" in refusal(lambda: hub.repository(bad)).args[0], bad


def test_a_repositorys_folder_is_models_org_name_both_ways(tmp_path):
    cache = tmp_path / "models" / "hub"
    assert hub.folder_of(cache, REPO) == cache / "models--Qwen--Qwen3-0.6B"
    assert hub.repo_of(cache / "models--Qwen--Qwen3-0.6B") == REPO
    assert hub.repo_of("models--gpt2") == "gpt2"  # (a name without an org, as the Hub's oldest are)
    assert hub.repo_of(hub.folder_of(cache, "someone/Odd-Model-7B")) == "someone/Odd-Model-7B"
    assert "named org/name" in refusal(lambda: hub.folder_of(cache, "../../outside")).args[0]
    assert (hub.FOLDER, hub.PREFIX) == ("hub", "models--") and list(tmp_path.iterdir()) == []


# -- the cache ---------------------------------------------------------------------------------------------------------
def test_the_cache_is_read_from_its_folders(tmp_path):
    cache = tmp_path / "models" / "hub"
    assert hub.read(cache) == []  # (not there yet)
    make_model(cache, REPO)
    make_model(cache, "org/Later-1B", incomplete=True)
    (cache / ".locks" / "models--org--Later-1B").mkdir(parents=True)
    (cache / "version.txt").write_text("1", encoding="utf-8")
    (cache / "models--not-a-folder").write_text("", encoding="utf-8")
    first, later = hub.read(cache)  # by name, whatever its case: org before Qwen
    # each blob once: through the snapshot's links where this system makes them, else beside its empty stand-ins
    assert (later.repo, later.path, later.size, later.files) == (REPO, cache / "models--Qwen--Qwen3-0.6B", 726 + 4096,
                                                                 2 if _links(later.path) else 4)
    assert (later.snapshot, later.incomplete, later.whole, later.why) == (SNAPSHOT, False, True, "")
    assert (first.repo, first.incomplete, first.size) == ("org/Later-1B", True, 726 + 4096 + 100)
    assert hub.find([first, later], "qwen/qwen3-0.6b") is later and hub.find([first, later], "Org/Other") is None


def _links(folder: Path) -> bool:
    return any(p.is_symlink() for p in folder.rglob("*"))


def test_a_file_two_links_show_is_counted_once(tmp_path):
    folder = make_model(tmp_path, REPO, {"model.safetensors": 1000})
    snap = folder / "snapshots" / SNAPSHOT
    if not (snap / "model.safetensors").is_symlink():
        pytest.skip("this system makes no links for a test")
    (snap / "copy.safetensors").symlink_to(next((folder / "blobs").iterdir()))
    (snap / "nowhere.safetensors").symlink_to(folder / "blobs" / "gone")  # a link that leads nowhere counts nothing
    assert hub.scan(folder) == (1000, 1, False, True)
    linked = tmp_path / "models--linked--repo"
    linked.symlink_to(folder, target_is_directory=True)
    assert [e.repo for e in hub.read(tmp_path)] == [REPO]  # a repository's folder that is a link is not read


def test_its_refs_and_no_exist_marks_count_nothing_and_the_newest_snapshot_stands_in(tmp_path):
    folder = make_model(tmp_path, REPO)
    (folder / ".no_exist" / SNAPSHOT).mkdir(parents=True)
    (folder / ".no_exist" / SNAPSHOT / "chat_template.jinja").write_bytes(b"z" * 50)
    assert hub.scan(folder)[0] == 726 + 4096
    (folder / "refs" / "main").write_text("not-a-snapshot", encoding="utf-8")
    newer = folder / "snapshots" / ("e" * 40)
    newer.mkdir()
    os.utime(newer, (os.stat(newer).st_atime, os.stat(folder / "snapshots" / SNAPSHOT).st_mtime + 60))
    assert hub.snapshot(folder) == "e" * 40
    (folder / "refs" / "main").unlink()
    assert hub.snapshot(folder) == "e" * 40
    empty = tmp_path / "models--a--b"
    empty.mkdir()
    assert hub.snapshot(empty) == "" and hub.scan(empty) == (0, 0, False, True)


def test_the_caps_hold(tmp_path, monkeypatch):
    for n in range(3):
        make_model(tmp_path, f"org/M{n}")
    monkeypatch.setattr(hub, "REPOS_MOST", 2)
    assert [e.repo for e in hub.read(tmp_path)] == ["org/M0", "org/M1"]
    monkeypatch.setattr(hub, "LOOKS_MOST", 1)
    entry = hub.read(tmp_path)[0]
    assert entry.whole is False and entry.files <= 1  # not all of it was looked at


# -- a download's progress ---------------------------------------------------------------------------------------------
class Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def test_progress_is_said_from_the_folders_bytes(tmp_path):
    cache, said, clock = tmp_path / "hub", [], Clock()
    target = hub.folder_of(cache, REPO)
    assert hub.folder_bytes(target) == 0  # (hf has not made it yet)
    watch = hub.Watch(target, TREESIZE["size"], REPO, said.append, clock=clock)
    watch.tick()
    assert said == [f"{REPO}: 0 B of 1.4 GB (0%)"]
    make_model(cache, REPO, incomplete=True)  # what came so far, its .incomplete part among it
    assert hub.folder_bytes(target) == 726 + 4096 + 100
    watch.tick()
    assert len(said) == 1  # said less than EVERY_S ago: nothing new yet
    clock.now += hub.EVERY_S
    watch.tick()
    assert said[-1] == f"{REPO}: 4.8 KB of 1.4 GB (0%)"
    unknown = hub.Watch(target, None, REPO, said.append, clock=clock)
    unknown.tick()
    assert said[-1] == f"{REPO}: 4.8 KB so far"
    watch.end(f"{REPO}: 4.8 KB in 3 files")
    assert said[-1] == f"{REPO}: 4.8 KB in 3 files"


def test_its_thread_says_it_while_the_download_runs_and_ends_with_it(tmp_path):
    make_model(tmp_path, REPO)
    heard = threading.Event()
    said: list[str] = []

    def log(line: str) -> None:
        said.append(line)
        heard.set()

    watch = hub.Watch(hub.folder_of(tmp_path, REPO), 9600, REPO, log, every=0.01)
    with watch as w:
        assert w is watch and heard.wait(5), "its thread said nothing"  # (the download's time, as hf would take)
        thread = watch._thread
        assert thread is not None and thread.is_alive() and thread.daemon
    assert not thread.is_alive()  # ended with its download, not left behind
    assert said[0] == f"{REPO}: 4.7 KB of 9.4 KB (50%)"


def test_a_folder_that_cannot_be_read_says_nothing(tmp_path, monkeypatch):
    said: list[str] = []
    watch = hub.Watch(tmp_path, 100, REPO, said.append)

    def broken(folder):
        raise PermissionError("denied")

    monkeypatch.setattr(hub, "folder_bytes", broken)
    watch.tick()
    assert said == []


# -- a delete ----------------------------------------------------------------------------------------------------------
def test_a_repository_is_deleted_with_its_lock_files_inside_the_plugins_folder(tmp_path):
    models = tmp_path / "ai" / "vllm" / "models"
    cache = models / "hub"
    folder = make_model(cache, REPO)
    keep = make_model(cache, "org/Other-1B")
    locks = cache / ".locks" / folder.name
    locks.mkdir(parents=True)
    (locks / "x.lock").write_text("", encoding="utf-8")
    freed, lines = hub.delete(folder, models)
    assert freed == WHOLE and lines == []
    assert not folder.exists() and not locks.exists() and keep.exists() and (cache / ".locks").exists()


def test_a_store_of_shared_files_is_said_and_left(tmp_path):
    models = tmp_path / "models"
    folder = make_model(models / "hub", REPO)
    (models / "hub" / "blobs" / "ab").mkdir(parents=True)
    freed, lines = hub.delete(folder, models)
    assert lines == [f"{models / 'hub' / 'blobs'} is a store of files shared between repositories (made by another "
                     "program's hf): what of it no repository uses is left, for `hf cache prune`"]
    assert (models / "hub" / "blobs" / "ab").is_dir()


def test_lock_files_that_cannot_be_removed_are_said(tmp_path, monkeypatch):
    models = tmp_path / "models"
    folder = make_model(models / "hub", REPO)
    locks = models / "hub" / ".locks" / folder.name
    locks.mkdir(parents=True)
    real = download.remove_tree

    def stuck(path, inside):
        if Path(path) == locks:
            raise OSError("a program still holds one")
        return real(path, inside)

    monkeypatch.setattr(download, "remove_tree", stuck)
    freed, lines = hub.delete(folder, models)
    assert freed == WHOLE and lines == ["its lock files could not be removed (a program still holds one)"]
    assert locks.exists() and not folder.exists()


def test_nothing_outside_the_plugins_folder_and_nothing_but_a_repository_is_deleted(tmp_path):
    models, elsewhere = tmp_path / "models", tmp_path / "elsewhere"
    folder = make_model(elsewhere / "hub", REPO)
    with pytest.raises(ValueError, match="does not lie inside"):
        hub.delete(folder, models)
    assert folder.exists()
    for name in ("hub", "models--", "datasets--org--name", "snapshots"):
        (models / name).mkdir(parents=True, exist_ok=True)
        with pytest.raises(ValueError, match="no repository's folder"):
            hub.delete(models / name, models)
    assert hub.delete(hub.folder_of(models / "hub", "org/Gone"), models) == (0, [])  # (not there: nothing freed)


# -- what the Hub says of a model --------------------------------------------------------------------------------------
def test_a_models_licence_and_the_page_its_words_are_on():
    assert hub.licence_of(MODEL, PAGE) == ("apache-2.0", f"{HTTPS}{WHERE}/{REPO}/blob/main/LICENSE")
    other_page = f"{HTTPS}{WHERE}/someone/Odd-Model-7B"
    assert hub.licence_of(OTHER, other_page) == ("odd-community-licence", f"{other_page}/blob/main/LICENSE.md")
    assert hub.licence_of(GATED, PAGE) == ("llama3.2", PAGE)
    assert hub.licence_of({"cardData": {"license": ["mit", "apache-2.0", 3]}}, PAGE) == ("mit, apache-2.0", PAGE)
    assert hub.licence_of({"tags": ["text-generation", "license:mit"]}, PAGE) == ("mit", PAGE)
    assert hub.licence_of({"cardData": {"license": "other"}}, PAGE) == ("other, named in its card", PAGE)
    assert hub.licence_of({"card_data": {"license": "gemma"}}, PAGE) == ("gemma", PAGE)  # hf models info's words
    for link in ("http:" + "//elsewhere.example.test/LICENSE", "/abs/LICENSE", "../../LICENSE"):
        assert hub.licence_of({"cardData": {"license": "x", "license_link": link}}, PAGE) == ("x", PAGE)
    assert hub.licence_of({}, PAGE) == ("", PAGE) and hub.licence_of(None, PAGE) == ("", PAGE)
    assert len(hub.licence_of({"cardData": {"license": "z" * 500}}, PAGE)[0]) == 200


@pytest.mark.parametrize("value, is_gated", [(True, True), ("auto", True), ("manual", True), ("true", True),
                                             (" Manual ", True), (False, False), (None, False), ("false", False),
                                             ("", False), (1, False)])
def test_a_gate_is_told_as_the_hub_says_it(value, is_gated):
    assert hub.gated(value) is is_gated


def test_its_files_and_its_size():
    assert hub.files_of(MODEL) == 10 and hub.files_of(GATED) == 2
    assert hub.files_of({"siblings": [{"rfilename": "a"}, {"rfilename": ""}, "b", {}]}) == 1
    assert hub.files_of({}) == hub.files_of({"siblings": "x"}) == hub.files_of(None) == 0
    assert hub.size_of(TREESIZE) == 1519209243
    for answer in ({"size": True}, {"size": 0}, {"size": -1}, {"size": "1"}, {}, None, [1]):
        assert hub.size_of(answer) is None, answer
    assert hub.EXPAND == ("cardData", "gated", "siblings")


@pytest.mark.parametrize("status, token, words", [
    (401, "", f"it is private or gated: {WHERE} shows it only to an account given access, with its token (none is "
              "kept here: Settings)"),
    (403, "hf_kept", f"it is private or gated: {WHERE} shows it only to an account given access, with its token, and "
                     "the token kept here is refused"),
    (404, "", f"{WHERE} knows no model by that name"),
    (429, "", f"{WHERE} asks for fewer requests now (429): try again in a few minutes"),
    (500, "", "GET /api/models/x: it answered 500"),
])
def test_why_the_hub_did_not_say_is_said_in_words(status, token, words):
    assert hub.why(EndpointError("GET /api/models/x:\n  it answered 500", status), token, WHERE) == words
    assert len(hub.why(EndpointError("x" * 900, 0), "", WHERE)) == 300


# -- hf, the command ---------------------------------------------------------------------------------------------------
def test_hfs_own_variables_with_and_without_a_token(tmp_path):
    models = tmp_path / "models"
    quiet = {"HF_HOME": str(models), "HF_HUB_DISABLE_TELEMETRY": "1", "HF_HUB_DISABLE_UPDATE_CHECK": "1",
             "HF_HUB_DISABLE_SHARED_BLOBS": "1", "HF_HUB_DISABLE_PROGRESS_BARS": "1", "DO_NOT_TRACK": "1",
             "NO_COLOR": "1", "PYTHONUNBUFFERED": "1"}
    assert hub.environment(models) == {**quiet, "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1"}  # no token is sent at all
    assert hub.environment(models, "hf_kept-token") == {**quiet, "HF_TOKEN": "hf_kept-token"}
    assert hub.TOKEN_VARIABLE == "HF_TOKEN" and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("system", ["windows", "linux"])
def test_hfs_whole_environment_takes_out_the_hubs_and_the_platforms_own(tmp_path, system):
    base = {"PATH": "/usr/bin", "HOME": "/home/me", "HF_TOKEN": "hf_of-yours", "HUGGING_FACE_HUB_TOKEN": "old",
            "HF_ENDPOINT": "mirror-of-yours", "HUGGINGFACE_HUB_CACHE": "/cache-of-yours", "TRANSFORMERS_CACHE": "x",
            "PYTHONPATH": "/yours", "PYTHONHOME": "/yours", "VIRTUAL_ENV": "/venv", "CONDA_PREFIX": "/conda",
            "VLLM_PORT": "1", "LIMINAL_PLATFORM_DIR": "/platform", "MASSIVE_API_KEY": "m-key"}
    env = hub.child_env(tmp_path / "models", base=base, drop=("VLLM_*", "MASSIVE_API_KEY"), system=system)
    assert env == {"PATH": "/usr/bin", "HOME": "/home/me", **hub.environment(tmp_path / "models")}
    kept = hub.child_env(tmp_path / "models", "hf_kept", base=base, drop="VLLM_*", system=system)
    assert kept["HF_TOKEN"] == "hf_kept" and "HF_HUB_DISABLE_IMPLICIT_TOKEN" not in kept and "VLLM_PORT" not in kept
    if system == "windows":  # a name in another case is the same name there
        assert "hf_endpoint" not in hub.child_env(tmp_path, base={"hf_endpoint": "x"}, system="windows")


def test_hfs_two_command_lines_word_for_word(tmp_path):
    hf = tmp_path / "app" / "0.33.0" / "venv" / "bin" / "hf"
    assert hub.download_argv(hf, REPO) == [str(hf), "download", REPO, "--quiet"]
    assert hub.dry_run_argv(hf, " Qwen/Qwen3-0.6B ") == [str(hf), "download", REPO, "--dry-run", "--format", "human"]
    for bare in ("hf", "", None):
        with pytest.raises(ValueError, match="whole path"):
            hub.download_argv(bare, REPO)
    assert "named org/name" in refusal(lambda: hub.dry_run_argv(hf, "--help/x")).args[0]
    assert hub.DRY_RUN_S == 60.0


@pytest.mark.parametrize("printed, read", [
    ("[dry-run] Will download 11 files (out of 26) totalling 5.6G.", (11, 26, 5_600_000_000, "5.6G")),
    ("[dry-run] Will download 1 file (out of 1) totalling 655.2M.", (1, 1, 655_200_000, "655.2M")),
    ("[dry-run] Will download 3 files (out of 3) totalling 999.0.", (3, 3, 999, "999.0")),
    ("[dry-run] Will download 2 files (out of 9) totalling an unknown size.", (2, 9, None, "an unknown size")),
    ("Will download 0 files (out of 4) totaling 0.0", (0, 4, 0, "0.0")),
    ("[dry-run] Will download 4 files (out of 4) totalling 1.2Y.", (4, 4, 1_200_000_000_000_000_000_000_000, "1.2Y")),
])
def test_the_dry_runs_line_is_read(printed, read):
    said = hub.dry_run(printed)
    assert (said.files, said.total, said.size, said.said) == read
    table = ["[dry-run] Fetching 26 files: 100%", printed + "\r", "file                 size",
             "model.safetensors    5.6G"]
    assert hub.dry_run(table) == said and hub.dry_run("\n".join(table)) == said


def test_no_line_of_its_is_none():
    for printed in ("", None, [], '[{"file": "config.json", "size": "726.0"}]', "Will download some files",
                    ["/home/me/.cache/huggingface/hub/models--a--b/snapshots/abc"]):
        assert hub.dry_run(printed) is None, printed
    assert hub.dry_run("[dry-run] Will download 2 files (out of 3) totalling lots.").size is None
    for text, size in (("1.0K", 1000), ("12", 12), ("5.6 G", None), ("-1.0K", None), ("", None), ("G", None)):
        assert hub.rounded(text) == size, text


def test_the_module_writes_out_no_address():
    found = [line.strip() for line in Path(hub.__file__).read_text(encoding="utf-8").splitlines()
             if WRITTEN.search(line)]
    assert found == []
    assert json.dumps(hub.environment("models"))  # (its words are plain JSON, as a log may hold them)
