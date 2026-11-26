"""The Linux kernel, WSL and container facts (liminal_libs.linuxsys.kernel): one reading for the library's two readers
of this machine, a function of files' texts and the environment that starts nothing and opens nothing (the linuxperm
plan's 3.11). The cases are the systems the recorded machines stand for."""
from __future__ import annotations

import pytest

from liminal_libs.linuxsys import kernel
from liminal_libs.machines import linux

pytestmark = pytest.mark.usefixtures("no_outside")

WSL2 = "6.18.58.1-microsoft-standard-WSL2\n"


def test_a_machine_of_its_own():
    k = kernel.read({kernel.OSRELEASE: "6.17.0-8-generic\n", kernel.ARCH: "x86_64\n"}, {})
    assert (k.release, k.machine, k.wsl, k.wsl_generation, k.container) == ("6.17.0-8-generic", "x86_64", "", 0, "")
    assert k.notes == () and k.describe() == {"release": "6.17.0-8-generic", "machine": "x86_64", "wsl": "",
                                             "wsl_generation": 0, "container": "", "notes": []}


def test_the_machine_s_name_is_taken_as_given_where_the_kernel_has_no_file_for_it():
    k = kernel.read({kernel.OSRELEASE: "5.15.0-91-generic"}, {}, machine="aarch64\n")
    assert k.machine == "aarch64"
    assert kernel.read({kernel.OSRELEASE: "6.8.0", kernel.ARCH: "riscv64"}, {}, machine="x86_64").machine == "riscv64"


def test_a_wsl_distribution_is_no_container_though_systemd_says_wsl():
    files = {kernel.OSRELEASE: WSL2, kernel.SYSTEMD_CONTAINER: "wsl\n",
             "/proc/sys/fs/binfmt_misc/WSLInterop": "enabled\n", "/run/WSL": ""}
    k = kernel.read(files, {"WSL_DISTRO_NAME": "Ubuntu", "WSL_INTEROP": "/run/WSL/8_interop"}, "x86_64")
    assert (k.wsl, k.wsl_generation, k.container) == ("Ubuntu", 2, "")
    # the same words as the machine plugins' own reading
    assert k.wsl == linux.wsl(WSL2.strip(), {"WSL_DISTRO_NAME": "Ubuntu"})
    assert k.wsl_generation == linux.wsl_generation(WSL2.strip())
    assert kernel.wsl_generation("4.4.0-19041-Microsoft") == 1 == linux.wsl_generation("4.4.0-19041-Microsoft")
    assert kernel.wsl_generation("6.17.0-8-generic") == 0


def test_wsl_is_told_by_the_kernel_by_its_marks_or_by_its_variables():
    assert kernel.read({kernel.OSRELEASE: WSL2}, {}).wsl == "WSL"  # the environment does not name it (a service's)
    assert kernel.read({kernel.OSRELEASE: "6.6.0-custom", "/run/WSL": ""}, {}).wsl == "WSL"
    assert kernel.read({kernel.OSRELEASE: "6.6.0-custom", "/proc/sys/fs/binfmt_misc/WSLInterop-late": "enabled"},
                       {}).wsl == "WSL"
    assert kernel.read({kernel.OSRELEASE: "6.6.0-custom"}, {"WSL_INTEROP": "/run/WSL/1_interop"}).wsl == "WSL"
    k = kernel.read({kernel.OSRELEASE: "6.6.0-custom"}, {"WSL_DISTRO_NAME": "Liminal-Ubuntu"})
    assert (k.wsl, k.wsl_generation) == ("Liminal-Ubuntu", 0)  # a custom kernel does not tell the generation
    # a mark that is not there (None) is no mark
    assert kernel.read({kernel.OSRELEASE: "6.6.0", "/run/WSL": None}, {}).wsl == ""


def test_containers_by_systemd_s_word_their_own_files_or_the_variable():
    base = {kernel.OSRELEASE: "6.17.0-8-generic"}
    for word, kind in (("docker", "docker"), ("podman", "podman"), ("lxc", "lxc"), ("lxc-libvirt", "lxc"),
                       ("systemd-nspawn", "nspawn"), ("something-new", "other")):
        assert kernel.read({**base, kernel.SYSTEMD_CONTAINER: word + "\n"}, {}).container == kind
    assert kernel.read({**base, kernel.DOCKERENV: ""}, {}).container == "docker"
    assert kernel.read({**base, kernel.CONTAINERENV: 'engine="podman-5.4"\n'}, {}).container == "podman"
    assert kernel.read({**base, kernel.CONTAINERENV: "", kernel.DOCKERENV: ""}, {}).container == "podman"
    assert kernel.read(base, {"container": "lxc"}).container == "lxc"
    assert kernel.read(base, {"container": "wsl"}).container == ""
    assert kernel.read(base, {}).container == ""


def test_a_container_on_a_wsl_kernel_is_both():
    k = kernel.read({kernel.OSRELEASE: WSL2, kernel.DOCKERENV: ""}, {})
    assert (k.wsl, k.wsl_generation, k.container) == ("WSL", 2, "docker")


def test_what_could_not_be_read_is_said_never_guessed():
    k = kernel.read({}, {})
    assert (k.release, k.machine, k.wsl, k.container) == ("", "", "", "")
    assert k.notes == ("the kernel's release could not be read (/proc/sys/kernel/osrelease)",)
    assert kernel.read(None, None).release == ""


def test_the_files_and_variables_it_reads_are_named_for_both_readers():
    assert kernel.FILES == ("/proc/sys/kernel/osrelease", "/proc/sys/kernel/arch", "/run/systemd/container",
                            "/run/.containerenv", "/.dockerenv", "/proc/sys/fs/binfmt_misc/WSLInterop",
                            "/proc/sys/fs/binfmt_misc/WSLInterop-late", "/run/WSL")
    assert kernel.ENV == ("WSL_DISTRO_NAME", "WSL_INTEROP", "container")
