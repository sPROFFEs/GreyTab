import hashlib
from io import BytesIO
import tarfile

import pytest

from scripts import install_runtime


def elf_header(machine):
    return b"\x7fELF\x02\x01" + bytes(12) + machine.to_bytes(2, "little")


@pytest.mark.parametrize(("architecture", "machine"), [("x86_64", 62), ("aarch64", 183)])
def test_elf_architecture_requires_the_native_machine(tmp_path, architecture, machine):
    binary = tmp_path / "chrome"
    binary.write_bytes(elf_header(machine))
    assert install_runtime.matches_architecture(binary, architecture)
    other = "aarch64" if architecture == "x86_64" else "x86_64"
    assert not install_runtime.matches_architecture(binary, other)
    binary.write_bytes(b"\x7fELF")
    assert not install_runtime.matches_architecture(binary, architecture)


def test_runtime_replaces_other_architecture_even_at_same_version(tmp_path, monkeypatch):
    installed = tmp_path / "browser"
    installed.mkdir()
    (installed / "chrome").write_bytes(elf_header(62))
    (installed / ".greytab-version").write_text("1.0")
    archive = tmp_path / "browser.tar"
    native = elf_header(183)
    with tarfile.open(archive, "w") as output:
        entry = tarfile.TarInfo("portable/chrome")
        entry.size = len(native)
        output.addfile(entry, BytesIO(native))
    spec = {"version": "1.0", "url": archive.as_uri(), "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    monkeypatch.setattr(install_runtime, "ROOT", tmp_path)

    install_runtime.download_component(spec, installed, "chrome", "aarch64")
    assert (installed / "chrome").read_bytes() == native
    assert (installed / ".greytab-version").read_text() == "1.0"
    assert not (tmp_path / "browser.previous").exists()

    with pytest.raises(RuntimeError, match="Unexpected executable architecture"):
        install_runtime.download_component(spec, installed, "chrome", "x86_64")
    assert (installed / "chrome").read_bytes() == native
