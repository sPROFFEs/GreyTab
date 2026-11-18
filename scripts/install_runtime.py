#!/usr/bin/env python3
"""Install the release's verified browser and uv. Runs on distro Python 3.9+."""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def download_component(spec, destination, executable):
    marker = destination / ".greytab-version"
    if marker.exists() and marker.read_text().strip() == spec["version"] and (destination / executable).is_file():
        print("Already installed:", destination.name, spec["version"])
        return
    with tempfile.TemporaryDirectory(prefix="greytab-download-", dir=ROOT) as temp:
        temp = Path(temp)
        archive = temp / "download.tar"
        print("Downloading:", spec["url"], flush=True)
        request = urllib.request.Request(spec["url"], headers={"User-Agent": "GreyTab-installer"})
        with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as output:
            shutil.copyfileobj(response, output)
        digest = hashlib.sha256()
        with archive.open("rb") as content:
            for block in iter(lambda: content.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != spec["sha256"]:
            raise RuntimeError("Checksum mismatch for " + destination.name)
        extracted = temp / "extracted"
        extracted.mkdir()
        with tarfile.open(archive) as tar:
            # Explicit validation also supports distro Python before tar's data filter.
            for member in tar.getmembers():
                target = (extracted / member.name).resolve()
                if not target.is_relative_to(extracted.resolve()) or member.isdev():
                    raise RuntimeError("Unsafe archive path")
                if member.issym() or member.islnk():
                    link = ((target.parent if member.issym() else extracted) / member.linkname).resolve()
                    if not link.is_relative_to(extracted.resolve()):
                        raise RuntimeError("Unsafe archive link")
            if hasattr(tarfile, "data_filter"):
                tar.extractall(extracted, filter="data")
            else:
                tar.extractall(extracted)
        binary = next(extracted.rglob(executable), None)
        if not binary:
            raise RuntimeError("Executable missing from downloaded archive")
        replacement = binary.parent
        (replacement / ".greytab-version").write_text(spec["version"])
        backup = destination.with_name(destination.name + ".previous")
        if backup.exists():
            shutil.rmtree(backup)
        if destination.exists():
            destination.rename(backup)
        try:
            replacement.rename(destination)
        except Exception:
            if backup.exists():
                backup.rename(destination)
            raise
        if backup.exists():
            shutil.rmtree(backup)


def main():
    lock = json.loads((ROOT / "runtime-lock.json").read_text())
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("This release supports Linux x86_64 only.")
    download_component(lock["uv"], ROOT / ".runtime" / "uv", "uv")
    download_component(lock["chromium"], ROOT / "browser", "chrome")
    result = subprocess.run([str(ROOT / "browser" / "chrome"), "--version"], capture_output=True, text=True)
    if result.returncode:
        raise SystemExit("Chromium is missing system libraries:\n" + result.stderr + "\nSee docs/INSTALL.md for distribution packages.")
    print(result.stdout.strip())


if __name__ == "__main__":
    (ROOT / ".runtime").mkdir(exist_ok=True)
    main()
