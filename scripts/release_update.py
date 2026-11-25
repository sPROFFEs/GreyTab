#!/usr/bin/env python3
"""Apply a staged release before starting the installed application."""
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

TAG_PATTERN = re.compile(r"v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_FILES = 2000
SOURCE_DIRS = {"core", "docs", "extension", "regression", "scripts", "tests", ".github"}
SOURCE_FILES = {
    ".gitattributes", ".gitignore", ".python-version", "AGENTS.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "LICENSE", "README.md", "SECURITY.md", "install.sh", "launcher.py",
    "pyproject.toml", "quickstart.sh", "requirements-dev.txt", "requirements.lock",
    "requirements.txt", "runtime-lock.json",
}
REQUIRED = {"core/__init__.py", "extension/manifest.json", "install.sh", "launcher.py",
            "runtime-lock.json", "requirements.lock", "scripts/install_runtime.py"}


def architecture():
    machine = platform.machine()
    machine = "aarch64" if machine == "arm64" else machine
    if sys.platform != "linux" or machine not in {"x86_64", "aarch64"}:
        raise ValueError("Updates support Linux x86_64 and ARM64 only.")
    return machine


def version_key(tag):
    match = TAG_PATTERN.fullmatch(tag) if isinstance(tag, str) else None
    if not match:
        raise ValueError("Invalid GreyTab release version.")
    return tuple(map(int, match.groups()))


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, data):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as file:
        temporary = Path(file.name)
        try:
            json.dump(data, file)
            file.flush()
            os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def app_version(source):
    text = (source / "core/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']\s*$', text, re.MULTILINE)
    tag = "v" + match[1] if match else ""
    version_key(tag)
    return tag


def asset_names(machine):
    return (f"greytab-linux-{machine}.tar.gz",
            "SHA256SUMS" if machine == "x86_64" else "SHA256SUMS.aarch64")


def checksum(text, filename):
    match = re.fullmatch(r"([a-fA-F0-9]{64}) [ *]" + re.escape(filename) + r"\r?\n?", text)
    if not match:
        raise ValueError("The release checksum does not name the expected archive.")
    return match[1].lower()


def extract_release(archive, destination, tag, digest, machine):
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("The release archive is too large.")
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError("The release archive failed its SHA-256 check.")
    total = 0
    names = set()
    with tarfile.open(archive, mode="r|gz") as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            parts = path.parts
            valid_root = (len(parts) == 1 and parts[0] in SOURCE_FILES or
                          len(parts) > 1 and parts[0] in SOURCE_DIRS)
            if (not valid_root or ".." in parts or path.as_posix() != member.name or not member.isfile() or
                    member.name in names or len(names) >= MAX_FILES or len(member.name) > 320):
                raise ValueError("The release archive contains an unexpected path or entry.")
            total += member.size
            if member.size < 0 or total > MAX_EXPANDED:
                raise ValueError("The extracted release is too large.")
            names.add(member.name)
            target = destination / path
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as content, target.open("xb") as output:
                shutil.copyfileobj(content, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    if not REQUIRED.issubset(names):
        raise ValueError("The release archive is incomplete.")
    if app_version(destination) != tag or read_json(destination / "extension/manifest.json").get("version") != tag[1:]:
        raise ValueError("The versions inside the release archive do not match its tag.")
    if machine not in read_json(destination / "runtime-lock.json")["targets"]:
        raise ValueError("The release does not include a runtime for this architecture.")
    return sorted(names)


def safe_target(root, name):
    path = root / name
    if any(item.is_symlink() for item in (path, *path.parents) if item != root and root in item.parents):
        raise ValueError(f"Cannot update a symbolic link inside the installation: {name}")
    return path


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as file:
        temporary = Path(file.name)
    try:
        shutil.copy2(source, temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def restore(root, work, journal):
    for name in journal["files"]:
        target = safe_target(root, name)
        backup = work / "source-backup" / name
        if backup.is_file():
            copy_file(backup, target)
        else:
            target.unlink(missing_ok=True)
    for name, existed in journal["runtimes"].items():
        target = safe_target(root, name)
        backup = work / "runtime-backup" / name
        if backup.exists() or not existed:
            if target.exists():
                shutil.rmtree(target)
            if backup.exists():
                backup.rename(target)
    for cache in (root / "core").rglob("*.pyc"):
        if cache.parent.name == "__pycache__":
            cache.unlink(missing_ok=True)


def clear_update(state):
    (state / "pending.json").unlink(missing_ok=True)
    (state / "release.tar.gz").unlink(missing_ok=True)
    work = state / "work"
    (work / "journal.json").unlink(missing_ok=True)
    if work.exists():
        shutil.rmtree(work)


def apply_pending(root, env):
    state = root / ".runtime/release-update"
    work = state / "work"
    journal_file = work / "journal.json"
    if journal_file.exists():
        journal = read_json(journal_file)
        if not (work / "committed").exists():
            restore(root, work, journal)
            write_json(state / "result.json", {"error": "An interrupted update was rolled back. Check for updates to retry."})
        clear_update(state)
    if not (state / "pending.json").is_file():
        return
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(mode=0o700)
    candidate = work / "candidate"
    candidate.mkdir()
    log = state / "install.log"
    try:
        pending = read_json(state / "pending.json")
        tag = pending["tag"]
        if version_key(tag) <= version_key(app_version(root)):
            clear_update(state)
            return
        machine = architecture()
        names = extract_release(state / "release.tar.gz", candidate, tag, pending["digest"], machine)
        runtimes = [".venv"]
        old = read_json(root / "runtime-lock.json")["targets"][machine]
        new = read_json(candidate / "runtime-lock.json")["targets"][machine]
        runtimes += [path for key, path in (("chromium", "browser"), ("uv", ".runtime/uv")) if old[key] != new[key]]
        journal = {"files": names, "runtimes": {name: safe_target(root, name).exists() for name in runtimes}}
        for name in names:
            target = safe_target(root, name)
            if target.exists():
                if not target.is_file():
                    raise ValueError(f"Cannot overwrite a non-file in the installation: {name}")
                backup = work / "source-backup" / name
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup)
        write_json(journal_file, journal)
        for name, existed in journal["runtimes"].items():
            if existed:
                backup = work / "runtime-backup" / name
                backup.parent.mkdir(parents=True, exist_ok=True)
                (root / name).rename(backup)
        for name in names:
            copy_file(candidate / name, root / name)
        layout = read_json(root / ".runtime/install-layout.json")
        install_env = {**env, "GREYTAB_BIN_DIR": layout["bin_dir"], "XDG_DATA_HOME": layout["data_home"]}
        install_env.pop("GREYTAB_CHROME_BIN", None)
        with log.open("w", encoding="utf-8") as output:
            subprocess.run(["bash", str(root / "install.sh")], cwd=root, env=install_env,
                           stdout=output, stderr=subprocess.STDOUT, check=True)
            installed = subprocess.check_output([root / ".venv/bin/python", root / "launcher.py", "--version"],
                                                env=install_env, text=True, stderr=output).strip()
        if installed != tag[1:]:
            raise ValueError("The updated launcher reported the wrong version.")
        (state / "result.json").unlink(missing_ok=True)
        (work / "committed").touch()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        with log.open("a", encoding="utf-8") as output:
            print(error, file=output)
        if journal_file.exists():
            restore(root, work, read_json(journal_file))
        write_json(state / "result.json", {"error": "The update failed. The previous installation was kept."})
    clear_update(state)


def launch():
    root = Path(__file__).resolve().parent.parent
    args = sys.argv[1:]
    command = [str(root / ".venv/bin/python"), str(root / "launcher.py"), *args]
    if any(arg in {"--check", "--version", "-h", "--help"} for arg in args):
        os.execv(command[0], command)
    with (root / ".runtime/launch.lock").open("a") as guard:
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("GreyTab is already running. Close it before starting another instance.", file=sys.stderr)
            return 1
        os.set_inheritable(guard.fileno(), True)
        apply_pending(root, os.environ)
        os.environ["GREYTAB_MANAGED_LAUNCH"] = "1"
        os.execv(command[0], command)


if __name__ == "__main__":
    raise SystemExit(launch())
