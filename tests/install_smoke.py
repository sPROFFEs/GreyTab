#!/usr/bin/env python3
"""Verify a release extracted into a disposable directory on the native host."""

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
from tempfile import TemporaryDirectory
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener


def api(path, payload=None):
    opener = build_opener(ProxyHandler({}))
    body = json.dumps(payload).encode() if payload is not None else None
    request = Request(f"http://127.0.0.1:8443{path}", data=body, headers={"Content-Type": "application/json"})
    with opener.open(request, timeout=2) as response:
        return json.load(response)


@contextmanager
def running_backend(wrapper, env, log_path, version, startup_timeout=10):
    with log_path.open("w") as log:
        process = subprocess.Popen([wrapper, "--backend-only"], env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(startup_timeout * 10):
                if process.poll() is not None:
                    raise RuntimeError(f"Installed backend exited early. See {log_path}")
                try:
                    health = api("/api/health")
                    if health["proxy_running"]:
                        break
                except (URLError, TimeoutError):
                    pass
                time.sleep(0.1)
            else:
                raise TimeoutError(f"Installed backend did not get ready. See {log_path}")
            assert health["version"] == version
            yield
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            try:
                status = process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise
        assert status == 0, f"Installed backend exited with {status}. See {log_path}"


def seed_stale_version_cache(app, version):
    source = app / "core/__init__.py"
    previous_version = ".".join("0" * len(part) for part in version.split("."))
    contents = source.read_bytes()
    previous = contents.replace(f'__version__ = "{version}"'.encode(),
                                f'__version__ = "{previous_version}"'.encode(), 1)
    assert previous != contents and len(previous) == len(contents)
    with TemporaryDirectory() as scratch:
        old_source = Path(scratch) / "previous_version.py"
        old_source.write_bytes(previous)
        stat = source.stat()
        os.utime(old_source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        subprocess.run([app / ".venv/bin/python", "-c", """
from importlib.util import cache_from_source
import py_compile
import sys

py_compile.compile(sys.argv[1], cfile=cache_from_source(sys.argv[2]), doraise=True,
                   invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
""", old_source, source], check=True)
    return previous_version


def check_staged_update(app, output, archive, wrapper, env, version, previous_version, session_id):
    source = app / "core/__init__.py"
    source.write_text(source.read_text().replace(f'__version__ = "{version}"', f'__version__ = "{previous_version}"'))
    assert subprocess.check_output([wrapper, "--version"], env=env, text=True).strip() == previous_version
    marker = app / "profile/updater-fixture.txt"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("keep this profile")
    subprocess.run([app / ".venv/bin/python", "-c", """
import hashlib
from pathlib import Path
import sys
from core.updater import Updater
from scripts.release_update import architecture

archive = Path(sys.argv[1]).read_bytes()
Updater(Path.cwd()).stage_archive(sys.argv[2], hashlib.sha256(archive).hexdigest(), archive, architecture())
""", str(archive), f"v{version}"], cwd=app, env=env, check=True)
    with running_backend(wrapper, env, output / "backend-update.log", version, startup_timeout=45):
        update = api("/api/updates")
        assert update["enabled"] and update["phase"] == "idle", update
        assert api(f"/api/sessions/{session_id}")["name"] == "Packaged install QA"
    assert marker.read_text() == "keep this profile"
    assert not (app / ".runtime/release-update/pending.json").exists()
    print(f"PASS GreyTab {version} staged update through the installed launcher with profile and session preservation")


def verify_install(app, output, archive=None):
    output.mkdir(parents=True, exist_ok=True)
    bin_dir = app.parent / "command bin"
    data_dir = app.parent / "desktop files"
    env = {**os.environ, "GREYTAB_BIN_DIR": str(bin_dir), "XDG_DATA_HOME": str(data_dir), "GREYTAB_RUNTIME_DIR": str(app)}
    env.pop("GREYTAB_CHROME_BIN", None)
    wrapper = bin_dir / "greytab"
    runtime = json.loads((app / "runtime-lock.json").read_text())
    version = json.loads((app / "extension/manifest.json").read_text())["version"]
    architecture = platform.machine()
    architecture = "aarch64" if architecture == "arm64" else architecture
    chromium_version = runtime["targets"][architecture]["chromium"]["version"].split("-", 1)[0]

    subprocess.run(["bash", app / "install.sh"], cwd=output, env=env, check=True)
    assert subprocess.check_output([wrapper, "--version"], env=env, text=True).strip() == version
    browser_check = subprocess.check_output([wrapper, "--check"], env=env, text=True)
    assert f"Chromium {chromium_version}" in browser_check
    print(browser_check, end="")
    assert subprocess.check_output([app / ".venv/bin/python", "--version"], text=True).strip() == f"Python {runtime['python']}"
    desktop_entry = (data_dir / "applications/greytab.desktop").read_text().splitlines()
    assert "Terminal=false" in desktop_entry
    assert any(line.startswith("Exec=") and line.endswith(" --desktop") for line in desktop_entry)
    desktop_check = subprocess.check_output([wrapper, "--desktop", "--check"], env=env, text=True)
    assert not desktop_check
    assert f"Chromium {chromium_version}" in (app / "logs/launcher.log").read_text()

    with running_backend(wrapper, env, output / "backend-first.log", version):
        session_id = api("/api/sessions", {"name": "Packaged install QA"})["id"]

    previous_version = seed_stale_version_cache(app, version)
    assert subprocess.check_output([wrapper, "--version"], env=env, text=True).strip() == previous_version
    subprocess.run(["bash", app / "install.sh"], cwd=output, env=env, check=True)
    assert subprocess.check_output([wrapper, "--version"], env=env, text=True).strip() == version
    with running_backend(wrapper, env, output / "backend-reinstall.log", version):
        assert api(f"/api/sessions/{session_id}")["name"] == "Packaged install QA"
    print(f"PASS GreyTab {version} install, backend lifecycle, session preservation and stale bytecode removal")
    if archive:
        check_staged_update(app, output, archive, wrapper, env, version, previous_version, session_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path, help="Disposable directory containing the extracted release")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path, help="Verified native release archive for the staged-update check")
    args = parser.parse_args()
    verify_install(args.app.resolve(), args.output.resolve(), args.archive.resolve() if args.archive else None)
