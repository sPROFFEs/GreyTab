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
def running_backend(wrapper, env, log_path, version):
    with log_path.open("w") as log:
        process = subprocess.Popen([wrapper, "--backend-only"], env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
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


def verify_install(app, output):
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
    assert (data_dir / "applications/greytab.desktop").is_file()

    with running_backend(wrapper, env, output / "backend-first.log", version):
        session_id = api("/api/sessions", {"name": "Packaged install QA"})["id"]

    subprocess.run(["bash", app / "install.sh"], cwd=output, env=env, check=True)
    with running_backend(wrapper, env, output / "backend-reinstall.log", version):
        assert api(f"/api/sessions/{session_id}")["name"] == "Packaged install QA"
    print(f"PASS GreyTab {version} clean install, backend lifecycle and reinstall with a saved session")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path, help="Disposable directory containing the extracted release")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    verify_install(args.app.resolve(), args.output.resolve())
