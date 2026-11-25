import hashlib
import io
import json
import subprocess
import tarfile

import httpx
import pytest

from core import updater
from scripts import release_update

TAG = "v0.10.0"


def release_payload(tag=TAG):
    files = {
        "core/__init__.py": f'__version__ = "{tag[1:]}"\n',
        "extension/manifest.json": json.dumps({"version": tag[1:]}),
        "runtime-lock.json": json.dumps({"targets": {
            machine: {"chromium": {"version": "test"}, "uv": {"version": "test"}}
            for machine in ("x86_64", "aarch64")
        }}),
        "requirements.lock": "",
        "launcher.py": "# fixture",
        "install.sh": "# fixture",
        "scripts/install_runtime.py": "# fixture",
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, text in files.items():
            data = text.encode()
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    body = output.getvalue()
    return body, hashlib.sha256(body).hexdigest()


def github_update_fixture(request):
    archive, sums = release_update.asset_names(release_update.architecture())
    body, digest = release_payload()
    pieces = {
        updater.LATEST_API: httpx.Response(429),
        f"{updater.RELEASES}/latest": httpx.Response(302, headers={"Location": f"{updater.RELEASES}/tag/{TAG}"}),
        f"{updater.RELEASES}/download/{TAG}/{sums}": httpx.Response(200, text=f"{digest}  {archive}\n"),
        f"{updater.RELEASES}/download/{TAG}/{archive}": httpx.Response(
            302, headers={"Location": "https://release-assets.githubusercontent.com/fixture"}),
        "https://release-assets.githubusercontent.com/fixture": httpx.Response(200, content=body),
    }
    return pieces[str(request.url)]


@pytest.mark.asyncio
async def test_rate_limited_updater_stages_only_verified_release(tmp_path):
    manager = updater.Updater(tmp_path, current="0.9.9", transport=httpx.MockTransport(github_update_fixture))
    status = await manager.check()
    assert (status["phase"], status["latest"], status["source"]) == ("available", TAG, "GitHub HTTPS")
    assert manager.prepare()["phase"] == "downloading"
    await manager.task
    assert manager.snapshot()["phase"] == "ready"
    assert not (tmp_path / "core").exists()
    assert (manager.state / "release.tar.gz").is_file()


@pytest.mark.asyncio
async def test_git_api_current_version_and_no_downgrade(tmp_path):
    def reply(request):
        assert str(request.url) == updater.LATEST_API
        names = release_update.asset_names(release_update.architecture())
        return httpx.Response(200, json={"tag_name": "v0.6.0", "draft": False, "prerelease": False,
                                         "assets": [{"name": name, "state": "uploaded"} for name in names]})

    manager = updater.Updater(tmp_path, current="0.6.1", transport=httpx.MockTransport(reply))
    assert (await manager.check())["phase"] == "current"
    with pytest.raises(ValueError, match="newer release"):
        manager.prepare()


@pytest.mark.asyncio
async def test_update_api_requires_managed_install_and_valid_browser_origin(app_client, tmp_path, monkeypatch):
    from core.api import app
    client, _ = app_client
    assert (await client.get("/api/updates")).json()["enabled"] is False
    assert (await client.post("/api/updates/prepare")).status_code == 409
    monkeypatch.setattr(app.state, "updater", updater.Updater(tmp_path), raising=False)
    assert (await client.post("/api/updates/check", headers={"Origin": "https://example.org"})).status_code == 403


def test_release_rejects_unexpected_paths_and_checksum(tmp_path):
    archive = tmp_path / "release.tar.gz"
    with tarfile.open(archive, mode="w:gz") as content:
        content.addfile(tarfile.TarInfo("profile/Preferences"), io.BytesIO())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="unexpected path"):
        release_update.extract_release(archive, tmp_path / "candidate", TAG, digest, "x86_64")
    with pytest.raises(ValueError, match="SHA-256"):
        release_update.extract_release(archive, tmp_path / "candidate", TAG, "0" * 64, "x86_64")


@pytest.mark.parametrize("fails", [False, True])
def test_apply_pending_preserves_user_data_and_restores_failed_install(tmp_path, monkeypatch, fails):
    machine = release_update.architecture()
    old, digest = release_payload("v0.6.0")
    archive = tmp_path / "old.tar.gz"
    archive.write_bytes(old)
    release_update.extract_release(archive, tmp_path, "v0.6.0", digest, machine)
    (tmp_path / ".runtime").mkdir()
    release_update.write_json(tmp_path / ".runtime/install-layout.json",
                              {"bin_dir": "/fixture bin", "data_home": "/fixture data"})
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv/old").touch()
    (tmp_path / "profile").mkdir()
    (tmp_path / "profile/saved").write_text("same")
    body, digest = release_payload()
    manager = updater.Updater(tmp_path)
    manager.stage_archive(TAG, digest, body, machine)

    def install(command, *, cwd, env, **kwargs):
        assert release_update.app_version(cwd) == TAG
        assert env["GREYTAB_BIN_DIR"] == "/fixture bin"
        (cwd / ".venv").mkdir()
        (cwd / ".venv/new").touch()
        if fails:
            raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(release_update.subprocess, "run", install)
    monkeypatch.setattr(release_update.subprocess, "check_output", lambda *args, **kwargs: TAG[1:])
    release_update.apply_pending(tmp_path, {})
    assert (tmp_path / "profile/saved").read_text() == "same"
    assert release_update.app_version(tmp_path) == ("v0.6.0" if fails else TAG)
    assert (tmp_path / ".venv/old").exists() is fails
    assert (tmp_path / ".venv/new").exists() is not fails
    assert (manager.state / "result.json").exists() is fails
    assert not (manager.state / "pending.json").exists()
