"""Find and stage updates from the official GreyTab GitHub releases."""
import asyncio
from pathlib import Path
import json
import os
import tarfile
import tempfile
from urllib.parse import urlsplit

import httpx

from core import __version__
from scripts.release_update import MAX_ARCHIVE, architecture, asset_names, checksum, extract_release, read_json, version_key, write_json

RELEASES = "https://github.com/sPROFFEs/GreyTab/releases"
LATEST_API = "https://api.github.com/repos/sPROFFEs/GreyTab/releases/latest"
DOWNLOAD_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
UPDATE_ERRORS = (httpx.HTTPError, OSError, TimeoutError, ValueError, KeyError, TypeError, tarfile.TarError)


async def discover(client, machine):
    try:
        async with client.stream("GET", LATEST_API, headers={"Accept": "application/vnd.github+json"}) as response:
            response.raise_for_status()
            content = await bounded_content(response, 512 * 1024)
        payload = json.loads(content)
        tag = payload["tag_name"]
        version_key(tag)
        if payload["draft"] or payload["prerelease"]:
            raise ValueError("GitHub returned a release outside the stable channel.")
        names = {asset.get("name") for asset in payload["assets"]
                 if isinstance(asset, dict) and asset.get("state") == "uploaded" and isinstance(asset.get("name"), str)}
        if not set(asset_names(machine)).issubset(names):
            raise ValueError("The latest release is missing assets for this architecture.")
        return tag, "GitHub API"
    except (httpx.HTTPError, TimeoutError):
        response = await client.head(f"{RELEASES}/latest")
        prefix = f"{RELEASES}/tag/"
        location = response.headers.get("location", "")
        if response.status_code not in (301, 302, 303, 307, 308) or not location.startswith(prefix):
            raise ValueError("Could not find the latest stable GreyTab release over HTTPS.")
        tag = location[len(prefix):]
        version_key(tag)
        return tag, "GitHub HTTPS"


async def bounded_content(response, limit):
    chunks = bytearray()
    async for chunk in response.aiter_bytes(chunk_size=16_384):
        if len(chunks) + len(chunk) > limit:
            raise ValueError("GitHub returned more data than expected.")
        chunks.extend(chunk)
    return chunks


async def download(client, tag, name, limit):
    url = f"{RELEASES}/download/{tag}/{name}"
    for _ in range(4):
        async with client.stream("GET", url) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                url = str(response.url.join(response.headers.get("location", "")))
                parsed = urlsplit(url)
                if (parsed.scheme != "https" or parsed.netloc not in DOWNLOAD_HOSTS or not parsed.path):
                    raise ValueError("GitHub redirected the update to an unexpected download host.")
                continue
            response.raise_for_status()
            return await bounded_content(response, limit)
    raise ValueError("GitHub returned too many download redirects.")


class Updater:
    def __init__(self, root, *, current=__version__, transport=None):
        self.state = Path(root) / ".runtime/release-update"
        self.current = f"v{current}"
        self.latest = None
        self.source = None
        self.error = None
        self.task = None
        self.transport = transport
        self.check_lock = asyncio.Lock()

    def snapshot(self):
        phase = "idle"
        latest = self.latest
        message = self.error
        if self.task and not self.task.done():
            phase = "downloading"
        elif (self.state / "pending.json").is_file():
            latest = read_json(self.state / "pending.json")["tag"]
            phase = "ready"
        elif message:
            phase = "error"
        elif latest:
            phase = "available" if version_key(latest) > version_key(self.current) else "current"
        elif (self.state / "result.json").is_file():
            phase = "error"
            message = read_json(self.state / "result.json").get("error")
        return {"enabled": True, "installed": self.current[1:], "latest": latest, "source": self.source,
                "phase": phase, "message": message}

    def client(self):
        return httpx.AsyncClient(transport=self.transport, follow_redirects=False, trust_env=False, timeout=8,
                                 headers={"User-Agent": "GreyTab-updater", "Accept-Encoding": "identity"})

    async def check(self):
        async with self.check_lock:
            if self.snapshot()["phase"] in {"ready", "downloading"}:
                return self.snapshot()
            try:
                async with asyncio.timeout(20), self.client() as client:
                    self.latest, self.source = await discover(client, architecture())
                self.error = None
            except UPDATE_ERRORS as error:
                self.latest = self.source = None
                self.error = self.describe(error, "Check for updates failed")
            return self.snapshot()

    def prepare(self):
        state = self.snapshot()
        if state["phase"] in {"ready", "downloading"}:
            return state
        if not self.latest or version_key(self.latest) <= version_key(self.current):
            raise ValueError("Check for a newer release before downloading an update.")
        self.task = asyncio.create_task(self._prepare(self.latest))
        return self.snapshot()

    async def _prepare(self, tag):
        self.error = None
        try:
            machine = architecture()
            archive, sums = asset_names(machine)
            async with asyncio.timeout(90), self.client() as client:
                data = await download(client, tag, sums, 4096)
                digest = checksum(data.decode("ascii"), archive)
                body = await download(client, tag, archive, MAX_ARCHIVE)
            await asyncio.to_thread(self.stage_archive, tag, digest, body, machine)
        except UPDATE_ERRORS as error:
            self.error = self.describe(error, "Download failed")

    def stage_archive(self, tag, digest, body, machine):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="download-", dir=self.state) as temp:
            temp = Path(temp)
            archive = temp / "release.tar.gz"
            archive.write_bytes(body)
            extract_release(archive, temp / "candidate", tag, digest, machine)
            os.replace(archive, self.state / "release.tar.gz")
            write_json(self.state / "pending.json", {"tag": tag, "digest": digest})
        (self.state / "result.json").unlink(missing_ok=True)

    @staticmethod
    def describe(error, prefix):
        if isinstance(error, httpx.HTTPStatusError):
            return f"{prefix}. GitHub returned HTTP {error.response.status_code}."
        if isinstance(error, (httpx.HTTPError, TimeoutError)):
            return f"{prefix}. Could not reach GitHub. Try again shortly."
        return f"{prefix}. {error}"
