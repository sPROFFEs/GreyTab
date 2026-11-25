#!/usr/bin/env python3
"""Launch the Linux audit browser and its local services as one lifecycle."""
import argparse
import asyncio
import base64
import hashlib
import os
import signal
import socket
import subprocess
import sys
from pathlib import Path

from core import __version__
from core.config import (CHROMIUM_BIN, EXTENSION_DIR, PROFILE_DIR, LOGS_DIR,
                         CA_CERT_DIR, ensure_dirs, get_config)
from rich.console import Console

console = Console()


def check_installation():
    if sys.platform != "linux":
        raise RuntimeError("GreyTab currently supports Linux only")
    if not CHROMIUM_BIN.is_file() or not os.access(CHROMIUM_BIN, os.X_OK):
        raise RuntimeError(f"Chromium not found: {CHROMIUM_BIN}. Run ./install.sh")
    if not (EXTENSION_DIR / "manifest.json").is_file():
        raise RuntimeError("GreyTab extension is missing")
    result = subprocess.run([str(CHROMIUM_BIN), "--version"], capture_output=True, text=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f"Chromium cannot start: {result.stderr.strip()}")
    console.print(f"[green]Chromium:[/green] {result.stdout.strip()}")


def check_ports(config):
    for name, host, port in [("API", config.api.host, config.api.port), ("proxy", config.proxy.host, config.proxy.port)]:
        with socket.socket() as sock:
            # Match the listeners' bind behavior when a closed connection is still in TIME_WAIT.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except OSError as e:
                raise RuntimeError(f"The {name} port {host}:{port} is already in use. Close the other instance first.") from e


def browser_command(config):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    cert = x509.load_pem_x509_certificate((CA_CERT_DIR / "mitmproxy-ca-cert.pem").read_bytes())
    public_key = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    spki = base64.b64encode(hashlib.sha256(public_key).digest()).decode()
    return [str(CHROMIUM_BIN), f"--proxy-server=http://{config.proxy.host}:{config.proxy.port}",
            "--proxy-bypass-list=<-loopback>;127.0.0.1:8443;localhost:8443", "--disable-quic", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            f"--user-data-dir={PROFILE_DIR}", f"--load-extension={EXTENSION_DIR}",
            f"--ignore-certificate-errors-spki-list={spki}", *config.chromium_flags, "about:blank"]


async def main(no_browser=False, open_workspace=True):
    import uvicorn
    ensure_dirs()
    config = get_config()
    if not no_browser:
        check_installation()
    check_ports(config)
    from core.api import app
    app.state.open_workspace_on_launch = not no_browser and open_workspace
    console.print(f"[bold]GreyTab {__version__}[/bold] · Linux · API {config.api.port} · Proxy {config.proxy.port}")
    server = uvicorn.Server(uvicorn.Config(app, host=config.api.host, port=config.api.port, log_level="warning"))
    backend = asyncio.create_task(server.serve())
    browser = None
    try:
        for _ in range(200):
            if backend.done():
                await backend
                raise RuntimeError("Backend stopped before becoming ready")
            if server.started:
                break
            await asyncio.sleep(.1)
        else:
            raise RuntimeError("Backend startup timed out")
        if not no_browser:
            with (LOGS_DIR / "chromium.log").open("w") as log:
                browser = subprocess.Popen(browser_command(config), stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
        if no_browser:
            console.print("[green]Ready.[/green] API and proxy running. Ctrl+C stops both services.")
        elif open_workspace:
            console.print("[green]Ready.[/green] GreyTab opens alongside Chromium. Ctrl+C closes both windows.")
        else:
            console.print("[green]Ready.[/green] Open GreyTab from the Chromium toolbar. Ctrl+C closes the session.")
        while not backend.done() and (browser is None or browser.poll() is None):
            await asyncio.sleep(.25)
        if browser is not None and browser.returncode:
            raise RuntimeError(f"Chromium exited with code {browser.returncode}; see {LOGS_DIR / 'chromium.log'}")
    finally:
        if browser and browser.poll() is None:
            os.killpg(browser.pid, signal.SIGTERM)
            try:
                await asyncio.to_thread(browser.wait, timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(browser.pid, signal.SIGKILL)
                await asyncio.to_thread(browser.wait)
        server.should_exit = True
        try:
            await asyncio.wait_for(backend, timeout=15)
        except asyncio.TimeoutError:
            backend.cancel()
            await asyncio.gather(backend, return_exceptions=True)


def run():
    parser = argparse.ArgumentParser(description="GreyTab web auditing suite (Linux)")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--check", action="store_true", help="Check browser and Python installation")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--backend-only", action="store_true", help="Start API and proxy without opening Chromium")
    mode.add_argument("--side-panel", action="store_true", help="Start Chromium without opening the GreyTab workspace")
    args = parser.parse_args()
    try:
        if args.check:
            check_installation()
        else:
            asyncio.run(main(args.backend_only, open_workspace=not args.side_panel))
    except KeyboardInterrupt:
        pass
    except (RuntimeError, OSError) as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    run()
