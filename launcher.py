#!/usr/bin/env python3
"""
PentestBrowser - Main Launcher
Entry point that orchestrates all components:
1. Starts the FastAPI backend (which starts the mitmproxy)
2. Launches ungoogled-chromium with proper flags
"""

import asyncio
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from core.config import (
    get_config, CHROMIUM_BIN, EXTENSION_DIR, PROFILE_DIR,
    SESSIONS_DIR, SCRIPTS_DIR, WORDLISTS_DIR, CA_CERT_DIR, LOGS_DIR,
    ensure_dirs,
)

# Rich for pretty terminal output
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()


BANNER = r"""
   ██████╗ ██████╗ ███████╗██╗   ██╗████████╗ █████╗ ██████╗ 
  ██╔════╝ ██╔══██╗██╔════╝╚██╗ ██╔╝╚══██╔══╝██╔══██╗██╔══██╗
  ██║  ███╗██████╔╝█████╗   ╚████╔╝    ██║   ███████║██████╔╝
  ██║   ██║██╔══██╗██╔══╝    ╚██╔╝     ██║   ██╔══██║██╔══██╗
  ╚██████╔╝██║  ██║███████╗   ██║      ██║   ██║  ██║██████╔╝
   ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═════╝ 

            🔒 GreyTab v0.2.0
            Advanced Web Auditing Suite
"""


def check_chromium():
    """Verify ungoogled-chromium binary exists."""
    if not CHROMIUM_BIN.exists():
        console.print(f"[red]✗ Chromium binary not found at: {CHROMIUM_BIN}[/red]")
        console.print("[yellow]  Make sure ungoogled-chromium is extracted in the project root.[/yellow]")
        sys.exit(1)
    
    # Make sure it's executable
    if not os.access(CHROMIUM_BIN, os.X_OK):
        os.chmod(CHROMIUM_BIN, 0o755)
    
    console.print(f"[green]✓ Chromium binary found[/green]")


def check_extension():
    """Verify the Chrome extension exists."""
    manifest = EXTENSION_DIR / "manifest.json"
    if not manifest.exists():
        console.print(f"[red]✗ Extension not found at: {EXTENSION_DIR}[/red]")
        sys.exit(1)
    console.print(f"[green]✓ Extension found[/green]")


def launch_chromium(config):
    """Launch ungoogled-chromium with pentesting configuration."""
    proxy_url = f"http://{config.proxy.host}:{config.proxy.port}"
    
    cmd = [
        str(CHROMIUM_BIN),
        f"--proxy-server={proxy_url}",
        f"--user-data-dir={PROFILE_DIR}",
        f"--load-extension={EXTENSION_DIR}",
        "--ignore-certificate-errors",
        "--ignore-certificate-errors-spki-list",
        "--no-sandbox",
        "--test-type",
        *config.chromium_flags,
    ]

    console.print(f"\n[cyan]🚀 Launching Chromium with proxy: {proxy_url}[/cyan]")
    console.print(f"[dim]   Profile: {PROFILE_DIR}[/dim]")
    console.print(f"[dim]   Extension: {EXTENSION_DIR}[/dim]")

    # Log stderr to file for debugging
    chrome_log = LOGS_DIR / "chromium.log"
    chrome_log_f = open(chrome_log, 'w')

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=chrome_log_f,
        preexec_fn=os.setsid,
    )

    # Wait briefly to detect early crashes
    time.sleep(2)
    if process.poll() is not None:
        chrome_log_f.close()
        exit_code = process.returncode
        console.print(f"[red]✗ Chromium crashed on startup (exit code: {exit_code})[/red]")
        # Show last lines of the log
        try:
            log_content = chrome_log.read_text()
            if log_content:
                last_lines = log_content.strip().split('\n')[-15:]
                console.print("[red]   Last log lines:[/red]")
                for line in last_lines:
                    console.print(f"[dim]   {line}[/dim]")
        except Exception:
            pass
        console.print(f"[yellow]   Log file: {chrome_log}[/yellow]")
        return None
    
    console.print(f"[green]✓ Chromium started (PID: {process.pid})[/green]")
    return process


async def start_backend(config):
    """Start the FastAPI backend server."""
    import uvicorn
    
    uv_config = uvicorn.Config(
        "core.api:app",
        host=config.api.host,
        port=config.api.port,
        log_level="warning",
        reload=False,
    )
    server = uvicorn.Server(uv_config)
    return server


async def main():
    """Main entry point."""
    console.print(BANNER, style="bold cyan")
    
    config = get_config()
    ensure_dirs()

    # Preflight checks
    console.print("\n[bold]Preflight Checks[/bold]")
    console.print("─" * 40)
    check_chromium()
    check_extension()
    console.print(f"[green]✓ Directories initialized[/green]")
    
    # Show configuration
    console.print(f"\n[bold]Configuration[/bold]")
    console.print("─" * 40)
    console.print(f"  API Server:  http://{config.api.host}:{config.api.port}")
    console.print(f"  Proxy:       http://{config.proxy.host}:{config.proxy.port}")
    console.print(f"  Sessions:    {SESSIONS_DIR}")
    console.print(f"  Scripts:     {SCRIPTS_DIR}")
    console.print(f"  Wordlists:   {WORDLISTS_DIR}")

    # Start API backend (which also starts mitmproxy)
    console.print(f"\n[bold]Starting Services[/bold]")
    console.print("─" * 40)
    
    server = await start_backend(config)
    
    # Run backend in background
    backend_task = asyncio.create_task(server.serve())
    
    # Wait a moment for backend to start
    await asyncio.sleep(2)
    
    # Launch Chromium
    chrome_process = launch_chromium(config)
    
    if chrome_process is None:
        console.print("[red]Failed to start Chromium. Shutting down backend...[/red]")
        server.should_exit = True
        await asyncio.sleep(1)
        return

    console.print(f"\n[bold green]═══ GreyTab is ready ═══[/bold green]")
    console.print(f"[dim]Press Ctrl+C to shutdown everything[/dim]\n")

    # Wait for either the backend task or Chrome to exit
    try:
        # Monitor Chrome process
        while chrome_process.poll() is None:
            await asyncio.sleep(1)
        
        console.print("\n[yellow]Chromium closed. Shutting down...[/yellow]")
    except asyncio.CancelledError:
        pass
    finally:
        # Cleanup
        if chrome_process.poll() is None:
            try:
                os.killpg(os.getpgid(chrome_process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass

        server.should_exit = True
        await asyncio.sleep(1)


def run():
    """Entry point with signal handling."""
    loop = asyncio.new_event_loop()
    
    def signal_handler(sig, frame):
        console.print("\n[yellow]Received shutdown signal...[/yellow]")
        for task in asyncio.all_tasks(loop):
            task.cancel()
        loop.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        loop.run_until_complete(main())
    except (KeyboardInterrupt, SystemExit):
        console.print("\n[yellow]Goodbye![/yellow]")
    finally:
        loop.close()


if __name__ == "__main__":
    run()
