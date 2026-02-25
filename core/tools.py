"""
PentestBrowser - Tool Runner
Executes system pentesting tools as async subprocesses with real-time output streaming.
"""

import asyncio
import shlex
import shutil
import signal
import time
from typing import Optional, Dict, Callable, Awaitable, List
from dataclasses import dataclass, field
from pathlib import Path

from core.config import (
    ToolDefinition, BUILTIN_TOOLS, SCRIPTS_DIR, WORDLISTS_DIR,
    load_custom_tools, save_custom_tools,
)


@dataclass
class RunningTool:
    """Represents a currently running tool process."""
    run_id: int
    tool_name: str
    command: str
    process: asyncio.subprocess.Process
    started_at: float
    output_buffer: List[str] = field(default_factory=list)
    is_cancelled: bool = False


class ToolRunner:
    """Manages execution of pentesting tools as subprocesses."""

    def __init__(self):
        self._running: Dict[int, RunningTool] = {}
        self._custom_tools: Dict[str, ToolDefinition] = load_custom_tools()
        self._tool_definitions: Dict[str, ToolDefinition] = {
            **BUILTIN_TOOLS,
            **self._custom_tools,
        }

    def get_available_tools(self) -> Dict[str, Dict]:
        """Get all available tools and whether they're installed."""
        result = {}
        for name, tool_def in self._tool_definitions.items():
            is_installed = shutil.which(tool_def.command) is not None
            result[name] = {
                "name": tool_def.name,
                "command": tool_def.command,
                "description": tool_def.description,
                "category": tool_def.category,
                "args_template": tool_def.args_template,
                "requires_target": tool_def.requires_target,
                "installed": is_installed,
                "is_custom": name in self._custom_tools,
            }
        return result

    # ── Custom Tool CRUD ──────────────────────────────────────

    def get_custom_tools(self) -> Dict[str, Dict]:
        """Get only user-added custom tools."""
        result = {}
        for name, td in self._custom_tools.items():
            result[name] = {
                "name": td.name,
                "command": td.command,
                "description": td.description,
                "category": td.category,
                "args_template": td.args_template,
                "requires_target": td.requires_target,
            }
        return result

    def add_custom_tool(self, tool_def: ToolDefinition) -> bool:
        """Add a new custom tool definition."""
        name = tool_def.name
        if name in BUILTIN_TOOLS:
            raise ValueError(f"Cannot override built-in tool: {name}")
        self._custom_tools[name] = tool_def
        self._tool_definitions[name] = tool_def
        save_custom_tools(self._custom_tools)
        return True

    def update_custom_tool(self, name: str, tool_def: ToolDefinition) -> bool:
        """Update a custom tool definition."""
        if name not in self._custom_tools:
            raise ValueError(f"Custom tool not found: {name}")
        self._custom_tools[name] = tool_def
        self._tool_definitions[name] = tool_def
        save_custom_tools(self._custom_tools)
        return True

    def remove_custom_tool(self, name: str) -> bool:
        """Remove a custom tool definition."""
        if name not in self._custom_tools:
            raise ValueError(f"Custom tool not found: {name}")
        del self._custom_tools[name]
        del self._tool_definitions[name]
        save_custom_tools(self._custom_tools)
        return True

    def get_running_tools(self) -> Dict[int, Dict]:
        """Get all currently running tools."""
        return {
            run_id: {
                "run_id": rt.run_id,
                "tool_name": rt.tool_name,
                "command": rt.command,
                "started_at": rt.started_at,
                "pid": rt.process.pid,
                "output_lines": len(rt.output_buffer),
            }
            for run_id, rt in self._running.items()
        }

    def get_wordlists(self) -> List[Dict]:
        """Get available wordlists (project + system paths)."""
        wordlists = []
        seen_paths = set()

        # Project-level wordlists
        if WORDLISTS_DIR.exists():
            for f in WORDLISTS_DIR.rglob("*"):
                if f.is_file():
                    rpath = str(f.resolve())
                    if rpath not in seen_paths:
                        seen_paths.add(rpath)
                        wordlists.append({
                            "name": f.name,
                            "path": str(f),
                            "size": f.stat().st_size,
                            "relative": str(f.relative_to(WORDLISTS_DIR)),
                            "source": "project",
                        })

        # System wordlist directories
        system_dirs = [
            Path("/usr/share/wordlists"),
            Path("/usr/share/seclists"),
            Path("/usr/share/dirb/wordlists"),
        ]
        for sys_dir in system_dirs:
            if not sys_dir.exists():
                continue
            try:
                # Only scan top-level and one level deep to avoid huge scans
                for f in sys_dir.iterdir():
                    if f.is_file() and f.suffix in ('.txt', '.lst', '.list', ''):
                        rpath = str(f.resolve())
                        if rpath not in seen_paths:
                            seen_paths.add(rpath)
                            wordlists.append({
                                "name": f.name,
                                "path": str(f),
                                "size": f.stat().st_size,
                                "relative": f"[sys] {sys_dir.name}/{f.name}",
                                "source": "system",
                            })
                    elif f.is_dir():
                        for sf in f.iterdir():
                            if sf.is_file() and sf.suffix in ('.txt', '.lst', '.list', ''):
                                rpath = str(sf.resolve())
                                if rpath not in seen_paths:
                                    seen_paths.add(rpath)
                                    wordlists.append({
                                        "name": sf.name,
                                        "path": str(sf),
                                        "size": sf.stat().st_size,
                                        "relative": f"[sys] {sys_dir.name}/{f.name}/{sf.name}",
                                        "source": "system",
                                    })
            except PermissionError:
                continue
        return wordlists

    def get_custom_scripts(self) -> List[Dict]:
        """Get available custom scripts."""
        scripts = []
        if SCRIPTS_DIR.exists():
            for f in SCRIPTS_DIR.rglob("*"):
                if f.is_file() and f.suffix in ('.py', '.sh', '.rb', '.pl'):
                    scripts.append({
                        "name": f.name,
                        "path": str(f),
                        "type": f.suffix[1:],
                        "relative": str(f.relative_to(SCRIPTS_DIR)),
                    })
        return scripts

    async def run_tool(
        self,
        run_id: int,
        tool_name: str,
        raw_command: str,
        on_output: Optional[Callable[[int, str], Awaitable[None]]] = None,
        on_complete: Optional[Callable[[int, int, float], Awaitable[None]]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> int:
        """
        Execute a tool command asynchronously.
        
        Args:
            run_id: Database run ID for tracking
            tool_name: Name of the tool being run
            raw_command: Full command string to execute
            on_output: Callback for each line of output (run_id, line)
            on_complete: Callback when tool finishes (run_id, exit_code, duration_ms)
            cwd: Working directory for the command
            env: Environment variables
            
        Returns:
            Process PID
        """
        # Security: refuse obviously dangerous commands
        dangerous = ['rm -rf /', 'mkfs', ':(){', 'dd if=/dev/zero']
        cmd_lower = raw_command.lower()
        for d in dangerous:
            if d in cmd_lower:
                raise ValueError(f"Refused to execute dangerous command pattern: {d}")

        started_at = time.time()
        
        process = await asyncio.create_subprocess_shell(
            raw_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
            env=env,
        )

        running = RunningTool(
            run_id=run_id,
            tool_name=tool_name,
            command=raw_command,
            process=process,
            started_at=started_at,
        )
        self._running[run_id] = running

        # Stream output in background
        asyncio.create_task(self._stream_output(running, on_output, on_complete))

        return process.pid

    async def _stream_output(
        self,
        running: RunningTool,
        on_output: Optional[Callable[[int, str], Awaitable[None]]],
        on_complete: Optional[Callable[[int, int, float], Awaitable[None]]],
    ):
        """Stream subprocess output line by line."""
        try:
            while True:
                line = await running.process.stdout.readline()
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').rstrip('\n')
                running.output_buffer.append(decoded)
                
                if on_output and not running.is_cancelled:
                    try:
                        await on_output(running.run_id, decoded)
                    except Exception:
                        pass  # Don't let callback errors kill the stream

            await running.process.wait()
            duration_ms = (time.time() - running.started_at) * 1000

            if on_complete:
                try:
                    await on_complete(running.run_id, running.process.returncode, duration_ms)
                except Exception:
                    pass

        finally:
            self._running.pop(running.run_id, None)

    async def cancel_tool(self, run_id: int) -> bool:
        """Cancel a running tool."""
        running = self._running.get(run_id)
        if not running:
            return False
        
        running.is_cancelled = True
        try:
            running.process.send_signal(signal.SIGTERM)
            # Give it 3 seconds to terminate gracefully
            try:
                await asyncio.wait_for(running.process.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                running.process.kill()
                await running.process.wait()
        except ProcessLookupError:
            pass  # Already dead
        
        return True

    async def cancel_all(self):
        """Cancel all running tools."""
        for run_id in list(self._running.keys()):
            await self.cancel_tool(run_id)

    def build_command(self, tool_name: str, target: str = "",
                      wordlist: str = "", extra_args: str = "",
                      raw_override: str = "") -> str:
        """
        Build a command string for a tool.
        
        If raw_override is provided, use it directly (advanced mode).
        Otherwise, build from template.
        """
        if raw_override:
            return raw_override

        tool_def = self._tool_definitions.get(tool_name)
        if not tool_def:
            raise ValueError(f"Unknown tool: {tool_name}")

        cmd = tool_def.command
        
        if tool_def.args_template:
            args = tool_def.args_template
            if "{target}" in args:
                if not target:
                    raise ValueError(f"Tool {tool_name} requires a target URL")
                args = args.replace("{target}", target)
            if "{wordlist}" in args:
                if not wordlist:
                    # Try default wordlist
                    default_wl = WORDLISTS_DIR / "common.txt"
                    if default_wl.exists():
                        wordlist = str(default_wl)
                    else:
                        raise ValueError(f"Tool {tool_name} requires a wordlist")
                args = args.replace("{wordlist}", wordlist)
            cmd = f"{cmd} {args}"

        if extra_args:
            cmd = f"{cmd} {extra_args}"

        return cmd
