"""Executor adapters for Jarvis v2.1.

Maps (target, action) pairs to concrete execution logic after a command
has been dequeued and approved.

Built-in executors:
  - LoggerExecutor — logs the command (safe for testing)
  - SubprocessExecutor — runs shell commands (for RUN_SCRIPT, LAUNCH_APP)
  - OpenUrlExecutor — opens URLs via ``open`` / ``xdg-open``
  - ScriptExecutor — runs a whitelisted script by name

Usage::

    registry = ExecutorRegistry()
    registry.register("PC", "OPEN_URL", OpenUrlExecutor())
    result = registry.dispatch(target="PC", action="OPEN_URL", parameter="https://example.com")
"""

from __future__ import annotations

import abc
import logging
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jarvis.types import Command

logger = logging.getLogger("jarvis.executors")


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass
class ExecutorResult:
    """Result of executing a command through an executor adapter.

    Attributes:
        success: True if execution completed without error.
        command_id: The command ID that was executed.
        result: Arbitrary result data (depends on executor type).
        error: Error message if execution failed.
        started_at: ISO-8601 timestamp when execution began.
        completed_at: ISO-8601 timestamp when execution ended.
    """

    success: bool
    command_id: str
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: str | None = None
    completed_at: str | None = None


# ---------------------------------------------------------------------------
# Base executor
# ---------------------------------------------------------------------------


class BaseExecutor(abc.ABC):
    """Abstract base class for executor adapters.

    Subclasses must implement :meth:`execute`.
    """

    def __init__(self, name: str = "") -> None:
        self._name = name or self.__class__.__name__

    @property
    def name(self) -> str:
        return self._name

    @abc.abstractmethod
    def execute(self, command: Command, **kwargs: Any) -> ExecutorResult:
        """Execute a command.

        Args:
            command: The validated command to execute.
            **kwargs: Extra arguments for the executor.

        Returns:
            An ExecutorResult indicating success or failure.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self._name}>"


# ---------------------------------------------------------------------------
# Logger executor (safe for all environments)
# ---------------------------------------------------------------------------


class LoggerExecutor(BaseExecutor):
    """Executor that logs the command and returns success.

    This is the safest executor — it never actually executes anything,
    just records what *would* have been executed. Useful for testing,
    dry-run mode, and audit-only deployments.
    """

    def __init__(self, name: str = "LoggerExecutor") -> None:
        super().__init__(name=name)

    def execute(self, command: Command, **kwargs: Any) -> ExecutorResult:
        started_at = datetime.now(timezone.utc).isoformat()
        logger.info(
            "EXECUTE (dry-run) target=%s action=%s param=%s cmd=%s",
            command.target, command.action, command.parameter, command.command_id,
        )
        logger.debug("Full command: %s", command)
        time.sleep(0.05)  # Simulate a tiny bit of work
        completed_at = datetime.now(timezone.utc).isoformat()

        return ExecutorResult(
            success=True,
            command_id=command.command_id,
            result={
                "dry_run": True,
                "target": command.target,
                "action": command.action,
                "parameter": command.parameter,
            },
            started_at=started_at,
            completed_at=completed_at,
        )


# ---------------------------------------------------------------------------
# Subprocess executor
# ---------------------------------------------------------------------------


class SubprocessExecutor(BaseExecutor):
    """Executor that runs a command via subprocess.

    WARNING: This executor actually runs system commands. Only use with
    validated and approved commands that have passed through the policy gate.

    The ``command_template`` is a string template that can reference:
    ``{parameter}`` — the command's parameter value
    ``{target}`` — the command's target
    ``{action}`` — the command's action
    """

    def __init__(
        self,
        command_template: str = "{parameter}",
        timeout_seconds: int = 30,
        name: str = "",
    ) -> None:
        super().__init__(name=name or "SubprocessExecutor")
        self._command_template = command_template
        self._timeout = timeout_seconds

    def execute(self, command: Command, **kwargs: Any) -> ExecutorResult:
        cmd_str = self._command_template.format(
            parameter=command.parameter,
            target=command.target,
            action=command.action,
        )
        started_at = datetime.now(timezone.utc).isoformat()
        logger.info("EXECUTE subprocess target=%s action=%s cmd=%s",
                     command.target, command.action, command.command_id)

        try:
            parts = shlex.split(cmd_str)
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired as e:
            completed_at = datetime.now(timezone.utc).isoformat()
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"Timeout after {self._timeout}s: {e}",
                started_at=started_at,
                completed_at=completed_at,
            )
        except FileNotFoundError as e:
            completed_at = datetime.now(timezone.utc).isoformat()
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"Command not found: {e}",
                started_at=started_at,
                completed_at=completed_at,
            )
        except OSError as e:
            completed_at = datetime.now(timezone.utc).isoformat()
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"OS error: {e}",
                started_at=started_at,
                completed_at=completed_at,
            )

        completed_at = datetime.now(timezone.utc).isoformat()

        if result.returncode != 0:
            stderr = result.stderr.strip() or "exit code {result.returncode}"
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=stderr,
                result={
                    "returncode": result.returncode,
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip(),
                },
                started_at=started_at,
                completed_at=completed_at,
            )

        return ExecutorResult(
            success=True,
            command_id=command.command_id,
            result={
                "returncode": 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            },
            started_at=started_at,
            completed_at=completed_at,
        )


# ---------------------------------------------------------------------------
# Open URL executor
# ---------------------------------------------------------------------------


class OpenUrlExecutor(BaseExecutor):
    """Executor that opens a URL in the default browser.

    Uses ``open`` on macOS, ``xdg-open`` on Linux, and ``start`` on Windows.
    Only https:// URLs should be passed (http:// should have been escalated
    by the policy gate).
    """

    def __init__(self, name: str = "OpenUrlExecutor") -> None:
        super().__init__(name=name)

    def _open_command(self, url: str) -> list[str]:
        """Return the platform-appropriate command to open a URL."""
        system = sys.platform
        if system == "darwin":
            return ["open", url]
        elif system == "win32":
            return ["cmd", "/c", "start", "", url]
        else:
            return ["xdg-open", url]

    def execute(self, command: Command, **kwargs: Any) -> ExecutorResult:
        url = command.parameter
        started_at = datetime.now(timezone.utc).isoformat()
        logger.info("EXECUTE open-url target=%s url=%s cmd=%s",
                     command.target, url, command.command_id)

        cmd = self._open_command(url)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            completed_at = datetime.now(timezone.utc).isoformat()
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"Failed to open URL: {e}",
                started_at=started_at,
                completed_at=completed_at,
            )

        completed_at = datetime.now(timezone.utc).isoformat()

        if result.returncode != 0:
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"open exited with code {result.returncode}: {result.stderr.strip()}",
                started_at=started_at,
                completed_at=completed_at,
            )

        return ExecutorResult(
            success=True,
            command_id=command.command_id,
            result={"url": url},
            started_at=started_at,
            completed_at=completed_at,
        )


# ---------------------------------------------------------------------------
# Script executor
# ---------------------------------------------------------------------------


class ScriptExecutor(BaseExecutor):
    """Executor that runs a whitelisted script by name.

    The ``script_dir`` should contain executable scripts. The parameter
    is the script name (e.g. ``daily-backup``), which gets resolved to
    ``{script_dir}/{script_name}`` and executed.

    Only scripts listed in the whitelist passed during construction
    should be allowed. This class relies on the policy gate to have
    already validated the script name against the whitelist.
    """

    def __init__(
        self,
        script_dir: str | Path = "/usr/local/bin",
        whitelisted_scripts: set[str] | None = None,
        timeout_seconds: int = 300,
        name: str = "",
    ) -> None:
        super().__init__(name=name or "ScriptExecutor")
        self._script_dir = Path(script_dir)
        self._whitelisted = whitelisted_scripts or {"daily-backup", "sync-photos", "update-hosts"}
        self._timeout = timeout_seconds

    def execute(self, command: Command, **kwargs: Any) -> ExecutorResult:
        script_name = command.parameter.strip()
        started_at = datetime.now(timezone.utc).isoformat()
        logger.info("EXECUTE script target=%s script=%s cmd=%s",
                     command.target, script_name, command.command_id)

        script_path = self._script_dir / script_name

        if script_name not in self._whitelisted:
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"Script '{script_name}' is not in the whitelist",
                started_at=started_at,
                completed_at=started_at,
            )

        if not script_path.is_file():
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"Script not found: {script_path}",
                started_at=started_at,
                completed_at=started_at,
            )

        if not os.access(str(script_path), os.X_OK):
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"Script is not executable: {script_path}",
                started_at=started_at,
                completed_at=started_at,
            )

        try:
            result = subprocess.run(
                [str(script_path)],
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            completed_at = datetime.now(timezone.utc).isoformat()
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"Script execution failed: {e}",
                started_at=started_at,
                completed_at=completed_at,
            )

        completed_at = datetime.now(timezone.utc).isoformat()

        if result.returncode != 0:
            return ExecutorResult(
                success=False,
                command_id=command.command_id,
                error=f"Script '{script_name}' exited with code {result.returncode}: {result.stderr.strip()}",
                result={
                    "script": script_name,
                    "returncode": result.returncode,
                    "stdout": result.stdout.strip(),
                    "stderr": result.stderr.strip(),
                },
                started_at=started_at,
                completed_at=completed_at,
            )

        return ExecutorResult(
            success=True,
            command_id=command.command_id,
            result={
                "script": script_name,
                "returncode": 0,
                "stdout": result.stdout.strip(),
            },
            started_at=started_at,
            completed_at=completed_at,
        )


# ---------------------------------------------------------------------------
# Executor registry
# ---------------------------------------------------------------------------

class ExecutorRegistry:
    """Registry that maps (target, action) pairs to executor adapters.

    Usage::

        registry = ExecutorRegistry()
        registry.register_defaults()  # sets up all built-in mappings
        result = registry.dispatch(command)
    """

    def __init__(self) -> None:
        self._mapping: dict[tuple[str, str], BaseExecutor] = {}
        self._fallback_executor: BaseExecutor | None = None

    def register(
        self,
        target: str,
        action: str,
        executor: BaseExecutor,
    ) -> None:
        """Register an executor for a specific (target, action) pair.

        Args:
            target: The command target (e.g. ``PC``, ``HOME``).
            action: The command action (e.g. ``OPEN_URL``, ``RUN_SCRIPT``).
            executor: The executor adapter to use.
        """
        self._mapping[(target.upper(), action.upper())] = executor

    def set_fallback(self, executor: BaseExecutor) -> None:
        """Set the fallback executor for unregistered (target, action) pairs.

        Args:
            executor: The fallback executor. Defaults to LoggerExecutor.
        """
        self._fallback_executor = executor

    def resolve(self, target: str, action: str) -> BaseExecutor:
        """Resolve the executor for a (target, action) pair.

        Args:
            target: The command target.
            action: The command action.

        Returns:
            The registered executor, or the fallback if not found.
        """
        executor = self._mapping.get((target.upper(), action.upper()))
        if executor is not None:
            return executor
        if self._fallback_executor is not None:
            return self._fallback_executor
        # Default fallback
        return LoggerExecutor(name=f"Fallback-{target}:{action}")

    def dispatch(
        self,
        command: Command,
        **kwargs: Any,
    ) -> ExecutorResult:
        """Dispatch a command to the appropriate executor.

        Args:
            command: The validated command to execute.
            **kwargs: Extra arguments passed through to the executor.

        Returns:
            An ExecutorResult from the executor.
        """
        executor = self.resolve(command.target, command.action)
        logger.debug("Dispatching %s:%s to %s",
                      command.target, command.action, executor.name)
        return executor.execute(command, **kwargs)

    def register_defaults(self) -> None:
        """Register all built-in executor mappings.

        This sets up sensible defaults for all known (target, action) pairs.
        All non-trivial actions use LoggerExecutor by default so that
        the system is safe out of the box — operators can replace with
        real executors as they validate each action.
        """
        # Safe actions — use LoggerExecutor (safe for any env)
        for action in [
            "OPEN_URL", "MEDIA_CONTROL", "TURN_ON", "TURN_OFF",
            "SET_BRIGHTNESS", "SET_SCENE", "LOCK_DOOR",
        ]:
            self.register("PC", action, LoggerExecutor(name=f"Logger-{action}"))
            self.register("HOME", action, LoggerExecutor(name=f"Logger-{action}"))

        # Risky actions — also LoggerExecutor by default (operator must opt in)
        for action in [
            "LOCK_WORKSTATION", "DELETE_FILE", "SHUTDOWN_PC",
            "SEND_KEYSTROKE", "RUN_SCRIPT", "UNLOCK_DOOR", "DISABLE_ALARM",
        ]:
            self.register("PC", action, LoggerExecutor(name=f"Logger-{action}"))
            self.register("HOME", action, LoggerExecutor(name=f"Logger-{action}"))

        # Fallback — any unknown action
        self.set_fallback(LoggerExecutor(name="FallbackExecutor"))
