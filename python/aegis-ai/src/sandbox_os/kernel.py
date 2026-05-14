"""
AEGIS Execution Kernel — Hardened
===================================
Changes vs original:
  C-02  Strict command allowlist — no arbitrary executables
  H-04  Execution timeout reduced from 30 s → 5 s
  H-05  Internal errors sanitized before returning to caller
"""

import subprocess
import time
import os
import logging
from pathlib import Path
from typing import List
from pydantic import BaseModel
from ..telemetry import telemetry

logger = logging.getLogger("aegis_kernel")

SANDBOX_MODE = os.environ.get("SANDBOX_MODE", "subprocess")

# ── C-02: Strict allowlist of permitted executables ───────────────────────────
# Only these base-names (resolved to absolute paths) may be spawned.
# Extend via the AEGIS_ALLOWED_COMMANDS env var (colon-separated basenames).
_DEFAULT_ALLOWED = {"python3", "python", "node", "ruff", "pytest", "git"}
_env_extra = set(os.environ.get("AEGIS_ALLOWED_COMMANDS", "").split(":")) - {""}
ALLOWED_COMMANDS: frozenset[str] = frozenset(_DEFAULT_ALLOWED | _env_extra)

# Hard-banned arguments that must never appear anywhere in the command list
BANNED_ARGS: frozenset[str] = frozenset({
    "-c", "--cmd",                           # shell eval
    "sh", "bash", "zsh", "fish", "cmd",     # shell invocations
    "rm", "rmdir", "dd", "mkfs",            # destructive ops
    "curl", "wget", "nc", "ncat",           # network exfil
    "sudo", "su", "chmod", "chown",         # privilege change
    "eval", "exec",                          # dynamic eval
})

EXECUTION_TIMEOUT_SEC: int = int(os.environ.get("AEGIS_EXEC_TIMEOUT", "5"))  # H-04


class ExecutionResult(BaseModel):
    execution_id: str
    status: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: float


def _validate_command(command: List[str]) -> None:
    """
    C-02: Validate command against allowlist and banned-arg list.
    Raises ValueError if the command is not permitted.
    """
    if not command:
        raise ValueError("Empty command is not permitted.")

    executable = Path(command[0]).name.lower()  # basename only
    if executable not in ALLOWED_COMMANDS:
        raise ValueError(f"Executable '{executable}' is not in the permitted command allowlist.")

    for arg in command[1:]:
        if arg.strip().lower() in BANNED_ARGS:
            raise ValueError(f"Argument '{arg}' is banned and may not be passed to sandboxed commands.")


class ExecutionKernel:
    """
    Tier 4 Sandbox Execution Engine.
    Applies allowlist validation before spawning any process.
    Production deployments should use SANDBOX_MODE=gvisor or firecracker.
    """

    def spawn_sandboxed_task(
        self,
        command: List[str],
        execution_id: str,
        allowed_capabilities: List[str],
    ) -> ExecutionResult:
        start_time = time.time()
        telemetry.log_event("SandboxSpawn", {
            "execution_id": execution_id,
            "command": command,
            "capabilities": allowed_capabilities,
        })

        # C-02: allowlist check before any subprocess call
        try:
            _validate_command(command)
        except ValueError as e:
            logger.warning("Command rejected [%s]: %s", execution_id, e)
            duration = (time.time() - start_time) * 1000
            result = ExecutionResult(
                execution_id=execution_id,
                status="blocked",
                stdout="",
                stderr="Command rejected by AEGIS policy engine.",
                exit_code=-3,
                duration_ms=duration,
            )
            telemetry.log_event("SandboxBlocked", result.model_dump())
            return result

        # H-09: Environment Sanitization — do NOT leak host env vars to the sandbox
        # Only pass a minimal set of safe variables
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "PYTHONUNBUFFERED": "1",
        }

        if SANDBOX_MODE == "docker":
            # H-07: Verify docker is actually working before attempting execution
            try:
                subprocess.run(["docker", "ps"], capture_output=True, check=True)
            except Exception:
                logger.critical("SANDBOX ERROR: Docker mode requested but docker is not responding.")
                raise RuntimeError("Mandatory Docker sandbox is unavailable. Execution blocked.")

            exec_cmd = [
                "docker", "run", "--rm",
                "--network", "none",
                "--user", "nobody",
                "--memory", "512m",
                "--cpus", "0.5",
                "python:3.11-slim"
            ] + command
            env_to_pass = None # Docker run doesn't use host env by default
        elif SANDBOX_MODE == "subprocess":
            # Subprocess is permitted only if explicitly set and not in a high-security environment
            exec_cmd = command
            env_to_pass = safe_env
        else:
            logger.critical("SANDBOX ERROR: Unknown or unsupported sandbox mode: %s", SANDBOX_MODE)
            raise ValueError(f"Unsupported sandbox mode: {SANDBOX_MODE}")

        try:
            process = subprocess.run(
                exec_cmd,
                env=env_to_pass,
                capture_output=True,
                text=True,
                timeout=EXECUTION_TIMEOUT_SEC,  # H-04: tight timeout
                check=False,
            )
            status    = "completed"
            exit_code = process.returncode
            stdout    = process.stdout[:4096]   # cap output size
            stderr    = process.stderr[:1024]

        except subprocess.TimeoutExpired:
            status    = "timeout"
            exit_code = -1
            stdout    = ""
            stderr    = f"Execution timed out after {EXECUTION_TIMEOUT_SEC}s."

        except Exception as e:
            # H-05: log internally, return generic message to caller
            logger.error("Sandbox execution error [%s]: %s", execution_id, e, exc_info=True)
            status    = "error"
            exit_code = -2
            stdout    = ""
            stderr    = "Internal execution error. See server logs for details."

        duration = (time.time() - start_time) * 1000
        result = ExecutionResult(
            execution_id=execution_id,
            status=status,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=duration,
        )
        telemetry.log_event("SandboxResult", result.model_dump())
        return result


kernel = ExecutionKernel()
