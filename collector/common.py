"""Shared helpers for read-only evidence collection.

Safety rules enforced here:
* Commands are executed with an argument list (``shell=False``), a fixed
  ``LC_ALL=C`` environment, a timeout and captured output.
* Only read operations are performed.  No collector writes to the host.
* Files are read with a size cap; unreadable/missing files are reported as
  evidence gaps, never as "secure".
* ``assert_no_secrets`` rejects evidence that looks like password hashes or
  private keys before it can be stored.
"""
from __future__ import annotations

import glob
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core.timeutil import utc_now_iso

COLLECTOR_VERSION = "rdf-collector-1.0"

SAFE_ENV = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}


@dataclass
class CommandResult:
    args: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str | None = None  # "not_found" | "timeout" | "permission" | "os_error: ..."

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0


Runner = Callable[[list[str], float], CommandResult]


def run_command(args: list[str], timeout: float) -> CommandResult:
    """Run a read-only command safely. Never raises for expected failures."""
    if not args or not all(isinstance(a, str) for a in args):
        raise ValueError("args must be a non-empty list of strings")
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False,
                              shell=False, env=SAFE_ENV, stdin=subprocess.DEVNULL)
        return CommandResult(tuple(args), proc.returncode, proc.stdout, proc.stderr)
    except FileNotFoundError:
        return CommandResult(tuple(args), None, error="not_found")
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(args), None, error="timeout")
    except PermissionError:
        return CommandResult(tuple(args), None, error="permission")
    except OSError as exc:
        return CommandResult(tuple(args), None, error=f"os_error: {exc}")


def no_command_runner(args: list[str], timeout: float) -> CommandResult:
    """Runner used when collecting from an offline filesystem tree (fixtures)."""
    return CommandResult(tuple(args), None, error="not_found")


@dataclass
class Context:
    """Collection context. ``root`` lets tests point at a fixture tree."""
    root: str = "/"
    runner: Runner = run_command
    timeout: float = 15.0
    max_bytes: int = 1_048_576
    policy_params: dict[str, Any] = field(default_factory=dict)

    def path(self, p: str) -> str:
        if self.root in ("", "/"):
            return p
        return os.path.join(self.root, p.lstrip("/"))

    def read_text(self, p: str) -> tuple[str | None, str | None]:
        """Return (text, error). error in {missing, permission, too_large, os_error}."""
        real = self.path(p)
        try:
            size = os.path.getsize(real)
            if size > self.max_bytes:
                return None, "too_large"
            with open(real, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read(), None
        except FileNotFoundError:
            return None, "missing"
        except PermissionError:
            return None, "permission"
        except IsADirectoryError:
            return None, "os_error: is a directory"
        except OSError as exc:
            return None, f"os_error: {exc.strerror}"

    def exists(self, p: str) -> bool:
        return os.path.exists(self.path(p))

    def glob(self, pattern: str) -> list[str]:
        """Glob relative to root, returning host-style absolute paths, sorted."""
        real_pattern = self.path(pattern)
        out = []
        for m in sorted(glob.glob(real_pattern)):
            if self.root in ("", "/"):
                out.append(m)
            else:
                out.append("/" + os.path.relpath(m, self.root))
        return out

    def run(self, args: list[str]) -> CommandResult:
        return self.runner(args, self.timeout)


def make_check(check_id: str, title: str, collector_status: str, evidence: dict[str, Any],
               sources: list[str], errors: list[str] | None = None,
               limitations: list[str] | None = None) -> dict[str, Any]:
    if collector_status not in ("OK", "PARTIAL", "ERROR"):
        raise ValueError(f"invalid collector_status {collector_status}")
    out = {
        "check_id": check_id,
        "title": title,
        "collected_at": utc_now_iso(),
        "collector_status": collector_status,
        "evidence": evidence,
        "sources": sorted(set(sources)),
        "errors": sorted(set(errors or [])),
        "limitations": list(dict.fromkeys(limitations or [])),
    }
    assert_no_secrets(out)
    return out


def error_check(check_id: str, title: str, exc: BaseException) -> dict[str, Any]:
    return make_check(check_id, title, "ERROR", {}, [], [f"collector exception: {type(exc).__name__}: {exc}"])


# ------------------------------------------------------------------ parsing
def strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


def parse_key_value_file(text: str, sep: str | None = None) -> dict[str, str]:
    """Parse 'KEY value' or 'key = value' lines; later definitions win."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        if sep is None:
            if "=" in line:
                k, v = line.split("=", 1)
            else:
                parts = line.split(None, 1)
                k, v = parts[0], parts[1] if len(parts) > 1 else ""
        else:
            if sep not in line:
                continue
            k, v = line.split(sep, 1)
        out[k.strip().lower()] = v.strip().strip('"').strip("'")
    return out


def to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


@dataclass
class PamLine:
    file: str
    type: str
    control: str
    module: str
    args: dict[str, str]
    flags: list[str]


_PAM_CONTROL_RE = re.compile(r"^(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*)$")


def parse_pam_file(text: str, file: str) -> list[PamLine]:
    """Parse a PAM stack file. Bracketed controls like [success=1 default=ignore] are kept intact."""
    lines: list[PamLine] = []
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line or line.startswith("@include"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        ptype = parts[0].lstrip("-").lower()
        m = _PAM_CONTROL_RE.match(parts[1])
        if not m:
            continue
        control, module, rest = m.group(1), m.group(2), m.group(3)
        args: dict[str, str] = {}
        flags: list[str] = []
        for tok in rest.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                args[k.lower()] = v
            else:
                flags.append(tok.lower())
        lines.append(PamLine(file, ptype, control, os.path.basename(module), args, flags))
    return lines


_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\$(1|2[aby]?|5|6|y|gy|7)\$[./A-Za-z0-9]{1,}\$[./A-Za-z0-9]{8,}"),  # crypt hashes
]
_FORBIDDEN_KEYS = {"password_hash", "private_key", "shadow_contents", "secret", "token"}


class SecretInEvidenceError(ValueError):
    pass


def assert_no_secrets(obj: Any, path: str = "") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in _FORBIDDEN_KEYS:
                raise SecretInEvidenceError(f"forbidden key in evidence: {path}.{k}")
            assert_no_secrets(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            assert_no_secrets(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        for pat in _SECRET_PATTERNS:
            if pat.search(obj):
                raise SecretInEvidenceError(f"secret-like value rejected at {path}")
