"""SVC-001 — prohibited / unnecessary services.

Evidence: running and enabled systemd service+socket units.  Unit suffixes
are stripped (``cups.socket`` and ``cups.service`` both become ``cups``) so
policy lists use plain names.  Matching against the deny/allowlist is done
in Rego, not here, keeping collection and evaluation separate.
"""
from __future__ import annotations

from typing import Any

from collector.common import Context, make_check

SUFFIXES = (".service", ".socket")


def _unit_name(token: str) -> str | None:
    token = token.strip().lstrip("●*").strip()
    for suf in SUFFIXES:
        if token.endswith(suf):
            return token[: -len(suf)]
    return None


def parse_unit_list(text: str) -> list[str]:
    names = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        name = _unit_name(parts[0])
        if name:
            names.add(name)
    return sorted(names)


def normalize_process_name(name: str) -> str:
    """Map a process name to the service name used in policy lists ("in.telnetd" -> "telnetd")."""
    name = name.strip()
    if name.startswith("in."):
        name = name[3:]
    return name


def list_running_processes(ctx: Context) -> list[str] | None:
    """Read-only fallback when systemd is not PID 1 (containers, minimal hosts).

    Returns None when /proc cannot be read.  Only processes that correspond to an
    installed service definition (systemd unit file or SysV init script) are kept,
    so short-lived shells/tools do not appear as false configuration drift."""
    procs = ctx.glob("/proc/[0-9]*/comm")
    if not procs:
        return None
    names = set()
    for comm in procs:
        text, err = ctx.read_text(comm)
        if err or not text:
            continue
        n = normalize_process_name(text)
        if n and _is_service(ctx, n):
            names.add(n)
    return sorted(names)


SERVICE_DIRS = ("/lib/systemd/system", "/usr/lib/systemd/system", "/etc/systemd/system")


def _is_service(ctx: Context, name: str) -> bool:
    for d in SERVICE_DIRS:
        if ctx.exists(f"{d}/{name}.service") or ctx.exists(f"{d}/{name}.socket"):
            return True
    return ctx.exists(f"/etc/init.d/{name}")


def collect_services(ctx: Context) -> dict[str, Any]:
    title = "No prohibited network services running or enabled"
    errors: list[str] = []
    sources: list[str] = []
    running_cmd = ["systemctl", "list-units", "--type=service,socket", "--state=running,listening",
                   "--no-legend", "--plain", "--no-pager"]
    enabled_cmd = ["systemctl", "list-unit-files", "--type=service,socket", "--state=enabled",
                   "--no-legend", "--no-pager"]
    running = ctx.run(running_cmd)
    enabled = ctx.run(enabled_cmd)
    ev: dict[str, Any] = {"running_units": None, "enabled_units": None, "method": "systemd"}
    limitations = ["Only systemd units are inspected; processes started outside systemd are not detected."]
    if running.ok:
        ev["running_units"] = parse_unit_list(running.stdout)
        sources.append("systemctl list-units (running/listening)")
    else:
        errors.append(f"running units unavailable: {running.error or running.stderr.strip()[:160]}")
        procs = list_running_processes(ctx)
        if procs is not None:
            ev["running_units"] = procs
            ev["method"] = "proc_fallback"
            sources.append("/proc/*/comm (running process names; systemd unavailable)")
            limitations = ["systemd unavailable: running services taken from the process table; enabled "
                           "(start-at-boot) units could not be determined."]
    if enabled.ok:
        ev["enabled_units"] = parse_unit_list(enabled.stdout)
        sources.append("systemctl list-unit-files (enabled)")
    else:
        errors.append(f"enabled units unavailable: {enabled.error or enabled.stderr.strip()[:160]}")
    if ev["running_units"] is None and ev["enabled_units"] is None:
        status = "ERROR"
    elif errors:
        status = "PARTIAL"
    else:
        status = "OK"
    return make_check("SVC-001", title, status, ev, sources, errors, limitations)
