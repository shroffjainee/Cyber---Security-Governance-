"""SSH-001 (root login) and SSH-002 (password authentication).

Evidence precedence:
1. ``sshd -T`` — prints the *effective* global configuration after all
   Include files and defaults are applied.  Normally needs root (it loads
   host keys).  This is the authoritative source.
2. Fallback: parse ``/etc/ssh/sshd_config`` following ``Include`` directives
   in order.  For these keywords sshd uses the *first* value it reads, so the
   first occurrence outside a ``Match`` block wins; unset keywords fall back
   to OpenSSH defaults (PermitRootLogin prohibit-password since 7.0,
   PasswordAuthentication yes, KbdInteractiveAuthentication yes).

Limitations (recorded in evidence): the fallback parser does not evaluate
Match criteria; any Match block that overrides a directive is reported in
``match_overrides`` and treated by the policy as a potential violation.
"""
from __future__ import annotations

import os
from typing import Any

from collector.common import Context, make_check, strip_comment

SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_BINARIES = ("/usr/sbin/sshd", "/usr/bin/sshd")
DEFAULTS = {"permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
            "kbdinteractiveauthentication": "yes"}
ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}
WANTED = set(DEFAULTS)
MAX_INCLUDE_DEPTH = 16


def detect_sshd_installed(ctx: Context) -> tuple[bool | None, list[str]]:
    sources: list[str] = []
    binary = any(ctx.exists(b) for b in SSHD_BINARIES)
    if binary:
        sources.append("sshd binary present")
    res = ctx.run(["dpkg-query", "-W", "-f=${Status}", "openssh-server"])
    pkg: bool | None = None
    if res.error is None:
        sources.append("dpkg-query openssh-server")
        if res.returncode == 0 and "install ok installed" in res.stdout:
            pkg = True
        elif res.returncode is not None:
            pkg = False
    if binary or pkg:
        return True, sources
    if pkg is False:
        return False, sources
    return None, sources


def _parse_config(ctx: Context, path: str, depth: int, entries: list[dict[str, Any]],
                  files: list[str], errors: list[str], seen: set[str]) -> None:
    if depth > MAX_INCLUDE_DEPTH:
        errors.append(f"include depth exceeded at {path}")
        return
    if path in seen:
        errors.append(f"include loop at {path}")
        return
    seen.add(path)
    text, err = ctx.read_text(path)
    if err:
        errors.append(f"{path}: {err}")
        return
    files.append(path)
    in_match = False
    match_criteria = ""
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw)
        if not line:
            continue
        parts = line.replace("=", " ", 1).split(None, 1) if "=" in line.split(None, 1)[0] else line.split(None, 1)
        key = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if key == "match":
            in_match = value.lower() != "all"
            match_criteria = value
            continue
        if key == "include":
            for pattern in value.split():
                pattern = pattern.strip('"')
                if not pattern.startswith("/"):
                    pattern = os.path.join("/etc/ssh", pattern)
                for inc in ctx.glob(pattern):
                    _parse_config(ctx, inc, depth + 1, entries, files, errors, seen)
            continue
        key = ALIASES.get(key, key)
        if key in WANTED:
            entries.append({"key": key, "value": value.split()[0].lower() if value else "",
                            "origin": f"{path}:{lineno}", "in_match": in_match, "criteria": match_criteria})


def collect_ssh(ctx: Context) -> dict[str, dict[str, Any]]:
    sources: list[str] = []
    errors: list[str] = []
    limitations: list[str] = []
    installed, inst_sources = detect_sshd_installed(ctx)
    sources += inst_sources

    values: dict[str, str | None] = {k: None for k in WANTED}
    origins: dict[str, str | None] = {k: None for k in WANTED}
    match_overrides: dict[str, list[str]] = {k: [] for k in WANTED}
    method: str | None = None
    files: list[str] = []

    if installed is False:
        method = "not_installed"
    else:
        res = ctx.run(["sshd", "-T"])
        if res.ok and "permitrootlogin" in res.stdout.lower():
            method = "sshd -T"
            sources.append("sshd -T")
            for line in res.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    key = ALIASES.get(parts[0].lower(), parts[0].lower())
                    if key in WANTED and values[key] is None:
                        values[key] = parts[1].strip().lower()
                        origins[key] = "effective (sshd -T)"
        else:
            if res.error:
                errors.append(f"sshd -T unavailable: {res.error}")
            elif res.returncode not in (0, None):
                errors.append(f"sshd -T exited {res.returncode}: {res.stderr.strip()[:200]}")
        # Config parsing is always done (when files exist) so Match overrides are visible.
        entries: list[dict[str, Any]] = []
        if ctx.exists(SSHD_CONFIG):
            _parse_config(ctx, SSHD_CONFIG, 0, entries, files, errors, set())
            sources += files
        elif installed:
            errors.append(f"{SSHD_CONFIG}: missing")
        for e in entries:
            if e["in_match"]:
                match_overrides[e["key"]].append(f"{e['value']}@{e['origin']}")
        if method is None and files:
            method = "config_parse"
            limitations.append("Effective config not verified with 'sshd -T' (run as root for authoritative result).")
            for e in entries:
                if not e["in_match"] and values[e["key"]] is None:
                    values[e["key"]] = e["value"]
                    origins[e["key"]] = e["origin"]
            for k in WANTED:
                if values[k] is None:
                    values[k] = DEFAULTS[k]
                    origins[k] = "openssh_default"
        if any(match_overrides.values()):
            limitations.append("Match blocks override authentication settings for some connections; criteria not evaluated.")

    if method == "not_installed":
        status = "OK"
    elif method in ("sshd -T", "config_parse"):
        # sshd -T failing is expected without root; it is a limitation, not a parse error.
        parse_errors = [e for e in errors if not e.startswith("sshd -T")]
        status = "PARTIAL" if parse_errors else "OK"
    else:
        status = "ERROR"
        if installed is None:
            errors.append("could not determine whether openssh-server is installed")

    common = {"sshd_installed": installed, "method": method, "config_files": files}
    ssh1 = make_check("SSH-001", "SSH root login disabled", status, {
        **common,
        "permit_root_login": values["permitrootlogin"],
        "value_origin": origins["permitrootlogin"],
        "match_overrides": sorted(match_overrides["permitrootlogin"]),
    }, sources, errors, limitations)
    ssh2 = make_check("SSH-002", "SSH password authentication disabled", status, {
        **common,
        "password_authentication": values["passwordauthentication"],
        "kbd_interactive_authentication": values["kbdinteractiveauthentication"],
        "value_origin": {"password_authentication": origins["passwordauthentication"],
                         "kbd_interactive_authentication": origins["kbdinteractiveauthentication"]},
        "match_overrides": sorted(match_overrides["passwordauthentication"]
                                  + match_overrides["kbdinteractiveauthentication"]),
    }, sources, errors, limitations)
    return {"SSH-001": ssh1, "SSH-002": ssh2}
