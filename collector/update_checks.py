"""UPD-001 — automatic security updates (unattended-upgrades).

Evidence precedence for APT settings:
1. ``apt-config dump`` — APT's own merged view of every apt.conf.d file.
2. Fallback: parse ``/etc/apt/apt.conf.d/*`` in lexical order (later files
   override scalars, as APT does).

Also collected: package state (dpkg-query), allowed origins containing a
``-security`` pocket, and ``apt-daily(-upgrade).timer`` enablement/activity.
"""
from __future__ import annotations

import re
from typing import Any

from collector.common import Context, make_check

_SCALAR_RE = re.compile(r'^\s*([A-Za-z0-9:_\-]+)\s+"([^"]*)"\s*;', re.M)
_BLOCK_RE = re.compile(r"Unattended-Upgrade::(Allowed-Origins|Origins-Pattern)\s*\{(.*?)\}\s*;", re.S)
_QUOTED_RE = re.compile(r'"([^"]*)"')
SCALAR_KEYS = {"apt::periodic::update-package-lists": "update_package_lists",
               "apt::periodic::unattended-upgrade": "unattended_upgrade",
               "apt::periodic::enable": "periodic_enable"}


def _strip_apt_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|\s)//.*$", "", text, flags=re.M)
    return re.sub(r"^\s*#.*$", "", text, flags=re.M)


def parse_apt_config_dump(text: str) -> dict[str, Any]:
    scalars: dict[str, str] = {}
    origins: list[str] = []
    for line in text.splitlines():
        m = re.match(r'^\s*(\S+)\s+"(.*)";\s*$', line)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2)
        if key in SCALAR_KEYS:
            scalars[SCALAR_KEYS[key]] = val
        elif key.startswith("unattended-upgrade::allowed-origins::") or key.startswith("unattended-upgrade::origins-pattern::"):
            if val:
                origins.append(val)
    return {"scalars": scalars, "origins": origins}


def parse_apt_conf_files(texts: list[str]) -> dict[str, Any]:
    scalars: dict[str, str] = {}
    origins: list[str] = []
    for raw in texts:
        text = _strip_apt_comments(raw)
        for block in _BLOCK_RE.finditer(text):
            origins.extend(_QUOTED_RE.findall(block.group(2)))
        text_wo_blocks = _BLOCK_RE.sub("", text)
        for key, val in _SCALAR_RE.findall(text_wo_blocks):
            if key.lower() in SCALAR_KEYS:
                scalars[SCALAR_KEYS[key.lower()]] = val
    return {"scalars": scalars, "origins": origins}


def _int_or_none(v: str | None) -> int | None:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def collect_updates(ctx: Context) -> dict[str, Any]:
    title = "Automatic security updates enabled"
    errors: list[str] = []
    sources: list[str] = []
    limitations: list[str] = []
    ev: dict[str, Any] = {"package_installed": None, "update_package_lists": None, "unattended_upgrade": None,
                          "periodic_enable": None, "allowed_origins": [], "security_origin": None,
                          "upgrade_timer_enabled": None, "upgrade_timer_active": None,
                          "update_timer_enabled": None, "method": None}

    pkg = ctx.run(["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"])
    if pkg.error is None and pkg.returncode is not None:
        sources.append("dpkg-query unattended-upgrades")
        ev["package_installed"] = pkg.returncode == 0 and "install ok installed" in pkg.stdout
    else:
        errors.append(f"dpkg-query unavailable: {pkg.error}")
        if ctx.exists("/usr/bin/unattended-upgrade"):
            ev["package_installed"] = True
            sources.append("/usr/bin/unattended-upgrade present")

    parsed = None
    dump = ctx.run(["apt-config", "dump"])
    if dump.ok and dump.stdout.strip():
        parsed = parse_apt_config_dump(dump.stdout)
        ev["method"] = "apt-config dump"
        sources.append("apt-config dump")
    else:
        files = ctx.glob("/etc/apt/apt.conf.d/*")
        texts = []
        for f in files:
            t, ferr = ctx.read_text(f)
            if ferr:
                errors.append(f"{f}: {ferr}")
            else:
                texts.append(t)
                sources.append(f)
        if texts or files:
            parsed = parse_apt_conf_files(texts)
            ev["method"] = "apt.conf.d parse"
            limitations.append("APT settings parsed from files; 'apt-config dump' unavailable.")
        else:
            errors.append("no APT configuration found")
    if parsed is not None:
        s = parsed["scalars"]
        ev["update_package_lists"] = _int_or_none(s.get("update_package_lists", "0"))
        ev["unattended_upgrade"] = _int_or_none(s.get("unattended_upgrade", "0"))
        ev["periodic_enable"] = _int_or_none(s.get("periodic_enable")) if "periodic_enable" in s else None
        ev["allowed_origins"] = sorted(set(parsed["origins"]))
        ev["security_origin"] = any("security" in o.lower() for o in parsed["origins"])

    for unit, key_en, key_act in (("apt-daily-upgrade.timer", "upgrade_timer_enabled", "upgrade_timer_active"),
                                  ("apt-daily.timer", "update_timer_enabled", None)):
        en = ctx.run(["systemctl", "is-enabled", unit])
        if en.error is None and en.stdout.strip():
            ev[key_en] = en.stdout.strip() in ("enabled", "static", "enabled-runtime")
            sources.append(f"systemctl is-enabled {unit}")
        else:
            errors.append(f"systemctl is-enabled {unit}: {en.error or 'no output'}")
        if key_act:
            act = ctx.run(["systemctl", "is-active", unit])
            if act.error is None and act.stdout.strip():
                ev[key_act] = act.stdout.strip() == "active"
                sources.append(f"systemctl is-active {unit}")

    if parsed is None and ev["package_installed"] is None:
        status = "ERROR"
    elif errors:
        status = "PARTIAL"
    else:
        status = "OK"
    return make_check("UPD-001", title, status, ev, sources, errors, limitations)
