"""FW-001 — UFW active with a default-deny/reject inbound policy.

Evidence precedence:
1. ``ufw status verbose`` (runtime state; requires root).
2. Fallback: ``/etc/ufw/ufw.conf`` (ENABLED=yes|no) + ``/etc/default/ufw``
   (DEFAULT_INPUT_POLICY) + ``systemctl is-active ufw``.  This shows the
   *configured* state, not the loaded netfilter rules — recorded as a
   limitation.

Only UFW is supported as ``firewall_tool``.  Hosts protected by raw
nftables/iptables or an external firewall will be reported as non-compliant
or unknown and must be documented as an exception.
"""
from __future__ import annotations

import re
from typing import Any

from collector.common import Context, make_check, parse_key_value_file

POLICY_MAP = {"drop": "deny", "deny": "deny", "reject": "reject", "accept": "allow", "allow": "allow"}


def parse_ufw_status(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"active": None, "default_incoming": None, "default_outgoing": None,
                           "default_routed": None, "rules": []}
    in_rules = False
    for raw in text.splitlines():
        line = raw.strip()
        low = line.lower()
        if low.startswith("status:"):
            val = low.split(":", 1)[1].strip()
            out["active"] = True if val == "active" else False if val == "inactive" else None
        elif low.startswith("default:"):
            for m in re.finditer(r"(\w+)\s*\((incoming|outgoing|routed)\)", low):
                out[f"default_{m.group(2)}"] = m.group(1)
        elif line.startswith("--"):
            in_rules = True
        elif in_rules and line:
            out["rules"].append(re.sub(r"\s{2,}", " | ", line))
    out["rules"] = sorted(out["rules"])
    return out


def collect_firewall(ctx: Context) -> dict[str, Any]:
    title = "Host firewall (UFW) active with default-deny inbound"
    tool = ctx.policy_params.get("firewall_tool", "ufw")
    sources: list[str] = []
    errors: list[str] = []
    limitations: list[str] = []
    if tool != "ufw":
        return make_check("FW-001", title, "ERROR", {"firewall_tool": tool}, [],
                          [f"firewall_tool '{tool}' is not supported by this collector (only 'ufw')"])

    installed = ctx.exists("/usr/sbin/ufw") or ctx.exists("/etc/ufw/ufw.conf")
    ev: dict[str, Any] = {"firewall_tool": "ufw", "installed": installed, "active": None,
                          "default_incoming": None, "default_outgoing": None, "rules": [],
                          "rule_count": None, "method": None}
    if not installed:
        ev.update(active=False, method="not_installed")
        sources.append("ufw binary/config absence")
        return make_check("FW-001", title, "OK", ev, sources, errors,
                          ["Only UFW is evaluated; nftables/iptables-only setups are not recognised."])

    res = ctx.run(["ufw", "status", "verbose"])
    if res.ok and "status:" in res.stdout.lower():
        parsed = parse_ufw_status(res.stdout)
        ev.update(active=parsed["active"], default_incoming=parsed["default_incoming"],
                  default_outgoing=parsed["default_outgoing"], rules=parsed["rules"],
                  rule_count=len(parsed["rules"]), method="ufw status verbose")
        sources.append("ufw status verbose")
        if parsed["active"] and parsed["default_incoming"] is None:
            errors.append("could not parse default incoming policy from ufw output")
        return make_check("FW-001", title, "PARTIAL" if errors else "OK", ev, sources, errors, limitations)

    errors.append(f"ufw status unavailable: {res.error or (res.stdout + res.stderr).strip()[:160]}")
    limitations.append("Runtime firewall state not verified (run as root); configured state used.")
    conf, err = ctx.read_text("/etc/ufw/ufw.conf")
    enabled = None
    if err:
        errors.append(f"/etc/ufw/ufw.conf: {err}")
    else:
        sources.append("/etc/ufw/ufw.conf")
        val = parse_key_value_file(conf).get("enabled")
        enabled = True if val == "yes" else False if val == "no" else None
    dflt, err = ctx.read_text("/etc/default/ufw")
    if err:
        errors.append(f"/etc/default/ufw: {err}")
    else:
        sources.append("/etc/default/ufw")
        kv = parse_key_value_file(dflt)
        ev["default_incoming"] = POLICY_MAP.get(kv.get("default_input_policy", "").lower())
        ev["default_outgoing"] = POLICY_MAP.get(kv.get("default_output_policy", "").lower())
    svc = ctx.run(["systemctl", "is-active", "ufw"])
    service_active = None
    if svc.error is None and svc.stdout.strip():
        sources.append("systemctl is-active ufw")
        service_active = svc.stdout.strip() == "active"
    if enabled is False:
        ev["active"] = False
    elif enabled is True and service_active is not False:
        ev["active"] = True
        if service_active is None:
            limitations.append("ufw.service state unknown; ENABLED=yes taken as active.")
    ev["method"] = "config_files"
    status = "ERROR" if ev["active"] is None and ev["default_incoming"] is None else "PARTIAL"
    return make_check("FW-001", title, status, ev, sources, errors, limitations)
