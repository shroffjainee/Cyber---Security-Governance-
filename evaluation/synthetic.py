"""SYNTHETIC fixture builders — for tests, demonstrations and the
reproducible evaluation only.  Everything produced here is labelled
``data_origin = "SYNTHETIC"`` and must never be presented as a real host
assessment or a real Greenbone scan.
"""
from __future__ import annotations

import copy
from typing import Any
from xml.sax.saxutils import escape

from collector.common import COLLECTOR_VERSION
from core.catalog import CHECKS


def _chk(cid: str, evidence: dict[str, Any], ts: str, status: str = "OK") -> dict[str, Any]:
    return {"check_id": cid, "title": CHECKS[cid]["title"], "collected_at": ts, "collector_status": status,
            "evidence": evidence, "sources": ["synthetic fixture"], "errors": [], "limitations": []}


def compliant_evidence(asset_id: str, ts: str, policy_params: dict[str, Any]) -> dict[str, Any]:
    """A fully compliant Ubuntu 24.04 evidence document (synthetic)."""
    files = {
        "/etc/passwd": {"exists": True, "mode": 0o644, "mode_octal": "0644", "uid": 0, "gid": 0, "owner": "root", "group": "root", "is_regular": True},
        "/etc/shadow": {"exists": True, "mode": 0o640, "mode_octal": "0640", "uid": 0, "gid": 42, "owner": "root", "group": "shadow", "is_regular": True},
        "/etc/group": {"exists": True, "mode": 0o644, "mode_octal": "0644", "uid": 0, "gid": 0, "owner": "root", "group": "root", "is_regular": True},
        "/etc/gshadow": {"exists": True, "mode": 0o640, "mode_octal": "0640", "uid": 0, "gid": 42, "owner": "root", "group": "shadow", "is_regular": True},
    }
    ssh_common = {"sshd_installed": True, "method": "sshd -T", "config_files": ["/etc/ssh/sshd_config"]}
    checks = {
        "SSH-001": _chk("SSH-001", {**ssh_common, "permit_root_login": "no", "value_origin": "effective (sshd -T)", "match_overrides": []}, ts),
        "SSH-002": _chk("SSH-002", {**ssh_common, "password_authentication": "no", "kbd_interactive_authentication": "no",
                                    "value_origin": {"password_authentication": "effective (sshd -T)", "kbd_interactive_authentication": "effective (sshd -T)"},
                                    "match_overrides": []}, ts),
        "FW-001": _chk("FW-001", {"firewall_tool": "ufw", "installed": True, "active": True, "default_incoming": "deny",
                                  "default_outgoing": "allow", "rules": ["22/tcp | ALLOW IN | Anywhere"], "rule_count": 1,
                                  "method": "ufw status verbose"}, ts),
        "SVC-001": _chk("SVC-001", {"running_units": ["cron", "rsyslog", "ssh", "systemd-journald"],
                                    "enabled_units": ["cron", "rsyslog", "ssh", "ufw"]}, ts),
        "FILE-001": _chk("FILE-001", {"files": files}, ts),
        "PWD-001": _chk("PWD-001", {"quality_module": "pam_pwquality", "pwquality_enabled": True, "minlen": 14, "minclass": 3,
                                    "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0,
                                    "value_origin": {"minlen": "/etc/security/pwquality.conf"},
                                    "pass_max_days": 90, "pass_min_days": 1, "pass_warn_age": 7}, ts),
        "LOCK-001": _chk("LOCK-001", {"faillock_preauth": True, "faillock_authfail": True, "faillock_account": True,
                                      "pam_tally2_present": False, "deny": 5, "unlock_time": 900, "fail_interval": 900,
                                      "even_deny_root": False, "value_origin": {}}, ts),
        "UPD-001": _chk("UPD-001", {"package_installed": True, "update_package_lists": 1, "unattended_upgrade": 1,
                                    "periodic_enable": None, "allowed_origins": ["${distro_id}:${distro_codename}-security"],
                                    "security_origin": True, "upgrade_timer_enabled": True, "upgrade_timer_active": True,
                                    "update_timer_enabled": True, "method": "apt-config dump"}, ts),
    }
    return {"schema_version": "1.0", "data_origin": "SYNTHETIC", "collector_version": COLLECTOR_VERSION,
            "collected_at": ts, "asset": {"asset_id": asset_id, "hostname": asset_id,
                                          "os_release": {"id": "ubuntu", "version_id": "24.04", "pretty_name": "Ubuntu 24.04 LTS (synthetic)"}},
            "policy_params": copy.deepcopy(policy_params), "checks": checks}


def mutate(doc: dict[str, Any], cid: str, ts: str | None = None, **changes: Any) -> dict[str, Any]:
    """Return a copy with evidence fields of ``cid`` changed."""
    new = copy.deepcopy(doc)
    if ts:
        new["collected_at"] = ts
        for c in new["checks"].values():
            c["collected_at"] = ts
    new["checks"][cid]["evidence"].update(changes)
    return new


def with_time(doc: dict[str, Any], ts: str) -> dict[str, Any]:
    new = copy.deepcopy(doc)
    new["collected_at"] = ts
    for c in new["checks"].values():
        c["collected_at"] = ts
    return new


def collector_error(doc: dict[str, Any], cid: str, message: str = "simulated collector failure") -> dict[str, Any]:
    new = copy.deepcopy(doc)
    new["checks"][cid].update(collector_status="ERROR", evidence={}, errors=[message])
    return new


def greenbone_xml(report_id: str, host: str, scan_start: str, scan_end: str,
                  results: list[dict[str, Any]], gmp_version: str = "22.4") -> str:
    """Build a SYNTHETIC report in Greenbone's XML report structure.

    results items: {id, name, oid, port, severity (float|None), threat, qod, cves: [..], solution}
    """
    parts = [f'<report id="{escape(report_id)}" format_id="a994b278-1f62-11e1-96ac-406186ea4fc5" extension="xml" '
             'content_type="text/xml">', "<name>SYNTHETIC TEST REPORT - not a real scan</name>",
             f'<report id="{escape(report_id)}"><gmp><version>{gmp_version}</version></gmp>',
             f"<scan_start>{scan_start}</scan_start>", f"<scan_end>{scan_end}</scan_end>",
             f'<results start="1" max="{len(results)}">']
    for r in results:
        sev = "" if r.get("severity") is None else f"{r['severity']}"
        refs = "".join(f'<ref type="cve" id="{escape(c)}"/>' for c in r.get("cves", []))
        sev_block = (f'<severities score="{sev}"><severity type="cvss_base_v3"><score>{sev}</score>'
                     f"<value>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</value></severity></severities>") if sev else ""
        parts.append(
            f'<result id="{escape(r["id"])}"><name>{escape(r["name"])}</name>'
            f"<host>{escape(host)}<hostname>{escape(r.get('hostname', ''))}</hostname></host>"
            f"<port>{escape(r.get('port', 'general/tcp'))}</port>"
            f'<nvt oid="{escape(r["oid"])}"><type>nvt</type><name>{escape(r["name"])}</name>{sev_block}'
            f"<solution type=\"VendorFix\">{escape(r.get('solution', 'Update the affected package.'))}</solution>"
            f"<refs>{refs}</refs></nvt>"
            f"<threat>{escape(r.get('threat', 'Medium'))}</threat><severity>{sev}</severity>"
            f"<qod><value>{r.get('qod', 80)}</value><type>remote_banner</type></qod>"
            f"<description>{escape(r.get('description', 'Synthetic finding for parser/scoring tests.'))}</description>"
            "</result>")
    parts.append("</results></report></report>")
    return "\n".join(parts)


GREENBONE_CSV_HEADER = ("IP,Hostname,Port,Port Protocol,CVSS,Severity,QoD,Solution Type,NVT Name,Summary,"
                        "Specific Result,NVT OID,CVEs,Task ID,Task Name,Timestamp,Result ID,Impact,Solution")


def greenbone_csv(host: str, ts: str, rows: list[dict[str, Any]]) -> str:
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(GREENBONE_CSV_HEADER.split(","))
    for r in rows:
        port, _, proto = str(r.get("port", "22/tcp")).partition("/")
        w.writerow([host, r.get("hostname", ""), port, proto or "tcp",
                    "" if r.get("severity") is None else r["severity"], r.get("threat", "Medium"), r.get("qod", 80),
                    "VendorFix", r["name"], "Synthetic finding", "", r["oid"], ",".join(r.get("cves", [])),
                    "synthetic-task", "SYNTHETIC", ts, r["id"], "", r.get("solution", "Update")])
    return buf.getvalue()


SAMPLE_FINDINGS = [
    {"id": "syn-r1", "name": "OpenSSH Multiple Vulnerabilities (synthetic)", "oid": "1.3.6.1.4.1.25623.1.0.900001",
     "port": "22/tcp", "severity": 9.8, "threat": "High", "cves": ["CVE-2023-38408"]},
    {"id": "syn-r2", "name": "Weak SSH MAC algorithms (synthetic)", "oid": "1.3.6.1.4.1.25623.1.0.900002",
     "port": "22/tcp", "severity": 2.6, "threat": "Low", "cves": []},
    {"id": "syn-r3", "name": "TCP timestamps information disclosure (synthetic)", "oid": "1.3.6.1.4.1.25623.1.0.900003",
     "port": "general/tcp", "severity": 2.6, "threat": "Low", "cves": []},
]
