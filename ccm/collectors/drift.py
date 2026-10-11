"""Configuration-drift collector for Ubuntu (run with sudo for full visibility).

Hardened settings are compared with the expected values in catalog.py.
"Unmanaged" items (listening ports, sudo users, root cron jobs) are compared
with an allow-list snapshot taken the first time the collector runs
(data/real_baseline.json). Review that file once and treat it as approved.
"""
import json
import platform
import re
import shutil
import subprocess
from pathlib import Path

from ..catalog import CONFIG_ITEMS


def _sh(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.stdout.strip()
    except Exception:
        return ""


def _read(path):
    try:
        return Path(path).read_text(errors="ignore")
    except Exception:
        return None


def _conf_value(text, key, sep=r"\s+"):
    if text is None:
        return None
    val = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        m = re.match(rf"^{re.escape(key)}{sep}(.+)$", line, re.I)
        if m:
            val = m.group(1).strip()
    return val


def _sshd(key):
    if shutil.which("sshd"):
        out = _sh(["sshd", "-T"])
        v = _conf_value(out, key.lower(), r"\s+")
        if v:
            return v
    return _conf_value(_read("/etc/ssh/sshd_config"), key)


def _active(svc):
    out = _sh(["systemctl", "is-active", svc])
    return "active" if out == "active" else ("inactive" if out else None)


def _listening_ports():
    out = _sh(["ss", "-ltnH"])
    ports = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            ports.add(parts[3].rsplit(":", 1)[-1])
    return sorted(ports)


def _sudo_users():
    out = _sh(["getent", "group", "sudo"])
    return sorted(u for u in out.split(":")[-1].split(",") if u) if out else []


def _root_cron():
    out = _sh(["crontab", "-l", "-u", "root"])
    return sorted(l.strip() for l in out.splitlines() if l.strip() and not l.strip().startswith("#"))


def current_values():
    mounts = _read("/proc/mounts") or ""
    tmp = [l for l in mounts.splitlines() if " /tmp " in l]
    return {
        "sshd.PermitRootLogin": _sshd("PermitRootLogin"),
        "sshd.PasswordAuthentication": _sshd("PasswordAuthentication"),
        "sshd.ClientAliveInterval": _sshd("ClientAliveInterval"),
        "firewall.ufw": ("active" if "Status: active" in _sh(["ufw", "status"]) else "inactive")
        if shutil.which("ufw") else None,
        "service.auditd": _active("auditd"),
        "service.rsyslog": _active("rsyslog"),
        "login.PASS_MAX_DAYS": _conf_value(_read("/etc/login.defs"), "PASS_MAX_DAYS"),
        "pwquality.minlen": _conf_value(_read("/etc/security/pwquality.conf"), "minlen", r"\s*=\s*"),
        "sysctl.net.ipv4.ip_forward": (_read("/proc/sys/net/ipv4/ip_forward") or "").strip() or None,
        "sysctl.kernel.randomize_va_space": (_read("/proc/sys/kernel/randomize_va_space") or "").strip() or None,
        "mount.tmp_noexec": ("yes" if tmp and "noexec" in tmp[0] else "no"),
        "package.aide": "installed" if "Status: install ok installed" in _sh(["dpkg", "-s", "aide"]) else "missing",
        "banner.issue": "set" if (_read("/etc/issue.net") or _read("/etc/issue") or "").strip() else "unset",
        "os.timezone": (_read("/etc/timezone") or "").strip() or None,
        "motd.text": str(abs(hash(_read("/etc/motd") or ""))),
        "app.log_level": None,
        "_ports": _listening_ports(),
        "_sudo": _sudo_users(),
        "_cron": _root_cron(),
    }


def collect(baseline_file):
    if platform.system() != "Linux":
        # Windows / macOS: settings cannot be read, so report them as unknown
        return [dict(item=i, value="unknown", baseline=m["baseline"], deviates=0,
                     security=int(m["security"]), severity=m["severity"]) for i, m in CONFIG_ITEMS.items()]
    cur = current_values()
    baseline_file = Path(baseline_file)
    if not baseline_file.exists():
        snap = {"ports": cur["_ports"], "sudo_users": cur["_sudo"], "root_cron": cur["_cron"],
                "os.timezone": cur["os.timezone"], "motd.text": cur["motd.text"]}
        baseline_file.write_text(json.dumps(snap, indent=2))
    snap = json.loads(baseline_file.read_text())

    cur["net.unexpected_listening_ports"] = str(len(set(cur["_ports"]) - set(snap["ports"])))
    cur["accounts.unexpected_sudo_users"] = str(len(set(cur["_sudo"]) - set(snap["sudo_users"])))
    cur["cron.unexpected_root_jobs"] = str(len(set(cur["_cron"]) - set(snap["root_cron"])))

    rows = []
    for item, meta in CONFIG_ITEMS.items():
        value = cur.get(item)
        expected = snap.get(item, meta["baseline"]) if not meta["security"] else meta["baseline"]
        if value is None:
            rows.append(dict(item=item, value="unknown", baseline=expected, deviates=0,
                             security=int(meta["security"]), severity=meta["severity"]))
            continue
        dev = _deviates(item, value, expected)
        rows.append(dict(item=item, value=value, baseline=expected, deviates=int(dev),
                         security=int(meta["security"]), severity=meta["severity"]))
    return rows


def _deviates(item, value, expected):
    v = str(value).strip().lower()
    e = str(expected).strip().lower()
    try:
        if item == "login.PASS_MAX_DAYS":
            return int(v) > int(e)
        if item == "pwquality.minlen":
            return int(v) < int(e)
        if item == "sshd.ClientAliveInterval":
            return int(v) == 0 or int(v) > int(e)
    except ValueError:
        return True
    return v != e
