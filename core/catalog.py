"""Catalogue of the eight security checks.

Stable IDs are used everywhere: evidence JSON, Rego results, SQLite rows,
risk weights and the dashboard.  Never renumber an ID; add a new one.
"""
from __future__ import annotations

from typing import TypedDict


class CheckInfo(TypedDict):
    check_id: str
    title: str
    purpose: str
    severity: str  # drift priority when this check newly fails
    evidence_sources: list[str]
    expected: str
    remediation: str


CHECKS: dict[str, CheckInfo] = {
    "SSH-001": {
        "check_id": "SSH-001",
        "title": "SSH root login disabled",
        "purpose": "Prevent direct remote login as root, forcing named accounts and privilege escalation that can be audited.",
        "severity": "CRITICAL",
        "evidence_sources": ["sshd -T (effective config, needs root)", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf (Include)"],
        "expected": "PermitRootLogin is one of policy_params.ssh_allowed_permit_root_login (default: no)",
        "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config (before any Include that overrides it, or in a file under sshd_config.d that sorts first), run 'sudo sshd -t' and 'sudo systemctl reload ssh'.",
    },
    "SSH-002": {
        "check_id": "SSH-002",
        "title": "SSH password authentication disabled",
        "purpose": "Require key-based authentication to resist password guessing and credential stuffing.",
        "severity": "HIGH",
        "evidence_sources": ["sshd -T", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf (e.g. 50-cloud-init.conf)"],
        "expected": "PasswordAuthentication no and KbdInteractiveAuthentication no (unless policy allows passwords)",
        "remediation": "Set 'PasswordAuthentication no' and 'KbdInteractiveAuthentication no'; check /etc/ssh/sshd_config.d/50-cloud-init.conf which often re-enables passwords; validate with 'sudo sshd -T | grep -i authentication'.",
    },
    "FW-001": {
        "check_id": "FW-001",
        "title": "Host firewall (UFW) active with default-deny inbound",
        "purpose": "Restrict inbound network exposure to explicitly permitted services.",
        "severity": "CRITICAL",
        "evidence_sources": ["ufw status verbose (needs root)", "/etc/ufw/ufw.conf", "/etc/default/ufw", "systemctl is-active ufw"],
        "expected": "UFW active; default incoming policy in policy_params.firewall_allowed_default_incoming (deny/reject)",
        "remediation": "Allow required ports first (e.g. 'sudo ufw allow OpenSSH'), then 'sudo ufw default deny incoming' and 'sudo ufw enable'.",
    },
    "SVC-001": {
        "check_id": "SVC-001",
        "title": "No prohibited network services running or enabled",
        "purpose": "Reduce attack surface by removing legacy or unnecessary services.",
        "severity": "HIGH",
        "evidence_sources": ["systemctl list-units --type=service --state=running", "systemctl list-unit-files --type=service --state=enabled"],
        "expected": "No running/enabled service matches policy_params.services_denylist (and, in allowlist mode, only allowlisted services run)",
        "remediation": "Stop and disable the service ('sudo systemctl disable --now <name>') or remove its package if not required.",
    },
    "FILE-001": {
        "check_id": "FILE-001",
        "title": "Account database file permissions and ownership",
        "purpose": "Protect password hashes and account data from unauthorized reading or modification.",
        "severity": "CRITICAL",
        "evidence_sources": ["os.stat() of /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow"],
        "expected": "Owner root; group in baseline list; mode no more permissive than baseline (passwd 0644, shadow 0640)",
        "remediation": "e.g. 'sudo chown root:shadow /etc/shadow && sudo chmod 0640 /etc/shadow'; 'sudo chown root:root /etc/passwd && sudo chmod 0644 /etc/passwd'.",
    },
    "PWD-001": {
        "check_id": "PWD-001",
        "title": "Password quality and ageing requirements",
        "purpose": "Ensure local passwords meet minimum length/complexity and are rotated per policy.",
        "severity": "MEDIUM",
        "evidence_sources": ["/etc/pam.d/common-password", "/etc/security/pwquality.conf(.d)", "/etc/login.defs"],
        "expected": "pam_pwquality enabled, minlen >= password_min_length, character classes >= password_min_classes, PASS_MAX_DAYS <= password_max_days, PASS_MIN_DAYS >= password_min_days",
        "remediation": "Install libpam-pwquality, set minlen/minclass in /etc/security/pwquality.conf, set PASS_MAX_DAYS / PASS_MIN_DAYS in /etc/login.defs (applies to new accounts; use chage for existing ones).",
    },
    "LOCK-001": {
        "check_id": "LOCK-001",
        "title": "Account lockout after failed logins (pam_faillock)",
        "purpose": "Slow down online password guessing against local accounts.",
        "severity": "MEDIUM",
        "evidence_sources": ["/etc/pam.d/common-auth", "/etc/pam.d/common-account", "/etc/security/faillock.conf"],
        "expected": "pam_faillock preauth+authfail in common-auth, 1 <= deny <= lockout_max_deny, unlock_time == 0 or >= lockout_min_unlock_time",
        "remediation": "Configure pam_faillock in common-auth (preauth before pam_unix, authfail after) and common-account, set deny/unlock_time in /etc/security/faillock.conf. Test in a second root session before logging out.",
    },
    "UPD-001": {
        "check_id": "UPD-001",
        "title": "Automatic security updates enabled",
        "purpose": "Ensure security patches are applied promptly without manual intervention.",
        "severity": "HIGH",
        "evidence_sources": ["dpkg-query unattended-upgrades", "apt-config dump", "/etc/apt/apt.conf.d/*", "systemctl is-enabled/is-active apt-daily-upgrade.timer"],
        "expected": "unattended-upgrades installed; APT::Periodic::Update-Package-Lists and ::Unattended-Upgrade >= 1; security origin allowed; apt-daily-upgrade.timer enabled",
        "remediation": "'sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades'; confirm '-security' origin in 50unattended-upgrades and 'systemctl enable --now apt-daily-upgrade.timer'.",
    },
}

CHECK_IDS: tuple[str, ...] = tuple(CHECKS)
STATUSES = ("COMPLIANT", "NON_COMPLIANT", "UNKNOWN", "ERROR")
