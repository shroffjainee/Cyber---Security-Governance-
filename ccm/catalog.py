"""Control catalogue used by both the real collectors and the simulator.

Rule IDs follow the SCAP Security Guide (SSG) naming used by OpenSCAP, so a
real `oscap xccdf eval` result file maps onto the same identifiers.

Each configuration item says:
  baseline   - the expected (hardened) value
  rule       - the OpenSCAP rule it drives, or None if no rule covers it
               (unmanaged drift: Compliance-as-Code cannot see it)
  severity   - high / medium / low (security impact if it deviates)
  security   - False for operational settings whose change is harmless
  iso / nist - interpretive mapping used for governance reporting
"""

PREFIX = "xccdf_org.ssgproject.content_rule_"

CONFIG_ITEMS = {
    # ---- covered by an OpenSCAP rule (CaC can see these) ----
    "sshd.PermitRootLogin": dict(baseline="no", rule="sshd_disable_root_login", severity="high",
                                 security=True, iso="A.8.5", nist="PR.AA"),
    "sshd.PasswordAuthentication": dict(baseline="no", rule="sshd_disable_password_authentication",
                                        severity="medium", security=True, iso="A.8.5", nist="PR.AA"),
    "firewall.ufw": dict(baseline="active", rule="service_ufw_enabled", severity="high",
                         security=True, iso="A.8.20", nist="PR.IR"),
    "service.auditd": dict(baseline="active", rule="service_auditd_enabled", severity="medium",
                           security=True, iso="A.8.15", nist="DE.CM"),
    "service.rsyslog": dict(baseline="active", rule="service_rsyslog_enabled", severity="medium",
                            security=True, iso="A.8.15", nist="DE.CM"),
    "login.PASS_MAX_DAYS": dict(baseline="90", rule="accounts_maximum_age_login_defs", severity="medium",
                                security=True, iso="A.5.17", nist="PR.AA"),
    "pwquality.minlen": dict(baseline="14", rule="accounts_password_pam_minlen", severity="medium",
                             security=True, iso="A.5.17", nist="PR.AA"),
    "sysctl.net.ipv4.ip_forward": dict(baseline="0", rule="sysctl_net_ipv4_ip_forward", severity="medium",
                                       security=True, iso="A.8.20", nist="PR.PS"),
    "sysctl.kernel.randomize_va_space": dict(baseline="2", rule="sysctl_kernel_randomize_va_space",
                                             severity="medium", security=True, iso="A.8.9", nist="PR.PS"),
    "mount.tmp_noexec": dict(baseline="yes", rule="mount_option_tmp_noexec", severity="low",
                             security=True, iso="A.8.9", nist="PR.PS"),
    "package.aide": dict(baseline="installed", rule="package_aide_installed", severity="medium",
                         security=True, iso="A.8.16", nist="DE.CM"),
    "banner.issue": dict(baseline="set", rule="banner_etc_issue", severity="low",
                         security=True, iso="A.5.10", nist="GV.PO"),
    "sshd.ClientAliveInterval": dict(baseline="300", rule="sshd_set_idle_timeout", severity="low",
                                     security=True, iso="A.8.5", nist="PR.AA"),
    # ---- security-relevant but NOT in the OpenSCAP profile (unmanaged drift) ----
    "net.unexpected_listening_ports": dict(baseline="0", rule=None, severity="high",
                                           security=True, iso="A.8.20", nist="DE.CM"),
    "accounts.unexpected_sudo_users": dict(baseline="0", rule=None, severity="high",
                                           security=True, iso="A.8.2", nist="PR.AA"),
    "cron.unexpected_root_jobs": dict(baseline="0", rule=None, severity="medium",
                                      security=True, iso="A.8.9", nist="DE.CM"),
    # ---- operational settings: change is harmless (noise for naive drift tools) ----
    "os.timezone": dict(baseline="Asia/Kolkata", rule=None, severity="low", security=False,
                        iso="-", nist="-"),
    "app.log_level": dict(baseline="INFO", rule=None, severity="low", security=False,
                          iso="-", nist="-"),
    "motd.text": dict(baseline="default", rule=None, severity="low", security=False,
                      iso="-", nist="-"),
}

# TLS certificate controls (added in response to the internal panel comment
# "Certificate Authority issues"). Applied to publicly exposed assets.
CERT_RULES = {
    "tls_certificate_not_expiring": dict(severity="medium", iso="A.8.24", nist="PR.DS"),
    "tls_certificate_not_expired": dict(severity="high", iso="A.8.24", nist="PR.DS"),
    "tls_certificate_trusted_ca": dict(severity="high", iso="A.8.24", nist="PR.DS"),
    "tls_key_strength_2048": dict(severity="medium", iso="A.8.24", nist="PR.DS"),
}


# "Key controls": rules that drive the risk score at full weight. In a real
# CIS profile (200+ rules) every other failing rule only adds a bounded
# "hygiene" term, otherwise one important change would be diluted by
# hundreds of minor findings. Any rule OpenSCAP marks "high" is also key.
KEY_RULES = {v["rule"] for v in CONFIG_ITEMS.values() if v["rule"]} | set(CERT_RULES) | {
    "sshd_disable_empty_passwords", "sshd_set_max_auth_tries", "sshd_use_strong_ciphers",
    "package_ufw_installed", "service_nftables_enabled", "auditd_data_retention_space_left_action",
    "accounts_password_pam_retry", "no_empty_passwords", "file_permissions_etc_shadow",
    "file_permissions_etc_passwd", "package_telnet_removed", "package_xinetd_removed",
}


def rule_to_item():
    return {v["rule"]: k for k, v in CONFIG_ITEMS.items() if v["rule"]}


def all_rules(public):
    rules = {v["rule"]: dict(severity=v["severity"], iso=v["iso"], nist=v["nist"])
             for v in CONFIG_ITEMS.values() if v["rule"]}
    if public:
        rules.update(CERT_RULES)
    return rules


def bad_value(item):
    """A deviating value used by the simulator for a given item."""
    bad = {
        "sshd.PermitRootLogin": "yes", "sshd.PasswordAuthentication": "yes",
        "firewall.ufw": "inactive", "service.auditd": "inactive", "service.rsyslog": "inactive",
        "login.PASS_MAX_DAYS": "99999", "pwquality.minlen": "6", "sysctl.net.ipv4.ip_forward": "1",
        "sysctl.kernel.randomize_va_space": "0", "mount.tmp_noexec": "no", "package.aide": "missing",
        "banner.issue": "unset", "sshd.ClientAliveInterval": "0",
        "net.unexpected_listening_ports": "1", "accounts.unexpected_sudo_users": "1",
        "cron.unexpected_root_jobs": "1", "os.timezone": "UTC", "app.log_level": "DEBUG",
        "motd.text": "changed",
    }
    return bad[item]
