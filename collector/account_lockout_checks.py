"""LOCK-001 — account lockout with pam_faillock (Ubuntu 22.04+).

Effective-value rules: ``/etc/security/faillock.conf`` provides defaults for
pam_faillock; module arguments on the PAM line override it.  Built-in
defaults when unset: deny=3, unlock_time=600, fail_interval=900.

Ubuntu does not enable pam_faillock by default; a stock system is therefore
expected to be NON_COMPLIANT.  ``pam_tally2`` (removed in newer PAM) is
detected and reported but not accepted as compliant by the default policy.
"""
from __future__ import annotations

from typing import Any

from collector.common import Context, make_check, parse_key_value_file, parse_pam_file, to_int

FAILLOCK_DEFAULTS = {"deny": 3, "unlock_time": 600, "fail_interval": 900}


def collect_account_lockout(ctx: Context) -> dict[str, Any]:
    title = "Account lockout after failed logins (pam_faillock)"
    errors: list[str] = []
    sources: list[str] = []
    ev: dict[str, Any] = {"faillock_preauth": None, "faillock_authfail": None, "faillock_account": None,
                          "pam_tally2_present": None, "deny": None, "unlock_time": None,
                          "fail_interval": None, "even_deny_root": None, "value_origin": {}}

    auth_text, err = ctx.read_text("/etc/pam.d/common-auth")
    auth_lines = []
    if err:
        errors.append(f"/etc/pam.d/common-auth: {err}")
    else:
        sources.append("/etc/pam.d/common-auth")
        auth_lines = parse_pam_file(auth_text, "/etc/pam.d/common-auth")
        fl = [line for line in auth_lines if line.type == "auth" and line.module == "pam_faillock.so"]
        ev["faillock_preauth"] = any("preauth" in line.flags for line in fl)
        ev["faillock_authfail"] = any("authfail" in line.flags for line in fl)
        ev["pam_tally2_present"] = any(line.module == "pam_tally2.so" for line in auth_lines)

    acct_text, err = ctx.read_text("/etc/pam.d/common-account")
    if err:
        errors.append(f"/etc/pam.d/common-account: {err}")
    else:
        sources.append("/etc/pam.d/common-account")
        acct = parse_pam_file(acct_text, "/etc/pam.d/common-account")
        ev["faillock_account"] = any(line.type == "account" and line.module == "pam_faillock.so" for line in acct)

    if ev["faillock_preauth"] or ev["faillock_authfail"]:
        values: dict[str, Any] = dict(FAILLOCK_DEFAULTS)
        origin = {k: "faillock_default" for k in FAILLOCK_DEFAULTS}
        even_deny_root = False
        conf, cerr = ctx.read_text("/etc/security/faillock.conf")
        if cerr and cerr != "missing":
            errors.append(f"/etc/security/faillock.conf: {cerr}")
        elif not cerr:
            sources.append("/etc/security/faillock.conf")
            kv = parse_key_value_file(conf)
            for k in FAILLOCK_DEFAULTS:
                if to_int(kv.get(k)) is not None:
                    values[k] = to_int(kv[k])
                    origin[k] = "/etc/security/faillock.conf"
            if "even_deny_root" in kv:
                even_deny_root = True
        for line in auth_lines:
            if line.module == "pam_faillock.so":
                for k in FAILLOCK_DEFAULTS:
                    if to_int(line.args.get(k)) is not None:
                        values[k] = to_int(line.args[k])
                        origin[k] = "pam_args:/etc/pam.d/common-auth"
                if "even_deny_root" in line.flags:
                    even_deny_root = True
        ev.update(values)
        ev["even_deny_root"] = even_deny_root
        ev["value_origin"] = origin

    if ev["faillock_preauth"] is None:
        status = "ERROR"
    elif errors:
        status = "PARTIAL"
    else:
        status = "OK"
    return make_check("LOCK-001", title, status, ev, sources, errors,
                      ["Only the common-auth/common-account stacks are inspected; service-specific PAM files may differ."])
