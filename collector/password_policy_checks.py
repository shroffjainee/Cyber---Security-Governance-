"""PWD-001 — password quality (pam_pwquality) and ageing (login.defs).

Effective-value rules implemented:
* pam_pwquality options come from ``/etc/security/pwquality.conf``, then
  ``/etc/security/pwquality.conf.d/*.conf`` (lexical order, later wins), and
  finally module arguments in ``/etc/pam.d/common-password`` which override
  the files.  Unset values use libpwquality defaults (minlen=8, minclass=0,
  credits=0).
* ``pam_cracklib`` is recognised for older systems (same option names).
* Ageing values come from ``/etc/login.defs`` and only apply to accounts
  created afterwards — a documented limitation (existing accounts: chage -l).
"""
from __future__ import annotations

from typing import Any

from collector.common import Context, make_check, parse_key_value_file, parse_pam_file, to_int

PWQ_DEFAULTS = {"minlen": 8, "minclass": 0, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0}
QUALITY_MODULES = ("pam_pwquality.so", "pam_cracklib.so")


def collect_password_policy(ctx: Context) -> dict[str, Any]:
    title = "Password quality and ageing requirements"
    errors: list[str] = []
    sources: list[str] = []
    limitations = ["login.defs ageing applies to newly created accounts; existing accounts need 'chage -l' review."]
    ev: dict[str, Any] = {"quality_module": None, "pwquality_enabled": None,
                          **{k: None for k in PWQ_DEFAULTS}, "value_origin": {},
                          "pass_max_days": None, "pass_min_days": None, "pass_warn_age": None}

    pam_text, err = ctx.read_text("/etc/pam.d/common-password")
    module_line = None
    if err:
        errors.append(f"/etc/pam.d/common-password: {err}")
    else:
        sources.append("/etc/pam.d/common-password")
        for line in parse_pam_file(pam_text, "/etc/pam.d/common-password"):
            if line.type == "password" and line.module in QUALITY_MODULES:
                module_line = line
                break
        ev["pwquality_enabled"] = module_line is not None
        ev["quality_module"] = module_line.module.replace(".so", "") if module_line else None

    if module_line is not None:
        values = dict(PWQ_DEFAULTS)
        origin = {k: "pwquality_default" for k in PWQ_DEFAULTS}
        conf_files = ["/etc/security/pwquality.conf"] + ctx.glob("/etc/security/pwquality.conf.d/*.conf")
        for cf in conf_files:
            text, cerr = ctx.read_text(cf)
            if cerr:
                if cerr != "missing":
                    errors.append(f"{cf}: {cerr}")
                continue
            sources.append(cf)
            for k, v in parse_key_value_file(text).items():
                if k in values and to_int(v) is not None:
                    values[k] = to_int(v)
                    origin[k] = cf
        for k, v in module_line.args.items():
            if k in values and to_int(v) is not None:
                values[k] = to_int(v)
                origin[k] = "pam_args:/etc/pam.d/common-password"
        ev.update(values)
        ev["value_origin"] = origin

    defs, derr = ctx.read_text("/etc/login.defs")
    if derr:
        errors.append(f"/etc/login.defs: {derr}")
    else:
        sources.append("/etc/login.defs")
        kv = parse_key_value_file(defs)
        ev["pass_max_days"] = to_int(kv.get("pass_max_days"))
        ev["pass_min_days"] = to_int(kv.get("pass_min_days"))
        ev["pass_warn_age"] = to_int(kv.get("pass_warn_age"))

    if ev["pwquality_enabled"] is None and ev["pass_max_days"] is None:
        status = "ERROR"
    elif errors:
        status = "PARTIAL"
    else:
        status = "OK"
    return make_check("PWD-001", title, status, ev, sources, errors, limitations)
