# Rego unit tests — run with:  opa test policies/ -v
# All inputs here are SYNTHETIC test fixtures, not host evidence.
package compliance_test

import rego.v1

import data.compliance

ok(e) := {"check_id": "x", "title": "x", "collected_at": "2026-01-01T00:00:00Z", "collector_status": "OK", "evidence": e, "sources": [], "errors": []}

base_checks := {
	"SSH-001": ok({"sshd_installed": true, "method": "sshd -T", "permit_root_login": "no", "value_origin": "effective (sshd -T)", "match_overrides": []}),
	"SSH-002": ok({"sshd_installed": true, "method": "sshd -T", "password_authentication": "no", "kbd_interactive_authentication": "no", "value_origin": {}, "match_overrides": []}),
	"FW-001": ok({"firewall_tool": "ufw", "installed": true, "active": true, "default_incoming": "deny", "rule_count": 1, "method": "ufw status verbose"}),
	"SVC-001": ok({"running_units": ["ssh", "cron"], "enabled_units": ["ssh", "cron"]}),
	"FILE-001": ok({"files": {
		"/etc/passwd": {"exists": true, "mode": 420, "mode_octal": "0644", "owner": "root", "group": "root", "uid": 0, "gid": 0, "is_regular": true},
		"/etc/shadow": {"exists": true, "mode": 416, "mode_octal": "0640", "owner": "root", "group": "shadow", "uid": 0, "gid": 42, "is_regular": true},
	}}),
	"PWD-001": ok({"pwquality_enabled": true, "minlen": 14, "minclass": 3, "dcredit": 0, "ucredit": 0, "lcredit": 0, "ocredit": 0, "pass_max_days": 90, "pass_min_days": 1}),
	"LOCK-001": ok({"faillock_preauth": true, "faillock_authfail": true, "faillock_account": true, "deny": 5, "unlock_time": 900}),
	"UPD-001": ok({"package_installed": true, "update_package_lists": 1, "unattended_upgrade": 1, "periodic_enable": null, "security_origin": true, "upgrade_timer_enabled": true}),
}

params := {
	"services_denylist": ["telnet", "vsftpd"],
	"file_baseline": {
		"/etc/passwd": {"owner": "root", "groups": ["root"], "max_mode": "0644"},
		"/etc/shadow": {"owner": "root", "groups": ["root", "shadow"], "max_mode": "0640"},
	},
}

inp(checks) := {"policy_params": params, "checks": checks}

with_ev(id, patch) := object.union(base_checks, {id: ok(object.union(base_checks[id].evidence, patch))})

test_all_compliant if {
	r := compliance.results with input as inp(base_checks)
	every id in compliance.check_ids {
		r[id].status == "COMPLIANT"
	}
}

test_missing_check_is_unknown if {
	r := compliance.results with input as inp(object.remove(base_checks, ["FW-001"]))
	r["FW-001"].status == "UNKNOWN"
}

test_collector_error_is_error if {
	c := object.union(base_checks, {"UPD-001": object.union(ok({}), {"collector_status": "ERROR", "errors": ["boom"]})})
	r := compliance.results with input as inp(c)
	r["UPD-001"].status == "ERROR"
}

test_root_login_yes if {
	r := compliance.results with input as inp(with_ev("SSH-001", {"permit_root_login": "yes"}))
	r["SSH-001"].status == "NON_COMPLIANT"
}

test_root_login_default_prohibit_password if {
	r := compliance.results with input as inp(with_ev("SSH-001", {"permit_root_login": "prohibit-password"}))
	r["SSH-001"].status == "NON_COMPLIANT"
}

test_root_login_match_override if {
	r := compliance.results with input as inp(with_ev("SSH-001", {"match_overrides": ["yes@/etc/ssh/sshd_config:40"]}))
	r["SSH-001"].status == "NON_COMPLIANT"
}

test_root_login_null_unknown if {
	r := compliance.results with input as inp(with_ev("SSH-001", {"permit_root_login": null}))
	r["SSH-001"].status == "UNKNOWN"
}

test_password_auth_yes if {
	r := compliance.results with input as inp(with_ev("SSH-002", {"password_authentication": "yes"}))
	r["SSH-002"].status == "NON_COMPLIANT"
}

test_firewall_inactive if {
	r := compliance.results with input as inp(with_ev("FW-001", {"active": false}))
	r["FW-001"].status == "NON_COMPLIANT"
}

test_firewall_allow_incoming if {
	r := compliance.results with input as inp(with_ev("FW-001", {"default_incoming": "allow"}))
	r["FW-001"].status == "NON_COMPLIANT"
}

test_firewall_state_unknown if {
	r := compliance.results with input as inp(with_ev("FW-001", {"active": null}))
	r["FW-001"].status == "UNKNOWN"
}

test_prohibited_service if {
	r := compliance.results with input as inp(with_ev("SVC-001", {"enabled_units": ["ssh", "telnet"]}))
	r["SVC-001"].status == "NON_COMPLIANT"
	r["SVC-001"].actual.prohibited == ["telnet"]
}

test_services_unlisted_unknown if {
	r := compliance.results with input as inp(with_ev("SVC-001", {"running_units": null}))
	r["SVC-001"].status == "UNKNOWN"
}

test_shadow_world_readable if {
	files := object.union(base_checks["FILE-001"].evidence.files, {"/etc/shadow": object.union(base_checks["FILE-001"].evidence.files["/etc/shadow"], {"mode": 420, "mode_octal": "0644"})})
	r := compliance.results with input as inp(with_ev("FILE-001", {"files": files}))
	r["FILE-001"].status == "NON_COMPLIANT"
}

test_stricter_mode_is_ok if {
	files := object.union(base_checks["FILE-001"].evidence.files, {"/etc/shadow": object.union(base_checks["FILE-001"].evidence.files["/etc/shadow"], {"mode": 384, "mode_octal": "0600", "group": "root"})})
	r := compliance.results with input as inp(with_ev("FILE-001", {"files": files}))
	r["FILE-001"].status == "COMPLIANT"
}

test_password_short if {
	r := compliance.results with input as inp(with_ev("PWD-001", {"minlen": 8}))
	r["PWD-001"].status == "NON_COMPLIANT"
}

test_password_credits_count_as_classes if {
	r := compliance.results with input as inp(with_ev("PWD-001", {"minclass": 0, "dcredit": -1, "ucredit": -1, "ocredit": -1}))
	r["PWD-001"].status == "COMPLIANT"
}

test_lockout_missing if {
	r := compliance.results with input as inp(with_ev("LOCK-001", {"faillock_preauth": false, "faillock_authfail": false, "deny": null, "unlock_time": null}))
	r["LOCK-001"].status == "NON_COMPLIANT"
}

test_lockout_short_unlock if {
	r := compliance.results with input as inp(with_ev("LOCK-001", {"unlock_time": 60}))
	r["LOCK-001"].status == "NON_COMPLIANT"
}

test_updates_disabled if {
	r := compliance.results with input as inp(with_ev("UPD-001", {"unattended_upgrade": 0}))
	r["UPD-001"].status == "NON_COMPLIANT"
}

test_updates_unknown_timer if {
	r := compliance.results with input as inp(with_ev("UPD-001", {"upgrade_timer_enabled": null}))
	r["UPD-001"].status == "UNKNOWN"
}

test_missing_field_unknown_not_null if {
	e := object.remove(base_checks["PWD-001"].evidence, ["pass_max_days"])
	c := object.union(object.remove(base_checks, ["PWD-001"]), {"PWD-001": ok(e)})
	r := compliance.results with input as inp(c)
	r["PWD-001"].status == "UNKNOWN"
}
