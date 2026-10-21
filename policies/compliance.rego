# Compliance policy for the Risk Drift Framework (RDF).
#
# Input : the normalized evidence document produced by collector/ (see
#         collector/evidence_schema.json).  Policy parameters come from
#         input.policy_params (config/asset_policy.json), merged over the
#         defaults below.
# Output: data.compliance.results — one object per check id:
#         {check_id, status, reason, expected, actual, violations}
#         status ∈ COMPLIANT | NON_COMPLIANT | UNKNOWN | ERROR
#
# Rules of evaluation (identical for every check):
#   1. check missing from input            -> UNKNOWN  (never compliant)
#   2. collector_status == "ERROR"         -> ERROR
#   3. any definite violation              -> NON_COMPLIANT
#   4. a required value is null/undetermined -> UNKNOWN
#   5. otherwise                           -> COMPLIANT
#
# Evaluate with:  opa eval -d policies/ -I --format json "data.compliance.results" < evidence.json

package compliance

import rego.v1

policy_version := "rdf-policy-1.0"

check_ids := ["SSH-001", "SSH-002", "FW-001", "SVC-001", "FILE-001", "PWD-001", "LOCK-001", "UPD-001"]

default_params := {
	"ssh_allowed_permit_root_login": ["no"],
	"ssh_password_authentication_allowed": false,
	"ssh_absent_is_compliant": true,
	"firewall_allowed_default_incoming": ["deny", "reject"],
	"services_denylist": [],
	"services_allowlist_mode": false,
	"services_allowlist": [],
	"file_baseline": {
		"/etc/passwd": {"owner": "root", "groups": ["root"], "max_mode": "0644"},
		"/etc/shadow": {"owner": "root", "groups": ["root", "shadow"], "max_mode": "0640"},
	},
	"password_min_length": 14,
	"password_min_classes": 3,
	"password_max_days": 365,
	"password_min_days": 1,
	"lockout_max_deny": 5,
	"lockout_min_unlock_time": 900,
	"updates_require_security_origin": true,
	"updates_require_timer": true,
}

params := object.union(default_params, object.get(input, "policy_params", {}))

checks := object.get(input, "checks", {})

# ---------------------------------------------------------------- helpers
mk(id, status, reason, expected, actual, violations) := {
	"check_id": id,
	"status": status,
	"reason": reason,
	"expected": expected,
	"actual": actual,
	"violations": violations,
}

wrap(id, evaluated, expected) := mk(id, "UNKNOWN", "No evidence was collected for this check; it cannot be treated as compliant.", expected, null, []) if {
	not checks[id]
} else := mk(id, "ERROR", sprintf("Collector failed: %s", [concat("; ", checks[id].errors)]), expected, null, []) if {
	checks[id].collector_status == "ERROR"
} else := mk(id, "UNKNOWN", "Policy evaluation incomplete for this evidence.", expected, null, []) if {
	evaluated == null
} else := evaluated

decide(id, violations, unknowns, expected, actual, ok_reason) := mk(id, "NON_COMPLIANT", concat("; ", sort(violations)), expected, actual, sort(violations)) if {
	count(violations) > 0
} else := mk(id, "UNKNOWN", sprintf("Evidence inconclusive: %s", [concat("; ", sort(unknowns))]), expected, actual, []) if {
	count(unknowns) > 0
} else := mk(id, "COMPLIANT", ok_reason, expected, actual, [])

as_list(x) := x if is_array(x)

else := []

ev(id) := checks[id].evidence

# null-safe field access: a missing evidence field is null (=> UNKNOWN), never undefined
g(id, k) := object.get(object.get(checks[id], "evidence", {}), k, null)

# octal string ("0644" / "644") -> integer
octal(s) := n if {
	t := sprintf("%04s", [s])
	d := [to_number(c) | some c in split(replace(t, " ", "0"), "")]
	n := (((d[0] * 512) + (d[1] * 64)) + (d[2] * 8)) + d[3]
}

# ---------------------------------------------------------------- SSH-001
ssh1_expected := sprintf("PermitRootLogin in %v", [params.ssh_allowed_permit_root_login])

ssh1_violations contains msg if {
	e := ev("SSH-001")
	e.sshd_installed != false
	is_string(e.permit_root_login)
	not e.permit_root_login in params.ssh_allowed_permit_root_login
	msg := sprintf("PermitRootLogin is '%s' (source: %v)", [e.permit_root_login, object.get(e, "value_origin", "unknown")])
}

ssh1_violations contains msg if {
	e := ev("SSH-001")
	some o in as_list(e.match_overrides)
	v := split(o, "@")[0]
	not v in params.ssh_allowed_permit_root_login
	msg := sprintf("Match block sets PermitRootLogin '%s' at %s", [v, split(o, "@")[1]])
}

ssh1_unknowns contains "openssh-server installation state unknown and no effective value" if {
	e := ev("SSH-001")
	not is_string(object.get(e, "permit_root_login", null))
	g("SSH-001", "sshd_installed") != false
}

ssh1_unknowns contains "openssh-server absent but policy requires explicit evaluation" if {
	g("SSH-001", "sshd_installed") == false
	params.ssh_absent_is_compliant != true
}

ssh1_reason := "openssh-server is not installed (no SSH exposure)" if {
	g("SSH-001", "sshd_installed") == false
} else := sprintf("PermitRootLogin is '%s' via %s", [g("SSH-001", "permit_root_login"), g("SSH-001", "method")])

ssh_001 := wrap(
	"SSH-001", decide(
		"SSH-001", ssh1_violations, ssh1_unknowns, ssh1_expected,
		{"permit_root_login": g("SSH-001", "permit_root_login"), "sshd_installed": g("SSH-001", "sshd_installed"), "method": g("SSH-001", "method")},
		ssh1_reason,
	),
	ssh1_expected,
) if {
	checks["SSH-001"].collector_status != "ERROR"
} else := wrap("SSH-001", null, ssh1_expected)

# ---------------------------------------------------------------- SSH-002
ssh2_expected := "PasswordAuthentication no and KbdInteractiveAuthentication no" if {
	params.ssh_password_authentication_allowed == false
} else := "Password authentication permitted by documented policy exception"

ssh2_violations contains msg if {
	params.ssh_password_authentication_allowed == false
	e := ev("SSH-002")
	e.sshd_installed != false
	some field in ["password_authentication", "kbd_interactive_authentication"]
	is_string(e[field])
	e[field] != "no"
	msg := sprintf("%s is '%s' (source: %v)", [field, e[field], object.get(object.get(e, "value_origin", {}), field, "unknown")])
}

ssh2_violations contains msg if {
	params.ssh_password_authentication_allowed == false
	some o in as_list(g("SSH-002", "match_overrides"))
	split(o, "@")[0] != "no"
	msg := sprintf("Match block enables password-style authentication at %s", [split(o, "@")[1]])
}

ssh2_unknowns contains sprintf("%s could not be determined", [field]) if {
	e := ev("SSH-002")
	g("SSH-002", "sshd_installed") != false
	some field in ["password_authentication", "kbd_interactive_authentication"]
	not is_string(object.get(e, field, null))
}

ssh2_unknowns contains "openssh-server absent but policy requires explicit evaluation" if {
	g("SSH-002", "sshd_installed") == false
	params.ssh_absent_is_compliant != true
}

ssh2_reason := "openssh-server is not installed (no SSH exposure)" if {
	g("SSH-002", "sshd_installed") == false
} else := "Password authentication allowed by policy" if {
	params.ssh_password_authentication_allowed == true
} else := "Password and keyboard-interactive authentication are disabled"

ssh_002 := wrap(
	"SSH-002", decide(
		"SSH-002", ssh2_violations, ssh2_unknowns, ssh2_expected,
		{"password_authentication": g("SSH-002", "password_authentication"), "kbd_interactive_authentication": g("SSH-002", "kbd_interactive_authentication"), "method": g("SSH-002", "method")},
		ssh2_reason,
	),
	ssh2_expected,
) if {
	checks["SSH-002"].collector_status != "ERROR"
} else := wrap("SSH-002", null, ssh2_expected)

# ---------------------------------------------------------------- FW-001
fw_expected := sprintf("UFW active with default incoming policy in %v", [params.firewall_allowed_default_incoming])

fw_violations contains "UFW is not installed; no supported host firewall detected" if {
	g("FW-001", "installed") == false
}

fw_violations contains "UFW is installed but inactive" if {
	g("FW-001", "installed") == true
	g("FW-001", "active") == false
}

fw_violations contains msg if {
	e := ev("FW-001")
	e.active == true
	is_string(e.default_incoming)
	not e.default_incoming in params.firewall_allowed_default_incoming
	msg := sprintf("Default incoming policy is '%s'", [e.default_incoming])
}

fw_unknowns contains "firewall active state could not be determined" if {
	g("FW-001", "active") == null
}

fw_unknowns contains "default incoming policy could not be determined" if {
	g("FW-001", "active") == true
	not is_string(g("FW-001", "default_incoming"))
}

fw_001 := wrap(
	"FW-001", decide(
		"FW-001", fw_violations, fw_unknowns, fw_expected,
		{"installed": g("FW-001", "installed"), "active": g("FW-001", "active"), "default_incoming": g("FW-001", "default_incoming"), "rule_count": g("FW-001", "rule_count"), "method": g("FW-001", "method")},
		"UFW is active with a restrictive default inbound policy",
	),
	fw_expected,
) if {
	checks["FW-001"].collector_status != "ERROR"
} else := wrap("FW-001", null, fw_expected)

# ---------------------------------------------------------------- SVC-001
svc_expected := "No running or enabled unit matches services_denylist (allowlist enforced when enabled)"

svc_all_units := array.concat(as_list(g("SVC-001", "running_units")), as_list(g("SVC-001", "enabled_units")))

svc_prohibited contains u if {
	some u in svc_all_units
	u in params.services_denylist
}

svc_violations contains sprintf("Prohibited service present: %s", [u]) if {
	some u in svc_prohibited
}

svc_violations contains sprintf("Running service not in allowlist: %s", [u]) if {
	params.services_allowlist_mode == true
	some u in as_list(g("SVC-001", "running_units"))
	not u in params.services_allowlist
}

svc_unknowns contains "running units could not be listed" if {
	not is_array(g("SVC-001", "running_units"))
}

svc_unknowns contains "enabled units could not be listed" if {
	not is_array(g("SVC-001", "enabled_units"))
}

svc_001 := wrap(
	"SVC-001", decide(
		"SVC-001", svc_violations, svc_unknowns, svc_expected,
		{"prohibited": sort(svc_prohibited), "running_count": count(as_list(g("SVC-001", "running_units"))), "enabled_count": count(as_list(g("SVC-001", "enabled_units")))},
		"No prohibited services running or enabled",
	),
	svc_expected,
) if {
	checks["SVC-001"].collector_status != "ERROR"
} else := wrap("SVC-001", null, svc_expected)

# ---------------------------------------------------------------- FILE-001
file_expected := sprintf("Baseline: %v", [params.file_baseline])

file_entry(path) := g("FILE-001", "files")[path]

file_violations contains sprintf("%s is missing", [path]) if {
	some path, _ in params.file_baseline
	file_entry(path).exists == false
}

file_violations contains sprintf("%s is not a regular file", [path]) if {
	some path, _ in params.file_baseline
	file_entry(path).exists == true
	file_entry(path).is_regular == false
}

file_violations contains sprintf("%s owner is '%s' (expected '%s')", [path, f.owner, b.owner]) if {
	some path, b in params.file_baseline
	f := file_entry(path)
	f.exists == true
	is_string(f.owner)
	f.owner != b.owner
}

file_violations contains sprintf("%s owner uid %v is not root", [path, f.uid]) if {
	some path, b in params.file_baseline
	f := file_entry(path)
	f.exists == true
	not is_string(f.owner)
	b.owner == "root"
	f.uid != 0
}

file_violations contains sprintf("%s group is '%s' (allowed %v)", [path, f.group, b.groups]) if {
	some path, b in params.file_baseline
	f := file_entry(path)
	f.exists == true
	is_string(f.group)
	not f.group in b.groups
}

file_violations contains sprintf("%s mode %s is more permissive than %s", [path, f.mode_octal, b.max_mode]) if {
	some path, b in params.file_baseline
	f := file_entry(path)
	f.exists == true
	is_number(f.mode)
	bits.and(f.mode, 4095 - octal(b.max_mode)) != 0
}

file_unknowns contains sprintf("%s: no evidence", [path]) if {
	some path, _ in params.file_baseline
	not file_entry(path)
}

file_unknowns contains sprintf("%s: stat failed", [path]) if {
	some path, _ in params.file_baseline
	file_entry(path).exists == null
}

file_unknowns contains sprintf("%s: group name unresolved (gid %v)", [path, f.gid]) if {
	some path, _ in params.file_baseline
	f := file_entry(path)
	f.exists == true
	not is_string(f.group)
}

file_actual[path] := sprintf("%v %v:%v", [f.mode_octal, f.owner, f.group]) if {
	some path, f in g("FILE-001", "files")
}

file_001 := wrap(
	"FILE-001", decide(
		"FILE-001", file_violations, file_unknowns, file_expected, file_actual,
		"All account database files match the ownership/permission baseline",
	),
	file_expected,
) if {
	checks["FILE-001"].collector_status != "ERROR"
} else := wrap("FILE-001", null, file_expected)

# ---------------------------------------------------------------- PWD-001
pwd_expected := sprintf("pam_pwquality enabled, minlen>=%v, classes>=%v, PASS_MAX_DAYS<=%v, PASS_MIN_DAYS>=%v", [params.password_min_length, params.password_min_classes, params.password_max_days, params.password_min_days])

pwd_classes := max([g("PWD-001", "minclass"), count([k | some k in ["dcredit", "ucredit", "lcredit", "ocredit"]; is_number(ev("PWD-001")[k]); ev("PWD-001")[k] < 0])]) if {
	is_number(g("PWD-001", "minclass"))
}

pwd_violations contains "Password quality module (pam_pwquality) not enabled in common-password" if {
	g("PWD-001", "pwquality_enabled") == false
}

pwd_violations contains sprintf("minlen is %v (required >= %v)", [e.minlen, params.password_min_length]) if {
	e := ev("PWD-001")
	e.pwquality_enabled == true
	e.minlen < params.password_min_length
}

pwd_violations contains sprintf("effective character classes %v (required >= %v)", [pwd_classes, params.password_min_classes]) if {
	g("PWD-001", "pwquality_enabled") == true
	pwd_classes < params.password_min_classes
}

pwd_violations contains sprintf("PASS_MAX_DAYS is %v (required <= %v)", [e.pass_max_days, params.password_max_days]) if {
	e := ev("PWD-001")
	is_number(e.pass_max_days)
	e.pass_max_days > params.password_max_days
}

pwd_violations contains sprintf("PASS_MIN_DAYS is %v (required >= %v)", [e.pass_min_days, params.password_min_days]) if {
	e := ev("PWD-001")
	is_number(e.pass_min_days)
	e.pass_min_days < params.password_min_days
}

pwd_unknowns contains "password quality module state unknown" if {
	g("PWD-001", "pwquality_enabled") == null
}

pwd_unknowns contains "PASS_MAX_DAYS not determined" if {
	not is_number(g("PWD-001", "pass_max_days"))
}

pwd_unknowns contains "PASS_MIN_DAYS not determined" if {
	not is_number(g("PWD-001", "pass_min_days"))
}

pwd_001 := wrap(
	"PWD-001", decide(
		"PWD-001", pwd_violations, pwd_unknowns, pwd_expected,
		{"pwquality_enabled": g("PWD-001", "pwquality_enabled"), "minlen": g("PWD-001", "minlen"), "minclass": g("PWD-001", "minclass"), "pass_max_days": g("PWD-001", "pass_max_days"), "pass_min_days": g("PWD-001", "pass_min_days")},
		"Password quality and ageing meet policy",
	),
	pwd_expected,
) if {
	checks["PWD-001"].collector_status != "ERROR"
} else := wrap("PWD-001", null, pwd_expected)

# ---------------------------------------------------------------- LOCK-001
lock_expected := sprintf("pam_faillock preauth+authfail+account, 1<=deny<=%v, unlock_time==0 or >=%v", [params.lockout_max_deny, params.lockout_min_unlock_time])

lock_violations contains "pam_faillock preauth line missing in common-auth" if {
	g("LOCK-001", "faillock_preauth") == false
}

lock_violations contains "pam_faillock authfail line missing in common-auth" if {
	g("LOCK-001", "faillock_authfail") == false
}

lock_violations contains "pam_faillock missing in common-account (counter never reset)" if {
	g("LOCK-001", "faillock_preauth") == true
	g("LOCK-001", "faillock_account") == false
}

lock_violations contains sprintf("deny=%v outside 1..%v", [e.deny, params.lockout_max_deny]) if {
	e := ev("LOCK-001")
	is_number(e.deny)
	not between(e.deny, 1, params.lockout_max_deny)
}

lock_violations contains sprintf("unlock_time=%v below %v seconds", [e.unlock_time, params.lockout_min_unlock_time]) if {
	e := ev("LOCK-001")
	is_number(e.unlock_time)
	e.unlock_time != 0
	e.unlock_time < params.lockout_min_unlock_time
}

between(x, lo, hi) if {
	x >= lo
	x <= hi
}

lock_unknowns contains "common-auth faillock state unknown" if {
	g("LOCK-001", "faillock_preauth") == null
}

lock_unknowns contains "common-account faillock state unknown" if {
	g("LOCK-001", "faillock_account") == null
}

lock_001 := wrap(
	"LOCK-001", decide(
		"LOCK-001", lock_violations, lock_unknowns, lock_expected,
		{"preauth": g("LOCK-001", "faillock_preauth"), "authfail": g("LOCK-001", "faillock_authfail"), "account": g("LOCK-001", "faillock_account"), "deny": g("LOCK-001", "deny"), "unlock_time": g("LOCK-001", "unlock_time")},
		"Account lockout configured within policy limits",
	),
	lock_expected,
) if {
	checks["LOCK-001"].collector_status != "ERROR"
} else := wrap("LOCK-001", null, lock_expected)

# ---------------------------------------------------------------- UPD-001
upd_expected := "unattended-upgrades installed, Update-Package-Lists>=1, Unattended-Upgrade>=1, security origin allowed, apt-daily-upgrade.timer enabled"

upd_violations contains "unattended-upgrades package not installed" if {
	g("UPD-001", "package_installed") == false
}

upd_violations contains sprintf("APT::Periodic::Update-Package-Lists is %v", [g("UPD-001", "update_package_lists")]) if {
	is_number(g("UPD-001", "update_package_lists"))
	g("UPD-001", "update_package_lists") < 1
}

upd_violations contains sprintf("APT::Periodic::Unattended-Upgrade is %v", [g("UPD-001", "unattended_upgrade")]) if {
	is_number(g("UPD-001", "unattended_upgrade"))
	g("UPD-001", "unattended_upgrade") < 1
}

upd_violations contains "APT::Periodic::Enable is 0 (periodic APT jobs disabled)" if {
	g("UPD-001", "periodic_enable") == 0
}

upd_violations contains "no '-security' origin in Unattended-Upgrade allowed origins" if {
	params.updates_require_security_origin == true
	g("UPD-001", "package_installed") == true
	g("UPD-001", "security_origin") == false
}

upd_violations contains "apt-daily-upgrade.timer is not enabled" if {
	params.updates_require_timer == true
	g("UPD-001", "upgrade_timer_enabled") == false
}

upd_unknowns contains "package state unknown" if {
	g("UPD-001", "package_installed") == null
}

upd_unknowns contains "APT periodic settings unknown" if {
	not is_number(g("UPD-001", "unattended_upgrade"))
}

upd_unknowns contains "security origin unknown" if {
	params.updates_require_security_origin == true
	g("UPD-001", "security_origin") == null
}

upd_unknowns contains "apt-daily-upgrade.timer state unknown" if {
	params.updates_require_timer == true
	g("UPD-001", "upgrade_timer_enabled") == null
}

upd_001 := wrap(
	"UPD-001", decide(
		"UPD-001", upd_violations, upd_unknowns, upd_expected,
		{"package_installed": g("UPD-001", "package_installed"), "update_package_lists": g("UPD-001", "update_package_lists"), "unattended_upgrade": g("UPD-001", "unattended_upgrade"), "security_origin": g("UPD-001", "security_origin"), "upgrade_timer_enabled": g("UPD-001", "upgrade_timer_enabled")},
		"Automatic security updates are configured and scheduled",
	),
	upd_expected,
) if {
	checks["UPD-001"].collector_status != "ERROR"
} else := wrap("UPD-001", null, upd_expected)

# ---------------------------------------------------------------- output
results := {
	"SSH-001": ssh_001,
	"SSH-002": ssh_002,
	"FW-001": fw_001,
	"SVC-001": svc_001,
	"FILE-001": file_001,
	"PWD-001": pwd_001,
	"LOCK-001": lock_001,
	"UPD-001": upd_001,
}

summary := {s: n |
	some s in ["COMPLIANT", "NON_COMPLIANT", "UNKNOWN", "ERROR"]
	n := count([id | some id, r in results; r.status == s])
}
