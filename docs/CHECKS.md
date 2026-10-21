# The eight security checks

Common rules
* Collection (Python, `collector/`) and evaluation (Rego, `policies/compliance.rego`) are separate.
  Collectors only gather normalized facts; all pass/fail logic is in Rego.
* Every check emits `{check_id, title, collected_at, collector_status (OK|PARTIAL|ERROR), evidence,
  sources, errors, limitations}`.
* Rego decision order: check missing → UNKNOWN; collector ERROR → ERROR; any violation →
  NON_COMPLIANT; any required value null → UNKNOWN; else COMPLIANT. A missing evidence *field* is read
  as `null` (helper `g()`), never "undefined", so it cannot silently pass.
* Commands run via `subprocess.run([...], shell=False, timeout, env LC_ALL=C)`; files are read with a
  1 MB cap. `assert_no_secrets` rejects crypt hashes, PEM private keys and forbidden keys before storage.
  `/etc/shadow` is only `stat`-ed, never read.

## SSH-001 — SSH root login disabled
*Purpose:* force named accounts and auditable privilege escalation.
*Evidence:* `sshd -T` (authoritative, needs root). Fallback parser follows `Include` globs in order
(relative paths resolve under /etc/ssh, loop/depth guarded); for these keywords sshd keeps the **first**
value read; unset → OpenSSH default `prohibit-password`. Directives inside `Match` blocks are reported in
`match_overrides` (`value@file`).
*Normalized output:* `sshd_installed, method, config_files, permit_root_login, value_origin, match_overrides`.
*Expected:* value ∈ `ssh_allowed_permit_root_login` (default `["no"]`), no Match override allowing root.
*openssh-server absent:* COMPLIANT if `ssh_absent_is_compliant` (no exposure, positively verified via
dpkg/binary), else UNKNOWN. Unknown install state + no config → ERROR.
*Limitations:* Match criteria are not evaluated by the fallback parser; `sshd -T` without `-C` shows the
global configuration.
*Remediation:* `PermitRootLogin no`, `sudo sshd -t && sudo systemctl reload ssh`.

## SSH-002 — Password authentication
Same evidence path. `KbdInteractiveAuthentication` (alias `ChallengeResponseAuthentication`) is also
required to be `no` because with PAM it can still accept passwords. Policy switch
`ssh_password_authentication_allowed: true` documents an exception. Ubuntu cloud images ship
`/etc/ssh/sshd_config.d/50-cloud-init.conf` with `PasswordAuthentication yes`, which wins because it is
included before the main-file setting — the parser reproduces this.

## FW-001 — UFW active with default-deny inbound
Runtime: `ufw status verbose` (Status / Default lines, rule table). Fallback (non-root): `ENABLED` in
`/etc/ufw/ufw.conf`, `DEFAULT_INPUT_POLICY` in `/etc/default/ufw` (DROP→deny, REJECT→reject,
ACCEPT→allow) and `systemctl is-active ufw`; flagged as configured-not-runtime. UFW not installed →
NON_COMPLIANT ("no supported host firewall"). Hosts using raw nftables or a perimeter firewall must be
handled as a documented policy exception (limitation).

## SVC-001 — Prohibited services
Running/listening and enabled **service and socket** units (suffix stripped, so `cups.socket` → `cups`).
NON_COMPLIANT if any name is in `services_denylist`; with `services_allowlist_mode` any running unit not
in `services_allowlist` also fails. If either list cannot be obtained (no systemd) → UNKNOWN unless a
prohibited unit was already seen. Processes started outside systemd are not detected.

## FILE-001 — Account database files
`os.stat` (no content read) of /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow and any path in
`file_baseline`. Baseline (Ubuntu defaults): passwd/group `root:root 0644`; shadow/gshadow
`root:shadow 0640` (root:root also accepted). A mode is a violation if it has any bit outside `max_mode`
(`bits.and(mode, 0o7777 - max) != 0`), so stricter modes (0600) pass. Unresolvable owner/group →
UNKNOWN; missing file → NON_COMPLIANT.

## PWD-001 — Password quality and ageing
Effective pwquality values: libpwquality defaults (minlen 8, minclass 0, credits 0) → pwquality.conf
→ pwquality.conf.d/*.conf → module arguments in common-password (highest). `pam_cracklib` recognised.
Effective classes = max(minclass, number of negative credits). Ageing from /etc/login.defs; note it
applies to accounts created afterwards (use `chage -l` for existing accounts — limitation).

## LOCK-001 — Account lockout (pam_faillock)
Requires `pam_faillock.so preauth` and `authfail` in common-auth and `pam_faillock.so` in
common-account. Values: defaults (deny 3, unlock_time 600, fail_interval 900) → faillock.conf → module
arguments. Policy: 1 ≤ deny ≤ `lockout_max_deny`; `unlock_time` 0 (admin unlock) or ≥
`lockout_min_unlock_time`. Ubuntu does not enable faillock by default. Only the common-* stacks are
inspected (service-specific PAM files may differ — limitation). **Test lockout changes in a second root
session before logging out.**

## UPD-001 — Automatic security updates
`dpkg-query` for unattended-upgrades; `apt-config dump` (APT's merged view) or, failing that, parsing
apt.conf.d files in lexical order (later scalars win, comments stripped); allowed origins/origin
patterns must include a `-security` pocket; `apt-daily-upgrade.timer` enabled (and `apt-daily.timer`
recorded). `APT::Periodic::Enable "0"` is a violation.

## Effective-configuration limitations (summary)
1. Without root, SSH and UFW results come from configuration files, not the running daemons.
2. sshd Match blocks are reported, not evaluated.
3. PAM: only common-auth/account/password are read; `@include` chains into other files are not followed.
4. login.defs ageing ≠ ageing of existing accounts.
5. Only UFW is supported as the firewall tool.
