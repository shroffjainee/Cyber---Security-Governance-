# Evaluation methodology

## A. Pipeline correctness on synthetic scenarios (automated, reproducible)
`python cli.py evaluate-scenarios` runs 17 scenarios in isolated in-memory databases with real OPA.
Expected statuses, drift events and risk direction are declared before execution.

| # | Scenario | Expected |
|---|---|---|
| 1 | all checks compliant | 8 × COMPLIANT, BASELINE only |
| 2 | SSH root login violation | SSH-001 NON_COMPLIANT, NEW_NON_COMPLIANCE, risk ↑ |
| 3 | SSH password auth violation | SSH-002 NON_COMPLIANT, risk ↑ |
| 4 | firewall disabled | FW-001 NON_COMPLIANT, risk ↑ |
| 5 | /etc/shadow 0644 | FILE-001 NON_COMPLIANT, risk ↑ |
| 6 | prohibited service (telnet) | SVC-001 NON_COMPLIANT, risk ↑ |
| 7 | remediation | NEW_NON_COMPLIANCE then CORRECTED, risk ↓ |
| 8 | new imported vulnerability | risk ↑, explanation cites the finding |
| 9 | missing CVSS | NULL stored, label fallback flagged |
| 10 | criticality change | risk ↑, explanation cites criticality history |
| 11 | no meaningful change (timestamps/order/whitespace) | no drift, ΔR = 0 |
| 12 | missing evidence + collector failure | UNKNOWN / ERROR, MISSING_EVIDENCE, run PARTIAL, wider bounds |
| 13 | stale scan (60 days) | V stale, score PARTIAL |
| 14 | no scan | V NULL (not 0), bounds reflect V ∈ [0,100] |
| 15 | malformed / XXE report | rejected, nothing stored |
| 16 | database errors | duplicate refused, invalid row rolls back |
| 17 | OPA unavailable | run FAILED, no results, ASSESSMENT_FAILED |

Results measured in the build environment (`evaluation/results/metrics.json`): 17/17 scenarios passed;
check-level TP 5, FP 0, FN 0, TN 105; drift TP 10, FP 0, FN 0; risk direction 10/10; mean
store-and-evaluate time ≈ 0.14 s per assessment (dominated by the `opa eval` subprocess).
**Interpretation:** these numbers show the implementation behaves as designed on scenarios written by
the author. They are not field detection accuracy and must not be presented as such.

## B0. Measured lab results (REAL evidence — `lab/drift_experiment.sh` + `cli.py lab-report`)

Host: `lab-ubuntu-container` — Ubuntu 24.04 container with OpenSSH, UFW, libpam-pwquality, pam_faillock,
unattended-upgrades and vsftpd installed; assessed as root; systemd not PID 1 (SVC-001 reads running
services from `/proc`, enabled units from unit files). 3 trials × 12 assessments = 36 real runs.
Full run-by-run table: `evaluation/results/lab_experiment.md` (CSV + JSON alongside).

**Table B1 (measured) — Detection per control**

| Check | Injected change | Trials | TP | FN | FP | UNKNOWN |
|---|---|---|---|---|---|---|
| SSH-001 | PermitRootLogin yes (sshd_config.d drop-in) | 3 | 3 | 0 | 0 | 0 |
| FW-001 | `ufw disable` | 3 | 3 | 0 | 0 | 0 |
| SVC-001 | vsftpd started and enabled | 3 | 3 | 0 | 0 | 0 |
| FILE-001 | chmod 0644 /etc/shadow | 3 | 3 | 0 | 0 | 0 |
| SSH-002 | PasswordAuthentication yes | 3 | 3 | 0 | 0 | 0 |
| PWD-001 | pwquality minlen = 8 | 3 | 3 | 0 | 0 | 0 |
| LOCK-001 | pam_faillock lines removed | 3 | 3 | 0 | 0 | 0 |
| UPD-001 | APT::Periodic::Unattended-Upgrade "0" | 3 | 3 | 0 | 0 | 0 |

Precision 1.0, recall 1.0 on this experiment (24 injected changes).

**Table B2 (measured) — Drift detection**: 36 assessments, 24 known changes → 24 detected, 0 missed,
0 false drift events; 6 no-change runs (R2, R12 of each trial) produced 0 drift events; all 24
remediations were reported as CORRECTED. Alternating root / non-root collection of the same
configuration produced 0 drift events.

**Table B3 (measured) — Execution time** (n = 10 each, same container, SQLite on local disk)

| Mode | Mean (s) | Std (s) | Max (s) |
|---|---|---|---|
| root, collect + OPA evaluate + store + drift + score (`cli.py assess`) | 0.58 | 0.04 | 0.65 |
| non-root, same pipeline (fallback to config files) | 0.57 | 0.04 | 0.66 |
| Greenbone XML import (2.4 KB synthetic report, `--no-score`) | 0.09 | 0.01 | 0.10 |

**Table B4 (measured, trial 3) — Risk-score changes**

| Event | R before | R after | ΔR | Band after |
|---|---|---|---|---|
| PermitRootLogin yes | 13.64 | 35.51 | +21.87 | Medium |
| UFW disabled | 35.51 | 57.39 | +21.88 | High |
| vsftpd running | 57.39 | 69.06 | +11.67 | High |
| /etc/shadow 0644 | 69.06 | 75.66 | +6.60 | Critical |
| SSH password auth | 75.66 | 82.26 | +6.60 | Critical |
| minlen 8 | 82.26 | 85.92 | +3.66 | Critical |
| faillock removed | 85.92 | 89.59 | +3.67 | Critical |
| auto-updates off | 89.59 | 95.45 | +5.86 | Critical |
| remediation | 95.45 | 13.64 | −81.81 | Low |

Scores are PARTIAL (V unavailable: no Greenbone scan of the lab host; weights renormalised over C, D, A).
The explanation page cites the matching `check_results` and `config_drift_events` records for every
increase (see Fig. 11).

**Threats to validity of B0:** single host, container rather than VM, changes chosen by the author,
no vulnerability component. Repeat on a full VM with a real Greenbone scan for the final report.

## B. Field evaluation on your lab VM (protocol — repeat on a full VM)
Use only an isolated, disposable VM snapshot. Never weaken a production system.

Procedure per case: take VM snapshot → apply the change (e.g. `PermitRootLogin yes` + reload) →
`sudo -E python cli.py assess` → record results → revert snapshot (or remediate) → assess again.
Repeat each case ≥ 3 times; record ground truth independently (e.g. `sshd -T`, `ufw status verbose`,
`stat`, manual PAM review).

**Table B1 — Detection** (TP: violation present & reported NON_COMPLIANT; FN: present but
COMPLIANT/UNKNOWN; FP: absent but NON_COMPLIANT; record UNKNOWN separately)

| Check | Injected change | Trials | TP | FN | FP | TN | UNKNOWN | Notes |
|---|---|---|---|---|---|---|---|---|
| SSH-001 | PermitRootLogin yes | | | | | | | |
| SSH-002 | PasswordAuthentication yes in sshd_config.d | | | | | | | |
| FW-001 | `ufw disable` | | | | | | | |
| SVC-001 | install & enable vsftpd | | | | | | | |
| FILE-001 | chmod 0644 /etc/shadow (snapshot!) | | | | | | | |
| PWD-001 | minlen=8 | | | | | | | |
| LOCK-001 | remove faillock lines (second root session open!) | | | | | | | |
| UPD-001 | disable apt-daily-upgrade.timer | | | | | | | |

Precision = TP/(TP+FP); recall = TP/(TP+FN); report UNKNOWN rate = UNKNOWN/trials. Also run every case
without root to measure how many results degrade to UNKNOWN.

**Table B2 — Drift detection**: for N consecutive assessments with K known changes, count detected,
missed, and false drift events (e.g. after reboots/package updates with no config change).

| Period | Assessments | Known changes | Detected | Missed | False events |
|---|---|---|---|---|---|

**Table B3 — Execution time** (`time sudo -E python cli.py assess ...`, n ≥ 10)

| Mode | Mean (s) | Std (s) | Max (s) |
|---|---|---|---|
| root, collect+evaluate+store+score | | | |
| non-root | | | |
| Greenbone import (report size …) | | | |

**Table B4 — Risk-score changes**: for each injected event record R before/after, ΔR, component
deltas, and whether the explanation referenced the right evidence.

| Event | R before | R after | ΔR | Largest component Δ | Explanation correct? |
|---|---|---|---|---|---|

## C. Baseline comparison
`python cli.py evaluate-baselines` ranks a constructed synthetic portfolio by CVSS-only,
compliance-only and the proposed score, reporting Kendall τ, top-2 overlap and weight sensitivity
(`evaluation/results/baseline_comparison.md`). On the synthetic portfolio, measured τ was 0.533
(proposed vs CVSS-only) and 0.267 (proposed vs compliance-only): the methods order assets differently.
That alone does not show which ordering is better. To argue usefulness you need a ground truth, e.g.
rankings by independent security practitioners over real lab assets, then compare each method's
agreement with that ranking (τ or top-k precision) — record such data in a table like:

| Asset | Expert rank (median) | CVSS-only rank | Compliance-only rank | Proposed rank |
|---|---|---|---|---|

Threats to validity: synthetic scenarios written by the author; single OS family; uncalibrated weights;
Greenbone results depend on feed version and credentials; small asset counts make τ unstable.
