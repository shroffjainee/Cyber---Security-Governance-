# Continuous Compliance Monitoring and Risk Drift Detection Framework for Proactive Cybersecurity Governance

M.Tech Cyber Security dissertation project. A local, zero-cost framework that:

1. collects Linux (Ubuntu) security-configuration evidence, read-only;
2. evaluates eight controls with **Open Policy Agent / Rego**;
3. stores every assessment in **SQLite** and detects **configuration drift** between snapshots;
4. imports **Greenbone Community Edition / OpenVAS** reports (XML or CSV);
5. computes an **explainable 0–100 risk-priority score** `R = 0.45V + 0.25C + 0.20D + 0.10A`;
6. detects and explains **risk drift** `ΔR = R_t − R_(t−1)`;
7. shows real stored results and trends in a **Streamlit** dashboard.

```
Ubuntu asset ─► collector/ (read-only, 8 checks) ─► normalized JSON evidence (schema-validated)
   ─► policy_engine/ → `opa eval` → policies/compliance.rego ─► storage/ SQLite (run + snapshot + results)
   ─► drift/ (configuration drift) ─► vulnerability/ (Greenbone import) ─► risk/ (score, risk drift,
   explanations) ─► app.py (Streamlit, read-only DB connection)
```

> **Honesty rules built into the code:** missing or failed evidence is never COMPLIANT; a missing
> vulnerability scan never becomes "zero risk"; stale data is flagged; synthetic data is labelled
> `SYNTHETIC` everywhere; risk drift is only computed between comparable scores; explanations say
> "observed alongside", never "caused by". The score is a prioritisation aid, **not** a validated
> probability of exploitation or loss.

---

## 1. Requirements

| Component | Minimum | Notes |
|---|---|---|
| Assessed asset | Ubuntu 22.04 / 24.04 VM, 1 vCPU, 1 GB RAM | Only read access needed; `sudo` gives authoritative SSH/UFW evidence |
| Framework host (can be the same VM) | Python 3.10+, 2 GB RAM, 1 GB disk | Tested here on Python 3.13 |
| OPA | single static binary (~70 MB) | v0.60+ or v1.x; tested with **v1.4.2** |
| Greenbone Community Edition | separate VM recommended | Greenbone's community docs list roughly **2 CPU / 4 GB RAM / 20 GB disk minimum, 4 CPU / 8 GB RAM / 60 GB recommended** — verify against the current docs; the feed sync alone takes a long time on first start |

A practical laptop lab: 16 GB RAM host running two VMs — `greenbone-vm` (4 vCPU, 8 GB) and the
`ubuntu-vm-01` target (2 vCPU, 2 GB) on a host-only network (e.g. 192.168.56.0/24).

## 2. Installation (Ubuntu)

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip unzip
unzip risk_drift_framework.zip && cd risk_drift_framework
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### Install OPA (documented static binary release)

```bash
curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v1.4.2/opa_linux_amd64_static
chmod 755 opa && sudo mv opa /usr/local/bin/opa
opa version
opa check --strict policies/ && opa test policies/ -v      # 22 Rego unit tests
```
Alternatively put the binary at `./bin/opa` or set `RDF_OPA_PATH=/path/to/opa`.

## 3. Configure

* `config/asset_policy.json` — your asset(s) (`asset_id`, `hostname`, `ip_address`, `criticality`
  Low/Medium/High/Critical) and the **policy parameters** (allowed `PermitRootLogin` values, service
  denylist, file baseline, password length/classes/ageing, lockout limits, update requirements).
  Set `ip_address` to the address Greenbone scans — imported findings for other hosts are not
  attributed to the asset.
* `config/risk_model.json` — weights, normalisation constants, thresholds, model version
  (see [docs/RISK_MODEL.md](docs/RISK_MODEL.md)).

## 4. Run

```bash
python cli.py init-db                                 # creates data/rdf.sqlite3, registers assets
sudo -E .venv/bin/python cli.py assess --asset-id ubuntu-vm-01   # collect → OPA → store → drift → score
python cli.py import-greenbone --asset-id ubuntu-vm-01 --file ~/report-ubuntu.xml   # then re-scores
python cli.py score --asset-id ubuntu-vm-01           # recompute score + risk drift
python cli.py set-criticality --asset-id ubuntu-vm-01 --level Critical
streamlit run app.py                                  # http://localhost:8501
```

### Web console (same design as a GitHub Pages site)

```bash
python cli.py build-site                      # data/rdf.sqlite3 → docs/index.html
python cli.py --db data/demo_synthetic.sqlite3 build-site   # SYNTHETIC demo console
```
`docs/index.html` is one self-contained file (no server, no internet needed): Mission Control,
Compliance Monitoring, Configuration Drift, Vulnerability Intake, Risk Prioritisation, Risk Drift,
Explanations, Scenario Evaluation, Baseline Comparison, History & Data Quality — dark/light theme,
mobile layout. Edit `config/project_meta.json` (name, enrolment, guide) before building.

**Publish it free with GitHub Pages:** push the project to GitHub → repository *Settings → Pages* →
*Source: Deploy from a branch* → branch `main`, folder `/docs` → Save. After a minute the console is live at
`https://<username>.github.io/<repo>/`. Re-run `build-site` and push again whenever you want to refresh it.
Publish only SYNTHETIC demo data or data you are allowed to share — a real host database reveals that host's
security configuration.

The Streamlit app (`streamlit run app.py`) uses the same colour theme (`.streamlit/config.toml`).

Other commands:

| Command | Purpose |
|---|---|
| `python cli.py collect --asset-id ID --out evidence.json` | Collect evidence only (inspect it before storing) |
| `python cli.py evaluate --evidence evidence.json` | Evaluate an evidence file with OPA, print statuses |
| `python cli.py assess --asset-id ID --evidence evidence.json` | Store a previously collected evidence file |
| `python cli.py demo` | Build the **SYNTHETIC** demo DB `data/demo_synthetic.sqlite3`; view with `RDF_DB=data/demo_synthetic.sqlite3 streamlit run app.py` |
| `python cli.py evaluate-scenarios` | Run the 17 reproducible evaluation scenarios → `evaluation/results/` |
| `python cli.py evaluate-baselines` | CVSS-only vs compliance-only vs proposed on a synthetic portfolio |
| `python cli.py monitor --asset-id ID --interval 3600` | **Continuous monitoring**: re-assess every N seconds until Ctrl+C (`--count N` to stop after N cycles) |
| `sudo TRIALS=3 bash lab/drift_experiment.sh all` | **Controlled drift experiment on a lab host** (REAL evidence): harden → 8 injected misconfigurations → remediation, assessed after every step |
| `python cli.py --db data/real_lab.sqlite3 lab-report` | Compare the experiment runs with the known ground truth → `evaluation/results/lab_experiment.md` |
| `python cli.py figures` | Generate the research-paper figures (PNG) → `figures/` |

Continuous monitoring: schedule the assessment, e.g. root's crontab
`0 */6 * * * cd /opt/risk_drift_framework && .venv/bin/python cli.py assess --asset-id ubuntu-vm-01 >> data/assess.log 2>&1`.

Running without root works, but `sshd -T` and `ufw status` are unavailable: the collector falls back to
configuration files, records a limitation, and anything it cannot establish becomes UNKNOWN.

## 5. The eight checks

| ID | Control | Primary evidence | Fallback | Default expectation |
|---|---|---|---|---|
| SSH-001 | Root login disabled | `sshd -T` | sshd_config + `Include` (first value wins), OpenSSH defaults, Match blocks reported | `PermitRootLogin no` |
| SSH-002 | Password auth disabled | `sshd -T` | as above (catches `50-cloud-init.conf`) | `PasswordAuthentication no`, `KbdInteractiveAuthentication no` |
| FW-001 | UFW active, default-deny | `ufw status verbose` | ufw.conf + /etc/default/ufw + `systemctl is-active ufw` | active; incoming deny/reject |
| SVC-001 | No prohibited services | `systemctl list-units` / `list-unit-files` (services+sockets) | — | none in denylist (optional allowlist mode) |
| FILE-001 | passwd/shadow/group/gshadow | `os.stat` metadata only | — | owner root; group in baseline; mode ≤ 0644 / 0640 |
| PWD-001 | Password quality & ageing | pam.d/common-password, pwquality.conf(.d), login.defs | libpwquality defaults | pwquality on, minlen ≥ 14, classes ≥ 3, max days ≤ 365, min days ≥ 1 |
| LOCK-001 | Account lockout | pam.d/common-auth, common-account, faillock.conf | pam_faillock defaults | preauth+authfail+account, deny 1–5, unlock 0 or ≥ 900 s |
| UPD-001 | Automatic security updates | `dpkg-query`, `apt-config dump`, timers | apt.conf.d parsing | installed, periodic ≥ 1, `-security` origin, timer enabled |

Purpose, remediation text and severities live in `core/catalog.py`; full details and limitations in
[docs/CHECKS.md](docs/CHECKS.md). Statuses: **COMPLIANT, NON_COMPLIANT, UNKNOWN** (evidence missing or
inconclusive), **ERROR** (collector failed). A stock Ubuntu install is normally NON_COMPLIANT on
PWD-001, LOCK-001 and often UPD-001/FW-001 — that is expected.

## 6. Greenbone / OpenVAS

See [docs/GREENBONE.md](docs/GREENBONE.md): installation (Greenbone Community Containers), creating an
**authorized** scan of your own lab VM, exporting the report as **XML** (preferred) or **CSV Results**,
and importing. The importer never starts scans and never calls an API; it parses exported files with
`defusedxml`, de-duplicates by (NVT OID, host, port), keeps missing CVSS as NULL, marks false positives,
refuses duplicate files/report ids, and rejects malformed or unsafe XML.

## 7. Tests

```bash
pytest -q                     # 152 tests; OPA-dependent ones are skipped if opa is missing
opa test policies/ -v         # Rego unit tests
python cli.py evaluate-scenarios
```

Suites: `test_collector.py` (fixture filesystems + fake command runner, no host changes),
`test_policies.py` (real `opa eval`, every check × all four statuses), `test_drift.py`, `test_risk.py`,
`test_database.py`, `test_greenbone_importer.py`, `test_integration.py` (scenarios, CLI, every dashboard
page via Streamlit `AppTest`).

## 8. Project layout

```
app.py                     Streamlit dashboard (9 pages, read-only DB connection)
cli.py                     command-line interface
config/                    asset_policy.json, risk_model.json
core/                      config loading/validation, check catalogue, time helpers
collector/                 common.py (safe subprocess, parsers, secret guard) + 7 check modules,
                           evidence_schema.json, collect_evidence()
policies/                  compliance.rego (+ compliance_test.rego)
policy_engine/opa_runner.py  `opa eval` integration
assessment/pipeline.py     evidence → OPA → SQLite → drift (→ score)
drift/drift_detector.py    normalization, drift classification
vulnerability/greenbone_importer.py
risk/                      risk_score.py, risk_explanation.py (risk drift), prioritization.py
storage/                   schema.sql, database.py
evaluation/                synthetic.py (fixtures), scenarios.py, baselines.py, demo.py, results/
sample_data/               synthetic/ fixtures + real collections (build sandbox, hardened lab container)
lab/drift_experiment.sh    controlled drift experiment on an authorised lab host (REAL evidence)
figures/, paper_figures/   generated paper figures + numbered figure set with captions
screenshots/               dashboard and terminal screenshots
docs/                      CHECKS, RISK_MODEL, GREENBONE, EVALUATION, ACCEPTANCE_CHECKLIST
tests/
```

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `OPA binary not found` and run FAILED | Install OPA (§2) or `export RDF_OPA_PATH=...`. Runs are stored as FAILED, never as compliant. |
| SSH checks say "Effective config not verified" | Run the assessment with `sudo -E`; `sshd -T` needs root to load host keys. |
| FW-001 PARTIAL / config_files | `ufw status` needs root; the fallback reads configuration, not live rules. |
| SVC-001 UNKNOWN in a container | systemd is not PID 1 (`System has not been booted with systemd`); assess a real VM. |
| `Import failed: ... already imported` | Same file hash or same Greenbone report id — by design. Export a new report after a new scan. |
| `CSV is not a Greenbone 'CSV Results' export` | Choose the "CSV Results" report format, or prefer XML. |
| Findings skipped "for other hosts" | Set the asset's `ip_address`/`hostname` to the scanned address, or use `--no-host-filter`. |
| Score PARTIAL with wide bounds | A component is missing or stale (no/old scan, undetermined checks) — see warnings. |
| Risk drift NOT_COMPARABLE / new BASELINE | Model version, weights or available components changed; deltas are only computed between comparable scores. |
| Dashboard empty | Point it at the right DB (`RDF_DB=...` or the sidebar field). |
| `database is locked` | Another writer is running (cron + manual). SQLite waits 10 s; retry. |

## 10. Verification status (what was actually run)

Verified in an Ubuntu 24.04 environment (Python 3.13, OPA 1.4.2, Streamlit 1.5x):
* `pytest`: **152 passed** with OPA (91 passed / 61 skipped without OPA). `opa check --strict` and `opa test policies/`: 22/22.
* 17/17 evaluation scenarios pass (SYNTHETIC evidence, real OPA, real pipeline).
* **Controlled lab drift experiment — REAL evidence** (`lab/drift_experiment.sh`, 3 trials × 12
  assessments on `lab-ubuntu-container`, an Ubuntu 24.04 container with OpenSSH, UFW, libpam-pwquality,
  pam_faillock and unattended-upgrades installed): all eight controls were hardened to COMPLIANT, then
  each was broken in turn and finally remediated. Result (`evaluation/results/lab_experiment.md`):
  **24/24 injected changes detected, 0 false drift events, 0 drift in no-change runs, 24/24
  remediations recognised**; risk rose 13.6 → 95.5 and fell by 81.8 after remediation.
* Root and non-root collections of the same configuration produce no false drift (collection method is
  stored but excluded from drift comparison).
* All nine dashboard pages render without exceptions (Streamlit AppTest + real browser screenshots in
  `screenshots/`).

**Still requires your environment:** a full Ubuntu VM with systemd as PID 1 (in the container,
SVC-001 reads running services from `/proc` because systemd is not PID 1); a **real Greenbone scan**
export (the importer is tested only against synthetic files shaped like Greenbone XML/CSV, so V is
missing for the real lab data and those scores are PARTIAL); multi-week continuous monitoring.

### Which parts use real data and which use synthetic data

| Part | Data | Where |
|---|---|---|
| Evidence collection (8 checks), OPA evaluation, SQLite history | **REAL** (lab host) | `data/real_lab.sqlite3`, `sample_data/host_evidence_lab_container_hardened.json` |
| Configuration drift, risk score (C, D, A), risk drift ΔR, explanations | **REAL** (lab host) | same; `evaluation/results/lab_experiment.*` |
| Vulnerability component V / Greenbone import | SYNTHETIC report files | `sample_data/synthetic/greenbone_*` |
| 17 evaluation scenarios | SYNTHETIC evidence through the real pipeline | `evaluation/results/scenario_results.csv` |
| Baseline comparison (CVSS-only vs compliance-only vs proposed) | SYNTHETIC 6-asset portfolio | `evaluation/results/baseline_comparison.*` |
| Dashboard showcase DB | both, every row labelled HOST / SYNTHETIC | `data/showcase.sqlite3` |

Do not report any experimental result in the dissertation that you have not reproduced yourself.
See [docs/ACCEPTANCE_CHECKLIST.md](docs/ACCEPTANCE_CHECKLIST.md), [docs/EVALUATION.md](docs/EVALUATION.md)
and `paper_figures/FIGURE_LIST.md`.
