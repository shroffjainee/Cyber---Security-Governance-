# CCM-RiskDrift: Phase-II Implementation

**Continuous Compliance Monitoring and Risk Drift Detection Framework for Proactive Cybersecurity Governance**
M.Tech (CSE – Cyber Security) Dissertation Phase-II, Jainee Kalpesh Shroff (2503032330026), PIET, Parul University.

**Base paper:** Z. Morić, M. Balković and D. Isić, "Evaluating the operational impact of automated endpoint compliance and security monitoring in Linux environments," *Journal of Cybersecurity and Privacy*, vol. 6, no. 1, 2026 (reference [13] in the Phase-I report).

---

## 1. Quick start on Windows

1. Install **Python 3.10 or newer** from python.org. During installation, tick **"Add Python to PATH"**.
2. Download or clone this repository.
3. Double-click **`run_windows.bat`**.
   - The first run installs the libraries and runs the experiment (about 2–3 minutes).
   - The dashboard then opens in the browser at `http://localhost:8501`.
4. Optional: double-click **`demo_real_mode.bat`**. It shows the real-scan pipeline using a saved OpenSCAP result. In the dashboard, choose **"This machine (real scans)"**.

Manual commands (same thing):

```
pip install -r requirements.txt
python run_experiment.py          # 30 runs -> results/ folder
streamlit run app.py              # dashboard
```

## 2. Real scans on an Ubuntu 22.04 VM

Use **Ubuntu 22.04**. The OpenSCAP content (`ssg-ubuntu2204-ds.xml`) is written for 22.04; on other versions most rules are reported as "not applicable".

```
bash setup_vm.sh                                   # installs OpenSCAP, SSG content, Trivy, Python libs
export CCM_PSEUDO_KEY='any-secret-phrase'          # used to pseudonymise the hostname
sudo -E .venv/bin/python collect_real.py --criticality 4 --exposure public --tls localhost:443
```

Every run counts as one scan period. Risk Drift appears from the second run onwards.

**Demonstrating real drift:** take scan 1, then make a change and take scan 2. For example:

```
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config   # weaken a control
sudo systemctl stop rsyslog                                                       # disable logging
sudo -E .venv/bin/python collect_real.py --criticality 4 --exposure public
```

The dashboard will show the risk rising and an alert opening. Revert the changes and scan again to watch the risk fall.

**Automatic weekly scan (cron):**

```
sudo crontab -e
0 9 * * 1  cd /path/to/ccm_riskdrift && CCM_PSEUDO_KEY='...' .venv/bin/python collect_real.py --criticality 4 --exposure public
```

Other vulnerability sources: `--openvas-csv report.csv` (Greenbone/OpenVAS CSV export) or `--vuln-csv file.csv` (columns `cve,cvss,epss,status`).

## 3. Project structure

```
ccm/
  catalog.py         controls: OpenSCAP rule IDs, config baselines, ISO 27001 / NIST CSF mapping
  collectors/
    openscap.py      runs `oscap xccdf eval`, parses XCCDF results            (base paper tool)
    drift.py         reads live Ubuntu settings, detects configuration drift   (incl. unmanaged drift)
    vulns.py         Trivy / OpenVAS / CSV import + EPSS enrichment (FIRST.org API)
    certs.py         TLS certificate controls                                  (certificate-authority checks)
  privacy.py         hostname pseudonymisation, IP/email scrubbing             (privacy and DLP)
  db.py              SQLite evidence store, time-indexed
  risk.py            risk score, Risk Drift(t), alert logic, baselines and ablations
  simulate.py        enterprise simulator with labelled ground truth
  metrics.py         precision / recall / F1, detection, NDCG@5, persistence
run_experiment.py    full experiment -> results/
collect_real.py      one real scan of this machine
app.py               Streamlit dashboard
config.json          all weights and thresholds
```

## 4. Method

For asset *a* at scan period *t*:

| Symbol | Meaning |
|---|---|
| C(a,t) | Compliance gap. Key-control failures, severity-weighted and saturating: 1 − exp(−k·Σw). Combined with a bounded "hygiene" share of all other failing rules. |
| D(a,t) | Configuration drift. Security settings deviating from the hardened baseline, including drift that no OpenSCAP rule checks (new listening ports, new sudo users, root cron jobs). |
| V(a,t) | Vulnerability exposure: 1 − Π(1 − (CVSS/10)·(0.2 + 0.8·EPSS)) over open vulnerabilities. |
| ctx(a) | Context: (0.3 + 0.7·criticality/5) × 1.3 if public × 1.15 if regulated. |

```
Risk(a,t)       = min(100, 100 · (0.35·C + 0.25·D + 0.40·V) · ctx(a))
Risk Drift(t)   = Risk(t) − Risk(t−1)            (Phase-I, Eq. 3.1)
Cumulative(t)   = Risk(t) − Risk(t−3)            (catches slow creep)
```

**Alert logic:** an alert opens when Risk Drift ≥ 5, Cumulative ≥ 7.5, or Risk ≥ 40. It stays open until the risk returns to within 2.5 points of its pre-alert level. A partial fix therefore shows as **improving-unresolved** and does not disappear early. This is the case in Table 3.4 of Phase-I.

**Compared methods:**

- **B0** – base paper style: OpenSCAP compliance score, alert on newly failed rules or a low score.
- **B1** – B0 plus a point-in-time CVSS ≥ 7 scanner.
- **P_no_context**, **P_no_temporal** – ablations of the proposed framework.
- **P_full** – the proposed framework.

All weights and thresholds were fixed in `config.json` before evaluation. The θ sensitivity analysis shows how results change if they are altered.

## 5. Results (30 runs × 20 assets × 16 weekly scans)

| Method | Precision | Recall | F1 | Critical events detected | NDCG@5 |
|---|---|---|---|---|---|
| B0 base paper (compliance only) | 0.574 | 0.529 | 0.544 | 71.1% | 0.513 |
| B1 compliance + CVSS scanner | 0.669 | 0.853 | 0.747 | 91.8% | 0.548 |
| P without context | 0.691 | 0.997 | 0.813 | 99.8% | 0.670 |
| P without temporal logic | 0.975 | 0.108 | 0.196 | 28.7% | 0.800 |
| **P_full (proposed)** | **0.727** | **0.902** | **0.802** | **100%** | **0.818** |

P_full against B0 and B1: every reported improvement is significant in paired Wilcoxon signed-rank tests (p < 0.01 for all 14 tests; p < 0.001 for 13 of them). Full tables, standard deviations and charts are in `results/`:

- `summary.md`, `summary_table.csv`, `significance_tests.csv`, `sensitivity_theta.csv`
- `fig_alert_quality.png`, `fig_detection_priority.png`, `fig_sensitivity_theta.png`, `fig_example_asset_timeline.png`

**Interpreting the ablation:**

- Removing the temporal logic gives very precise alerts but misses most events (recall 0.108). The drift component is what makes detection work.
- Removing context gives slightly higher F1 (0.813 vs 0.802), because it also alerts on low-value assets. But its ranking is much worse (NDCG 0.670 vs 0.818) and it raises more false alerts.
- Context is therefore a deliberate trade-off: slightly lower recall on unimportant systems in exchange for better precision and prioritisation.

## 6. Validation done

- **OpenSCAP:** a real CIS Level 1 Server scan was run with the parser. 223 rules were evaluated, 99 failed. The saved file is `data/samples/oscap-results-sample.xml.gz`. The test container was Ubuntu 24.04, so for that test it was made to identify as 22.04.
- **TLS checker:** tested against a local server using a self-signed, 1024-bit certificate expiring in 9 days. It correctly reported untrusted CA, weak key and expiring certificate.
- **Dashboard:** all 4 pages were tested for both data sources without errors.
- **Not tested here:** Trivy could not be downloaded in the test environment, so vulnerability import was tested through the CSV path. Trivy should work normally on the VM.

## 7. Limitations

1. **Simulation-based evaluation.** The detection and prioritisation metrics come from a scenario simulator with labelled ground truth, not from real incidents. Ground-truth labels use event severity and asset business value. Some of these factors overlap with the inputs of the proposed score, which is unavoidable when the literature itself defines risk this way.
2. **Real-mode test scope.** Real mode was validated on a single machine and a few scans, not a production enterprise.
3. **Fixed weights.** Weights are expert-set, not learned.
4. **Interpretive mapping.** The ISO 27001 / NIST CSF mapping is interpretive, as in Phase-I Table 3.1.
5. **Tool change.** OpenVAS (named in the Annexure-I proposal) is supported only through CSV import. Trivy is used as the lighter default.
