# Final acceptance checklist

Legend: ✅ verified by automated test/run in the build environment · 🟡 implemented, needs validation in
your lab environment.

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | All eight collectors exist | ✅ | `collector/*_checks.py`; `tests/test_collector.py` (fixture trees, fake runner) |
| 2 | All eight policies evaluated by OPA | ✅ | `policies/compliance.rego`; `tests/test_policies.py` (each check × 4 statuses), `opa test` 22/22 |
| 3 | Missing/failed evidence never compliant | ✅ | `test_missing_check_is_unknown_never_compliant`, `test_empty_evidence_is_not_compliant` |
| 4 | SQLite initialisation & persistence | ✅ | `tests/test_database.py::test_persistence_on_disk` |
| 5 | First assessment = baseline, not drift | ✅ | `test_first_assessment_is_baseline_not_drift` |
| 6 | Later assessments detect meaningful drift; no false drift from timestamps/order/whitespace | ✅ | `tests/test_drift.py` |
| 7 | Greenbone import of supported formats | ✅ synthetic / 🟡 real export | XML (modern + legacy) and CSV tests; validate with your own report |
| 8 | Duplicate, malformed, unsafe reports handled | ✅ | `tests/test_greenbone_importer.py` |
| 9 | Risk score handles missing/stale data honestly | ✅ | `test_no_scan_is_not_zero_risk`, `test_stale_scan_flagged`, `test_unknown_when_most_weight_missing` |
| 10 | Risk drift only between valid comparable scores | ✅ | `test_risk_drift_*`, `test_unknown_score_drift_not_computed` |
| 11 | Explanations reference stored evidence | ✅ | `evidence_ref` = `table:id`; resolvable on dashboard page 7; tested in scenarios 8 & 10 |
| 12 | Streamlit reads actual DB data (read-only) | ✅ | `tests/test_integration.py::test_dashboard_all_pages_render` (AppTest); not inspected visually in a browser |
| 13 | Automated tests run, reported truthfully | ✅ | 152 passed with OPA 1.4.2; OPA-dependent tests skip when OPA is absent |
| 14 | Installation & execution instructions | ✅ | README §2–4, docs/GREENBONE.md |
| 15 | Live collection on a full Ubuntu VM with sshd/ufw/systemd as root | ✅ lab container / 🟡 full VM | Real collection with sshd, UFW, PAM pwquality/faillock, unattended-upgrades as root in an Ubuntu 24.04 container (`lab/drift_experiment.sh`); systemd not PID 1 → SVC-001 uses /proc fallback. Repeat on a full VM |
| 16 | Baseline comparison (CVSS-only / compliance-only / proposed) | ✅ synthetic | `evaluation/baselines.py`, dashboard page 9 |
| 17 | Field evaluation tables | ✅ lab container | docs/EVALUATION.md §B filled from `lab-report` (3 trials, 24/24 detected, 0 false drift) and measured execution time |
| 18 | Continuous monitoring command | ✅ | `cli.py monitor`; `tests/test_lab_and_figures.py` |
| 19 | No false drift when collection method changes (root vs non-root) | ✅ | `test_collection_method_change_is_not_config_drift`; alternating root/non-root runs → 0 drift |
| 20 | Research-paper figures generated from stored data | ✅ | `cli.py figures`; `paper_figures/FIGURE_LIST.md` |

## Dissertation objective → module → test

| Objective | Module(s) | Tests / evidence |
|---|---|---|
| Collect Linux security evidence | `collector/` | test_collector.py |
| Evaluate compliance with OPA/Rego | `policies/`, `policy_engine/` | test_policies.py, compliance_test.rego |
| Detect configuration drift | `drift/`, `assessment/` | test_drift.py |
| Import Greenbone findings | `vulnerability/` | test_greenbone_importer.py |
| Explainable risk score | `risk/risk_score.py` | test_risk.py |
| Risk drift + explanations | `risk/risk_explanation.py` | test_risk.py, scenarios 2–10 |
| Historical storage | `storage/` | test_database.py |
| Dashboard | `app.py` | test_integration.py |
| Evaluation vs baselines | `evaluation/`, `risk/prioritization.py` | test_integration.py, results/ |
