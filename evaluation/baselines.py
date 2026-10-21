"""Baseline comparison on a SYNTHETIC multi-asset portfolio.

Builds six synthetic assets with deliberately different profiles, runs the
real pipeline for each (OPA, drift, Greenbone import, scoring) and ranks
them with CVSS-only, compliance-only and the proposed score.  It reports
rank tables, Kendall tau between methods, top-2 overlap and the weight
sensitivity of the proposed model.

This demonstrates *how the methods differ* on constructed cases.  It is not
evidence that one method is better in practice; that requires real assets
and an agreed ground truth (see docs/EVALUATION.md).
"""
from __future__ import annotations

import json
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

from assessment.pipeline import register_asset, store_evidence_assessment
from core.config import load_asset_policy, load_risk_model
from core.timeutil import iso
from evaluation import synthetic as syn
from evaluation.scenarios import RESULTS_DIR, t
from policy_engine.opa_runner import OPARunner
from risk.prioritization import kendall_tau, prioritization_table, top_k_overlap
from risk.risk_score import score_asset
from storage.database import Database
from vulnerability.greenbone_importer import import_report

CRIT = dict(syn.SAMPLE_FINDINGS[0])
MED = {"id": "m1", "name": "Apache HTTP Server outdated (synthetic)", "oid": "1.3.6.1.4.1.25623.1.0.900010",
       "port": "80/tcp", "severity": 6.1, "threat": "Medium", "cves": ["CVE-2024-0001"]}
LOW = dict(syn.SAMPLE_FINDINGS[2])

# asset_id, criticality, findings, {check: evidence changes} applied at day 1 (drift), changes present from day 0
PORTFOLIO = [
    ("syn-web-dmz", "Critical", [MED, LOW], {"SSH-002": {"password_authentication": "yes"}, "FW-001": {"active": False}}, {}),
    ("syn-db-core", "Critical", [CRIT, LOW], {}, {}),
    ("syn-dev-box", "Low", [CRIT, MED, LOW], {}, {"PWD-001": {"pwquality_enabled": False}}),
    ("syn-file-srv", "High", [LOW], {"FILE-001": "shadow_0644"}, {}),
    ("syn-jump-host", "High", [MED], {}, {"SSH-001": {"permit_root_login": "prohibit-password"},
                                          "LOCK-001": {"faillock_preauth": False, "faillock_authfail": False}}),
    ("syn-kiosk", "Medium", [LOW], {}, {}),
]


def _apply(doc: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    for cid, ch in changes.items():
        if ch == "shadow_0644":
            files = json.loads(json.dumps(doc["checks"]["FILE-001"]["evidence"]["files"]))
            files["/etc/shadow"].update(mode=0o644, mode_octal="0644")
            doc = syn.mutate(doc, "FILE-001", files=files)
        else:
            doc = syn.mutate(doc, cid, **ch)
    return doc


def build_portfolio(db: Database, workdir: Path, tf=t) -> None:
    """tf maps a day number to a datetime (fixed anchor for reproducible evaluation)."""
    cfg, model, runner = load_asset_policy(), load_risk_model(), OPARunner()
    for i, (aid, crit, findings, drift_changes, static_changes) in enumerate(PORTFOLIO):
        ip = f"10.99.0.{i + 1}"
        register_asset(db, {"asset_id": aid, "criticality": crit, "ip_address": ip}, "SYNTHETIC", iso(tf(-1)))
        path = workdir / f"{aid}.xml"
        path.write_text(syn.greenbone_xml(f"syn-{aid}", ip, iso(tf(0.9)), iso(tf(1)), findings))
        import_report(db, path, aid, "SYNTHETIC")
        day0 = _apply(syn.compliant_evidence(aid, iso(tf(0)), cfg["policy_params"]), static_changes)
        store_evidence_assessment(db, day0, runner)
        day1 = _apply(syn.with_time(day0, iso(tf(1))), drift_changes)
        store_evidence_assessment(db, day1, runner)
        score_asset(db, aid, model, now=tf(1) + timedelta(minutes=5))


def run_comparison(out_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    model = load_risk_model()
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(":memory:")
        db.init_schema()
        build_portfolio(db, Path(tmp))
        rows = prioritization_table(db)
        sens = {}
        for r in rows:
            s = db.query("SELECT components FROM risk_scores WHERE asset_id=? ORDER BY score_id DESC LIMIT 1",
                         (r["asset_id"],))
            sens[r["asset_id"]] = json.loads(s[0]["components"])["sensitivity"]
        db.close()
    ids = [r["asset_id"] for r in rows]
    rank = {k: [r[k] for r in rows] for k in ("rank_cvss_only", "rank_compliance_only", "rank_proposed")}
    sens_rank = {}
    for name in model["alternative_weight_sets"]:
        vals = sorted(ids, key=lambda a: -(sens[a][name] or -1))
        sens_rank[name] = {a: vals.index(a) + 1 for a in ids}
    result = {
        "table": rows,
        "kendall_tau": {
            "proposed_vs_cvss_only": kendall_tau(rank["rank_proposed"], rank["rank_cvss_only"]),
            "proposed_vs_compliance_only": kendall_tau(rank["rank_proposed"], rank["rank_compliance_only"]),
            "cvss_only_vs_compliance_only": kendall_tau(rank["rank_cvss_only"], rank["rank_compliance_only"]),
        },
        "top2_overlap": {
            "proposed_vs_cvss_only": top_k_overlap(rows, "rank_proposed", "rank_cvss_only", 2),
            "proposed_vs_compliance_only": top_k_overlap(rows, "rank_proposed", "rank_compliance_only", 2),
        },
        "sensitivity_scores": sens,
        "sensitivity_ranks": sens_rank,
        "sensitivity_tau_vs_default": {name: kendall_tau(rank["rank_proposed"], [sens_rank[name][a] for a in ids])
                                       for name in sens_rank},
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "baseline_comparison.json").write_text(json.dumps(result, indent=2, default=str))
    lines = ["| Asset | Criticality | Max CVSS | Non-compliant | Risk score | Rank CVSS-only | Rank compliance-only | Rank proposed |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r['asset_id']} | {r['criticality']} | {r['max_cvss']} | {r['non_compliant']} | {r['risk_score']} "
                     f"| {r['rank_cvss_only']} | {r['rank_compliance_only']} | {r['rank_proposed']} |")
    (out_dir / "baseline_comparison.md").write_text(
        "# Baseline comparison (SYNTHETIC portfolio — generated by `python cli.py evaluate-baselines`)\n\n"
        + "\n".join(lines) + "\n\nKendall tau: " + json.dumps(result["kendall_tau"]) +
        "\n\nTop-2 overlap: " + json.dumps(result["top2_overlap"]) +
        "\n\nSensitivity (tau of alternative weight sets vs default): " + json.dumps(result["sensitivity_tau_vs_default"]) +
        "\n\nThese assets were constructed to have different profiles; the table shows how the methods *differ*, "
        "not which is correct.\n")
    return result
