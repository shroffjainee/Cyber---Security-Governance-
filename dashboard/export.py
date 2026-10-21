"""Export the SQLite records (and evaluation results) into one JSON document
for the static web console (dashboard/console_template.html).

Only stored records are exported — nothing is computed or invented here
except simple counts/aggregations of those records.
"""
from __future__ import annotations

import csv
import json
import platform
import sys
from pathlib import Path
from typing import Any

from core.catalog import CHECKS
from core.config import CONFIG_DIR, PROJECT_ROOT, load_risk_model
from core.timeutil import utc_now_iso
from risk.prioritization import kendall_tau, prioritization_table
from storage.database import Database

RESULTS = PROJECT_ROOT / "evaluation" / "results"
MAX_TEXT = 600


def _clip(v: Any, n: int = MAX_TEXT) -> Any:
    return v[:n] + "…" if isinstance(v, str) and len(v) > n else v


def _load_meta() -> dict[str, Any]:
    p = CONFIG_DIR / "project_meta.json"
    meta = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    meta.pop("_comment", None)
    return meta


def _evaluation() -> dict[str, Any] | None:
    mfile = RESULTS / "metrics.json"
    if not mfile.exists():
        return None
    out: dict[str, Any] = {"metrics": json.loads(mfile.read_text())}
    sfile = RESULTS / "scenario_results.csv"
    if sfile.exists():
        rows = []
        with sfile.open() as fh:
            for r in csv.DictReader(fh):
                rows.append({"name": r["scenario"], "passed": r["passed"] == "True",
                             "exp": r["expected_direction"] or None, "obs": r["observed_direction"] or None,
                             "scores": r["risk_scores"], "ms": r["mean_eval_ms"],
                             "failed": r["failed_checks"] not in ("[]", "")})
        out["scenarios"] = rows
    bfile = RESULTS / "baseline_comparison.json"
    if bfile.exists():
        b = json.loads(bfile.read_text())
        out["baseline"] = {"table": b["table"], "tau": b["kendall_tau"], "top2": b["top2_overlap"],
                           "sens_tau": b["sensitivity_tau_vs_default"]}
    return out


def export(db: Database) -> dict[str, Any]:
    model = load_risk_model()
    assets_out = []
    for a in db.list_assets():
        aid = a["asset_id"]
        runs = db.query("SELECT run_id, started_at, status, policy_version, opa_version, collector_version, data_origin,"
                        " error_message FROM assessment_runs WHERE asset_id=? ORDER BY run_id", (aid,))
        latest = db.latest_successful_run(aid)
        checks = []
        if latest:
            res = db.check_results(latest["run_id"])
            for cid, r in sorted(res.items(), key=lambda kv: list(CHECKS).index(kv[0]) if kv[0] in CHECKS else 99):
                ev = r["evidence"] or {}
                checks.append({"id": cid, "title": r["title"], "status": r["status"], "collector": r["collector_status"],
                               "expected": _clip(r["expected"]), "actual": r["actual"], "reason": _clip(r["reason"]),
                               "remediation": r["remediation"], "purpose": CHECKS.get(cid, {}).get("purpose"),
                               "sources": ev.get("sources") or [], "errors": ev.get("errors") or [],
                               "limitations": ev.get("limitations") or [], "evidence": ev.get("evidence") or {},
                               "rid": r["result_id"]})
        history = {}
        for row in db.query("SELECT r.run_id, r.check_id, r.status FROM check_results r WHERE r.asset_id=? ORDER BY r.run_id",
                            (aid,)):
            history.setdefault(row["check_id"], []).append([row["run_id"], row["status"]])
        drift = [{k: e[k] for k in ("drift_id", "run_id", "previous_run_id", "check_id", "category", "priority",
                                     "previous_status", "current_status", "explanation", "detected_at")}
                 | {"prev": _clip(e["previous_value"], 300), "cur": _clip(e["current_value"], 300)}
                 for e in db.drift_events(aid)]
        scans = []
        for s in db.query("SELECT * FROM vulnerability_scans WHERE asset_id=? ORDER BY scan_id", (aid,)):
            f = db.findings_for_scan(s["scan_id"])
            scans.append({k: s[k] for k in ("scan_id", "source_file", "report_format", "source_report_id", "scan_started_at",
                                            "scan_ended_at", "imported_at", "finding_count", "duplicate_count",
                                            "skipped_count", "data_origin")}
                         | {"findings": [{k: x[k] for k in ("finding_id", "name", "host", "port", "cvss_score",
                                                            "severity_label", "qod", "cves", "nvt_oid", "status")}
                                         | {"solution": _clip(x["solution"], 300)} for x in f]})
        scores = []
        for sid in [r["score_id"] for r in db.query("SELECT score_id FROM risk_scores WHERE asset_id=? ORDER BY score_id", (aid,))]:
            s = db.get_score(sid)
            rd = db.query("SELECT * FROM risk_drift_events WHERE score_id=?", (sid,))
            rd = rd[0] if rd else None
            expl = db.query("SELECT kind, component, factor, detail, evidence_ref FROM risk_explanations WHERE score_id=?"
                            " ORDER BY explanation_id", (sid,))
            scores.append({
                "id": sid, "t": s["calculated_at"], "score": s["score"], "lo": s["score_lower"], "hi": s["score_upper"],
                "band": s["band"], "status": s["status"], "V": s["v_score"], "C": s["c_score"], "D": s["d_score"],
                "A": s["a_score"], "avail": s["available_components"], "warn": s["warnings"], "crit": s["criticality"],
                "model": s["model_version"], "sens": (s["components"] or {}).get("sensitivity"),
                "vstale": bool((s["components"] or {}).get("V", {}).get("stale")),
                "drift": None if not rd else {"dir": rd["direction"], "delta": rd["delta"], "sig": bool(rd["significant"]),
                                              "prev": rd["previous_score"],
                                              "cd": json.loads(rd["component_deltas"]) if rd["component_deltas"] else None},
                "expl": [{k: _clip(v, 400) for k, v in e.items()} for e in expl]})
        assets_out.append({
            "id": aid, "host": a["hostname"], "ip": a["ip_address"], "crit": a["criticality"], "origin": a["data_origin"],
            "desc": a["description"], "crit_hist": [[h["changed_at"], h["criticality"]] for h in db.criticality_history(aid)],
            "runs": runs, "checks": checks, "check_hist": history, "drift": drift, "scans": scans, "scores": scores})
    prio = prioritization_table(db)
    tau = None
    if len(prio) >= 2:
        tau = {"cvss": kendall_tau([r["rank_proposed"] for r in prio], [r["rank_cvss_only"] for r in prio]),
               "comp": kendall_tau([r["rank_proposed"] for r in prio], [r["rank_compliance_only"] for r in prio])}
    return {
        "meta": _load_meta() | {"built": utc_now_iso(), "python": platform.python_version(), "system": platform.system(),
                                "db": Path(db.path).name},
        "model": {"version": model["model_version"], "weights": model["weights"], "bands": model["bands"],
                  "crit": model["criticality"], "stale_days": model["vulnerability"]["max_scan_age_days"],
                  "sig": model.get("risk_drift", {}).get("significant_delta", 5.0),
                  "check_weights": model["compliance"]["check_weights"]},
        "catalog": [{"id": k, "title": v["title"], "severity": v["severity"], "purpose": v["purpose"],
                     "expected": v["expected"], "sources": v["evidence_sources"]} for k, v in CHECKS.items()],
        "assets": assets_out,
        "prio": prio, "tau": tau,
        "evaluation": _evaluation(),
    }


TEMPLATE = Path(__file__).with_name("console_template.html")


def as_fragment(html: str) -> str:
    """Strip the document wrapper (doctype/html/head/body) for hosts that add their own skeleton."""
    head_start = html.index("<title>")
    html = html[head_start:]
    for tag in ("</head>", "<body>", "</body></html>"):
        html = html.replace(tag, "", 1)
    return html


def build_site(db_path: str | Path, out_path: str | Path, fragment: bool = False) -> Path:
    db = Database(db_path, read_only=True)
    try:
        data = export(db)
    finally:
        db.close()
    blob = json.dumps(data, separators=(",", ":"), default=str).replace("</", "<\\/")
    html = TEMPLATE.read_text(encoding="utf-8").replace("/*__DATA__*/null", blob)
    if fragment:
        html = as_fragment(html)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    (out.parent / ".nojekyll").write_text("")
    return out


if __name__ == "__main__":  # pragma: no cover
    print(build_site(sys.argv[1], sys.argv[2]))
