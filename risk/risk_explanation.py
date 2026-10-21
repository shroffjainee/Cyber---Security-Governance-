"""Risk drift:  Delta R_t = R_t - R_(t-1)  and evidence-based explanations.

Comparability rules: both scores valid (status COMPLETE or PARTIAL with a
number), same asset, same ``model_version`` and the same set of available
components.  The previous score used is the most recent comparable one; if
none exists the current score becomes the BASELINE.

Explanations are of two kinds:
* arithmetic decomposition — because the model is linear,
  Delta R = sum_k w_k * (X_k,t - X_k,t-1) exactly (for non-renormalised
  scores; renormalised ones use the effective weights), so each
  component's contribution is a fact, not an inference;
* coinciding evidence — new/resolved findings, CVSS changes, compliance
  transitions, configuration drift, criticality and policy changes found in
  the stored records between the two scores.  These are reported as
  "observed alongside" the change; no causal claim is made.
"""
from __future__ import annotations

from typing import Any

from core.config import COMPONENTS
from storage.database import Database

EPS = 0.005


def _effective_weights(score: dict[str, Any]) -> dict[str, float]:
    w = score["weights"]
    avail = score["available_components"]
    total = sum(w[k] for k in avail) or 1.0
    return {k: (w[k] / total if k in avail else 0.0) for k in COMPONENTS}


def _comparable(prev: dict[str, Any], cur: dict[str, Any]) -> bool:
    return (prev["model_version"] == cur["model_version"]
            and prev["available_components"] == cur["available_components"]
            and prev["weights"] == cur["weights"])


def _previous_comparable(db: Database, cur: dict[str, Any]) -> tuple[dict[str, Any] | None, bool]:
    """Return (previous comparable score, skipped_noncomparable)."""
    skipped = False
    before = cur["score_id"]
    while True:
        prev = db.previous_score(cur["asset_id"], before)
        if prev is None:
            return None, skipped
        if _comparable(prev, cur):
            return prev, skipped
        skipped = True
        before = prev["score_id"]


def evidence_explanations(db: Database, prev: dict[str, Any], cur: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    # --- vulnerabilities
    pv = prev["components"]["V"].get("details", {})
    cv = cur["components"]["V"].get("details", {})
    if prev["scan_id"] != cur["scan_id"]:
        pk, ck = pv.get("scores_by_key", {}), cv.get("scores_by_key", {})
        new_keys = sorted(set(ck) - set(pk), key=lambda k: -ck[k])
        gone = sorted(set(pk) - set(ck), key=lambda k: -pk[k])
        changed = [k for k in set(pk) & set(ck) if abs(pk[k] - ck[k]) >= 0.1]
        ref_by_key = {}
        if cur["scan_id"]:
            for f in db.findings_for_scan(cur["scan_id"]):
                ref_by_key[f["finding_key"]] = (f["finding_id"], f["name"], f["cves"])
        for k in new_keys[:10]:
            fid, name, cves = ref_by_key.get(k, (None, k, []))
            rows.append({"component": "V", "factor": "new_vulnerability",
                         "detail": f"New finding in latest scan: {name} (severity {ck[k]}; {', '.join(cves) or 'no CVE'})",
                         "evidence_ref": f"vulnerability_findings:{fid}" if fid else f"vulnerability_scans:{cur['scan_id']}"})
        if gone:
            rows.append({"component": "V", "factor": "resolved_vulnerability",
                         "detail": f"{len(gone)} finding(s) from the previous scan are absent in the latest scan "
                                   "(remediated, or not detected this time).",
                         "evidence_ref": f"vulnerability_scans:{cur['scan_id']}" if cur["scan_id"] else None})
        for k in changed[:10]:
            fid, name, _ = ref_by_key.get(k, (None, k, []))
            rows.append({"component": "V", "factor": "severity_change",
                         "detail": f"Severity of {name} changed {pk[k]} -> {ck[k]}",
                         "evidence_ref": f"vulnerability_findings:{fid}" if fid else None})
        if cur["scan_id"] and not prev["scan_id"]:
            rows.append({"component": "V", "factor": "scan_imported", "detail": "First vulnerability scan imported.",
                         "evidence_ref": f"vulnerability_scans:{cur['scan_id']}"})
    if cur["components"]["V"].get("stale") and not prev["components"]["V"].get("stale"):
        rows.append({"component": "V", "factor": "stale_evidence",
                     "detail": "Vulnerability scan became stale; vulnerability component may no longer reflect the host.",
                     "evidence_ref": f"vulnerability_scans:{cur['scan_id']}"})
    # --- compliance transitions and configuration drift between the two runs
    if prev["run_id"] and cur["run_id"] and prev["run_id"] != cur["run_id"]:
        pr, cr = db.check_results(prev["run_id"]), db.check_results(cur["run_id"])
        for cid in sorted(set(pr) | set(cr)):
            ps, cs = pr.get(cid, {}).get("status"), cr.get(cid, {}).get("status")
            if ps != cs:
                rows.append({"component": "C", "factor": "compliance_transition",
                             "detail": f"{cid} {ps} -> {cs}: {cr.get(cid, {}).get('reason', '')}"[:400],
                             "evidence_ref": f"check_results:{cr[cid]['result_id']}" if cid in cr else None})
        drift = db.query("SELECT drift_id, check_id, category, priority FROM config_drift_events WHERE asset_id=?"
                         " AND run_id>? AND run_id<=? AND category NOT IN ('BASELINE') ORDER BY drift_id",
                         (cur["asset_id"], prev["run_id"], cur["run_id"]))
        for d in drift:
            factor = "policy_change" if d["category"] in ("POLICY_CHANGE", "TOOL_VERSION_CHANGE") else "configuration_drift"
            rows.append({"component": "D" if factor == "configuration_drift" else None, "factor": factor,
                         "detail": f"{d['category']} ({d['priority']}) on {d['check_id'] or 'assessment'}",
                         "evidence_ref": f"config_drift_events:{d['drift_id']}"})
    # --- criticality
    if prev.get("criticality") != cur.get("criticality"):
        hist = db.query("SELECT history_id FROM asset_criticality_history WHERE asset_id=? ORDER BY history_id DESC LIMIT 1",
                        (cur["asset_id"],))
        rows.append({"component": "A", "factor": "criticality_change",
                     "detail": f"Asset criticality changed {prev.get('criticality')} -> {cur.get('criticality')}",
                     "evidence_ref": f"asset_criticality_history:{hist[0]['history_id']}" if hist else None})
    return rows


def compute_risk_drift(db: Database, score_id: int, model: dict[str, Any]) -> int:
    cur = db.get_score(score_id)
    if cur is None:
        raise ValueError(f"score {score_id} not found")
    threshold = float(model.get("risk_drift", {}).get("significant_delta", 5.0))
    base = {"asset_id": cur["asset_id"], "score_id": score_id, "model_version": cur["model_version"],
            "detected_at": cur["calculated_at"], "current_score": cur["score"]}
    if cur["status"] == "UNKNOWN" or cur["score"] is None:
        return db.insert_risk_drift({**base, "direction": "NOT_COMPARABLE", "significant": 0}, [
            {"component": None, "factor": "not_comparable",
             "detail": "Current score is UNKNOWN (insufficient data); risk drift not computed.", "evidence_ref": None}])
    prev, skipped = _previous_comparable(db, cur)
    if prev is None:
        detail = "First valid score for this asset/model/component set: baseline established."
        if skipped:
            detail += " Earlier scores exist but used a different model version or component set."
        return db.insert_risk_drift({**base, "direction": "BASELINE", "significant": 0}, [
            {"component": None, "factor": "baseline", "detail": detail, "evidence_ref": f"risk_scores:{score_id}"}])
    delta = round(cur["score"] - prev["score"], 2)
    direction = "UNCHANGED" if abs(delta) < EPS else ("INCREASED" if delta > 0 else "DECREASED")
    ew = _effective_weights(cur)
    comp_deltas = {}
    for k in COMPONENTS:
        a, b = prev[f"{k.lower()}_score"], cur[f"{k.lower()}_score"]
        comp_deltas[k] = round(ew[k] * (b - a), 2) if a is not None and b is not None else None
    rows = [{"component": None, "factor": "delta",
             "detail": f"Risk {direction.lower()} by {delta:+.2f} ({prev['score']} -> {cur['score']}); "
                       f"significance threshold {threshold}.", "evidence_ref": f"risk_scores:{prev['score_id']}"}]
    for k, d in sorted(comp_deltas.items(), key=lambda kv: -abs(kv[1] or 0)):
        if d:
            rows.append({"component": k, "factor": "component_contribution",
                         "detail": f"Component {k} contributed {d:+.2f} points "
                                   f"({prev[f'{k.lower()}_score']} -> {cur[f'{k.lower()}_score']}).",
                         "evidence_ref": None})
    ev_rows = evidence_explanations(db, prev, cur)
    if ev_rows:
        rows.append({"component": None, "factor": "note",
                     "detail": "The following stored evidence was observed between the two scores; it is listed as "
                               "coinciding with the change, not as a proven cause.", "evidence_ref": None})
    rows.extend(ev_rows)
    if direction != "UNCHANGED" and not ev_rows:
        rows.append({"component": None, "factor": "no_evidence_found",
                     "detail": "No stored evidence change was found that coincides with this delta (e.g. only time-window effects).",
                     "evidence_ref": None})
    if skipped:
        rows.append({"component": None, "factor": "not_comparable",
                     "detail": "Intermediate scores with a different model/component set were skipped.", "evidence_ref": None})
    return db.insert_risk_drift({**base, "previous_score_id": prev["score_id"], "previous_score": prev["score"],
                                 "delta": delta, "direction": direction, "significant": int(abs(delta) >= threshold),
                                 "component_deltas": comp_deltas}, rows)
