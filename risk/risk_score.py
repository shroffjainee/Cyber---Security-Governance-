"""Explainable prototype risk-priority score (0-100).

    R_t = wV*V_t + wC*C_t + wD*D_t + wA*A_t      (default 0.45/0.25/0.20/0.10)

The score is a transparent PRIORITISATION aid, not a validated probability
of exploitation or loss.  Every component is 0-100, higher = more risk.

V_t  vulnerability risk (latest imported scan for the asset)
     per open finding s_i = CVSS base score (0-10). Missing CVSS -> fallback
     from Greenbone threat label (configurable), else unknown_cvss_default;
     each such estimate is flagged.  Findings with QoD < min_qod or
     s_i < min_cvss_counted are excluded.  Findings are already de-duplicated
     per (NVT, host, port) by the importer, and only ONE scan (the latest)
     is used, so repeated scans are never double-counted.
         V = max_share*10*max(s_i) + breadth_share*100*min(1, sum(s_i/10)/saturation)
     No scan -> V unavailable (NOT zero).  Scan older than max_scan_age_days
     -> V used but flagged STALE (score status PARTIAL).

C_t  compliance risk (latest successful assessment)
         C = 100 * sum(w_i * r_i) / sum(w_i)
     r_i = 1 NON_COMPLIANT, 0 COMPLIANT, 0.5 UNKNOWN/ERROR (configurable).
     Bounds use r_i in [0,1] for undetermined checks.  If more than
     max_undetermined_fraction of checks are undetermined, C is unavailable.

D_t  configuration-drift risk: unresolved risk-increasing drift events in
     the last window_days.  Each check contributes only its most recent
     event; run-level events (failed assessment, policy change) count once
     per category.  Corrected/baseline/restored events and events for checks
     that are now COMPLIANT are ignored.  D = min(100, sum(priority points)).
     First assessment (baseline) -> D = 0, flagged as baseline.

A_t  asset criticality: Low 25, Medium 50, High 75, Critical 100.

Missing components: if more than half of the total weight is missing the
score is UNKNOWN (no number).  Otherwise the score is renormalised over
available weights, status PARTIAL, and lower/upper bounds (missing
component = 0 / 100) are stored so the uncertainty is explicit.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from core.catalog import CHECKS
from core.config import COMPONENTS
from core.timeutil import iso, parse_iso, utc_now
from storage.database import Database

UNDETERMINED = ("UNKNOWN", "ERROR")


def _band(score: float | None, bands: dict[str, float]) -> str | None:
    if score is None:
        return None
    current = None
    for name, lo in sorted(bands.items(), key=lambda kv: kv[1]):
        if score >= lo:
            current = name
    return current


def _r2(x: float | None) -> float | None:
    return None if x is None else round(float(x), 2)


# ---------------------------------------------------------------- components
def vulnerability_component(findings: list[dict[str, Any]] | None, scan: dict[str, Any] | None,
                            cfg: dict[str, Any], now: datetime) -> dict[str, Any]:
    if scan is None or findings is None:
        return {"value": None, "available": False, "stale": False, "lower": 0.0, "upper": 100.0,
                "note": "No vulnerability scan imported: vulnerability risk is unknown (not zero).",
                "refs": [], "details": {}}
    scan_time = parse_iso(scan.get("scan_ended_at") or scan.get("scan_started_at") or scan.get("imported_at"))
    age_days = (now - scan_time).total_seconds() / 86400 if scan_time else None
    stale = age_days is None or age_days > cfg["max_scan_age_days"]
    seen: set[str] = set()
    counted: list[dict[str, Any]] = []
    estimated = excluded_qod = 0
    for f in findings:
        if f.get("status", "OPEN") != "OPEN" or f["finding_key"] in seen:
            continue
        seen.add(f["finding_key"])
        if f.get("qod") is not None and f["qod"] < cfg["min_qod"]:
            excluded_qod += 1
            continue
        s, basis = f.get("cvss_score"), "cvss"
        if s is None:
            label = (f.get("severity_label") or "").lower()
            if label in cfg["label_fallback_cvss"]:
                s, basis = cfg["label_fallback_cvss"][label], f"label:{label}"
            else:
                s, basis = cfg["unknown_cvss_default"], "default"
            estimated += 1
        s = max(0.0, min(10.0, float(s)))
        if s < cfg["min_cvss_counted"]:
            continue
        counted.append({"finding_id": f.get("finding_id"), "key": f["finding_key"], "s": s, "basis": basis,
                        "name": f.get("name"), "cves": f.get("cves") or []})
    if counted:
        max_s = max(c["s"] for c in counted)
        breadth = 100.0 * min(1.0, sum(c["s"] / 10.0 for c in counted) / cfg["breadth_saturation"])
        value = cfg["max_component_share"] * 10.0 * max_s + cfg["breadth_share"] * breadth
    else:
        max_s, breadth, value = 0.0, 0.0, 0.0
    value = max(0.0, min(100.0, value))
    counted.sort(key=lambda c: -c["s"])
    note = f"{len(counted)} counted open findings, max CVSS {max_s:.1f}, breadth {breadth:.1f}"
    if stale:
        note += f"; scan is STALE ({'unknown age' if age_days is None else f'{age_days:.0f} days old'})"
    return {"value": value, "available": True, "stale": stale, "lower": value, "upper": value, "note": note,
            "refs": [f"vulnerability_findings:{c['finding_id']}" for c in counted[:5] if c["finding_id"]],
            "details": {"scan_id": scan.get("scan_id"), "scan_time": iso(scan_time) if scan_time else None,
                        "age_days": _r2(age_days), "max_cvss": max_s, "breadth": _r2(breadth),
                        "counted": len(counted), "estimated_cvss": estimated, "excluded_low_qod": excluded_qod,
                        "top": [{k: c[k] for k in ("finding_id", "name", "s", "basis", "cves")} for c in counted[:5]],
                        "scores_by_key": {c["key"]: c["s"] for c in counted[:500]}}}


def compliance_component(results: dict[str, dict[str, Any]] | None, cfg: dict[str, Any]) -> dict[str, Any]:
    if results is None:
        return {"value": None, "available": False, "lower": 0.0, "upper": 100.0, "stale": False,
                "note": "No successful compliance assessment: compliance risk unknown.", "refs": [], "details": {}}
    weights, risk_of = cfg["check_weights"], cfg["status_risk"]
    total_w = sum(weights[c] for c in CHECKS)
    val = lo = hi = 0.0
    statuses: dict[str, str] = {}
    refs = []
    issues = []
    for cid in CHECKS:
        st = results.get(cid, {}).get("status", "UNKNOWN")
        statuses[cid] = st
        w = weights[cid]
        val += w * risk_of[st]
        lo += w * (risk_of[st] if st not in UNDETERMINED else 0.0)
        hi += w * (risk_of[st] if st not in UNDETERMINED else 1.0)
        if st != "COMPLIANT":
            rid = results.get(cid, {}).get("result_id")
            if rid:
                refs.append(f"check_results:{rid}")
            issues.append({"check_id": cid, "status": st, "result_id": rid,
                           "reason": (results.get(cid, {}).get("reason") or "no result")[:300]})
    undetermined = [c for c, s in statuses.items() if s in UNDETERMINED]
    frac = len(undetermined) / len(CHECKS)
    comp = {"value": 100 * val / total_w, "available": True, "stale": False,
            "lower": 100 * lo / total_w, "upper": 100 * hi / total_w, "refs": refs,
            "note": f"{sum(1 for s in statuses.values() if s == 'NON_COMPLIANT')} non-compliant, "
                    f"{len(undetermined)} undetermined of {len(CHECKS)} checks",
            "details": {"statuses": statuses, "undetermined": undetermined, "issues": issues}}
    if frac > cfg["max_undetermined_fraction"]:
        comp.update(value=None, available=False, lower=0.0, upper=100.0,
                    note=comp["note"] + f" — too many undetermined checks ({frac:.0%}); compliance risk unreliable")
    return comp


def drift_component(events: list[dict[str, Any]] | None, current_statuses: dict[str, str] | None,
                    is_baseline: bool, cfg: dict[str, Any]) -> dict[str, Any]:
    if events is None or current_statuses is None:
        return {"value": None, "available": False, "lower": 0.0, "upper": 100.0, "stale": False,
                "note": "No assessment history: drift risk unknown.", "refs": [], "details": {}}
    if is_baseline:
        return {"value": 0.0, "available": True, "lower": 0.0, "upper": 0.0, "stale": False,
                "note": "Baseline assessment: no previous state, so no drift can be measured yet.",
                "refs": [], "details": {"baseline": True, "counted": []}}
    ignore = set(cfg["ignore_categories"]) | {"ASSESSMENT_INCOMPLETE"}
    latest: dict[str, dict[str, Any]] = {}
    for ev in sorted(events, key=lambda e: (e["detected_at"], e["drift_id"])):
        key = ev["check_id"] or f"run:{ev['category']}"
        latest[key] = ev
    counted = []
    for key, ev in latest.items():
        if ev["category"] in ignore:
            continue
        if ev["check_id"] and current_statuses.get(ev["check_id"]) == "COMPLIANT":
            continue  # resolved since
        pts = cfg["priority_points"][ev["priority"]]
        if pts > 0:
            counted.append({"drift_id": ev["drift_id"], "check_id": ev["check_id"], "category": ev["category"],
                            "priority": ev["priority"], "points": pts})
    value = float(min(100, sum(c["points"] for c in counted)))
    return {"value": value, "available": True, "lower": value, "upper": value, "stale": False,
            "note": f"{len(counted)} unresolved drift events in last {cfg['window_days']} days",
            "refs": [f"config_drift_events:{c['drift_id']}" for c in counted], "details": {"counted": counted}}


def criticality_component(criticality: str | None, cfg: dict[str, Any]) -> dict[str, Any]:
    if criticality not in cfg:
        return {"value": None, "available": False, "lower": 0.0, "upper": 100.0, "stale": False,
                "note": "Asset criticality not set.", "refs": [], "details": {}}
    v = float(cfg[criticality])
    return {"value": v, "available": True, "lower": v, "upper": v, "stale": False,
            "note": f"Asset criticality {criticality}", "refs": [], "details": {"criticality": criticality}}


# --------------------------------------------------------------- combination
def combine(components: dict[str, dict[str, Any]], weights: dict[str, float],
            bands: dict[str, float]) -> dict[str, Any]:
    for k in COMPONENTS:
        c = components[k]
        if c["value"] is not None and not 0 <= c["value"] <= 100:
            raise ValueError(f"component {k} out of range: {c['value']}")
    available = [k for k in COMPONENTS if components[k]["available"] and components[k]["value"] is not None]
    avail_w = sum(weights[k] for k in available)
    lower = sum(weights[k] * components[k]["lower"] for k in COMPONENTS)
    upper = sum(weights[k] * components[k]["upper"] for k in COMPONENTS)
    warnings = [components[k]["note"] for k in COMPONENTS if not components[k]["available"]]
    if any(components[k].get("stale") for k in COMPONENTS):
        warnings.append("Vulnerability data is stale; score may understate current exposure.")
    undetermined = components["C"].get("details", {}).get("undetermined") or []
    if undetermined:
        warnings.append(f"Undetermined compliance checks: {', '.join(undetermined)} (penalised, see bounds).")
    if avail_w < 0.5 - 1e-9:
        return {"status": "UNKNOWN", "score": None, "lower": _r2(lower), "upper": _r2(upper), "band": None,
                "available": "".join(available), "warnings": warnings +
                ["Less than half of the model weight is backed by data: score withheld."]}
    if avail_w >= 1 - 1e-9:
        score = sum(weights[k] * components[k]["value"] for k in COMPONENTS)
    else:
        score = sum(weights[k] * components[k]["value"] for k in available) / avail_w
        warnings.append(f"Score renormalised over available components {''.join(available)}; "
                        f"true value lies within [{lower:.1f}, {upper:.1f}].")
    partial = avail_w < 1 - 1e-9 or bool(undetermined) or any(components[k].get("stale") for k in COMPONENTS)
    score = max(0.0, min(100.0, score))
    return {"status": "PARTIAL" if partial else "COMPLETE", "score": _r2(score), "lower": _r2(lower),
            "upper": _r2(upper), "band": _band(score, bands), "available": "".join(available), "warnings": warnings}


def score_from_components(components: dict[str, dict[str, Any]], weights: dict[str, float]) -> float | None:
    """Weighted score for an alternative weight set (used for sensitivity analysis)."""
    if any(components[k]["value"] is None for k in COMPONENTS):
        return None
    return round(sum(weights[k] * components[k]["value"] for k in COMPONENTS), 2)


def compute_risk(model: dict[str, Any], *, check_results: dict[str, dict[str, Any]] | None,
                 findings: list[dict[str, Any]] | None, scan: dict[str, Any] | None,
                 drift_events: list[dict[str, Any]] | None, is_baseline: bool, criticality: str | None,
                 now: datetime | None = None) -> dict[str, Any]:
    """Pure scoring function (no database access) — deterministic for identical inputs."""
    now = now or utc_now()
    comps = {
        "V": vulnerability_component(findings, scan, model["vulnerability"], now),
        "C": compliance_component(check_results, model["compliance"]),
        "D": drift_component(drift_events, {c: r["status"] for c, r in (check_results or {}).items()} if check_results is not None else None,
                             is_baseline, model["drift"]),
        "A": criticality_component(criticality, model["criticality"]),
    }
    for c in comps.values():
        for key in ("value", "lower", "upper"):
            c[key] = _r2(c[key])
    out = combine(comps, model["weights"], model["bands"])
    out["components"] = comps
    out["weights"] = model["weights"]
    out["model_version"] = model["model_version"]
    out["sensitivity"] = {name: score_from_components(comps, ws)
                          for name, ws in model.get("alternative_weight_sets", {}).items()}
    return out


def score_explanations(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Evidence-linked explanation rows for a score (stored in risk_explanations)."""
    rows = []
    w = result["weights"]
    for k, comp in result["components"].items():
        contrib = None if comp["value"] is None else round(w[k] * comp["value"], 2)
        rows.append({"component": k, "factor": "component",
                     "detail": f"{k}={comp['value']} (weight {w[k]}, contributes {contrib}): {comp['note']}",
                     "evidence_ref": None})
        if k == "V":
            for t in comp["details"].get("top", []):
                rows.append({"component": "V", "factor": "vulnerability",
                             "detail": f"{t['name']} — severity {t['s']} ({t['basis']}); CVEs: {', '.join(t['cves']) or 'none listed'}",
                             "evidence_ref": f"vulnerability_findings:{t['finding_id']}"})
        if k == "C":
            for i in comp["details"].get("issues", []):
                rows.append({"component": "C", "factor": "compliance",
                             "detail": f"{i['check_id']} {i['status']}: {i['reason']}",
                             "evidence_ref": f"check_results:{i['result_id']}" if i["result_id"] else None})
        if k == "D":
            for c in comp["details"].get("counted", []):
                rows.append({"component": "D", "factor": "drift",
                             "detail": f"{c['category']} on {c['check_id'] or 'assessment'} ({c['priority']}, {c['points']} pts)",
                             "evidence_ref": f"config_drift_events:{c['drift_id']}"})
    for wmsg in result["warnings"]:
        rows.append({"component": None, "factor": "data_quality", "detail": wmsg, "evidence_ref": None})
    return rows


# ------------------------------------------------------------- DB wrapper
def gather_inputs(db: Database, asset_id: str, model: dict[str, Any], now: datetime) -> dict[str, Any]:
    asset = db.get_asset(asset_id)
    if asset is None:
        raise ValueError(f"unknown asset {asset_id}")
    run = db.latest_successful_run(asset_id)
    check_results = None
    events = None
    is_baseline = False
    if run:
        check_results = db.check_results(run["run_id"])
        since = iso(now - timedelta(days=model["drift"]["window_days"]))
        events = db.drift_events(asset_id, since=since, until=iso(now))
        is_baseline = db.previous_comparable_run(asset_id, run["run_id"], run["data_origin"]) is None
    scan = db.latest_scan(asset_id, at=iso(now))
    findings = db.findings_for_scan(scan["scan_id"]) if scan else None
    return {"asset": asset, "run": run, "scan": scan, "check_results": check_results, "findings": findings,
            "drift_events": events, "is_baseline": is_baseline}


def score_asset(db: Database, asset_id: str, model: dict[str, Any], now: datetime | None = None) -> int:
    """Compute, store and explain a score; then compute risk drift. Returns score_id."""
    from risk.risk_explanation import compute_risk_drift  # local import avoids cycle

    now = now or utc_now()
    inp = gather_inputs(db, asset_id, model, now)
    result = compute_risk(model, check_results=inp["check_results"], findings=inp["findings"], scan=inp["scan"],
                          drift_events=inp["drift_events"], is_baseline=inp["is_baseline"],
                          criticality=inp["asset"]["criticality"], now=now)
    comps = result["components"]
    origin = "SYNTHETIC" if inp["asset"]["data_origin"] == "SYNTHETIC" else "HOST"
    row = {
        "asset_id": asset_id, "run_id": inp["run"]["run_id"] if inp["run"] else None,
        "scan_id": inp["scan"]["scan_id"] if inp["scan"] else None, "calculated_at": iso(now),
        "model_version": result["model_version"], "status": result["status"], "score": result["score"],
        "score_lower": result["lower"], "score_upper": result["upper"], "band": result["band"],
        "v_score": comps["V"]["value"], "c_score": comps["C"]["value"], "d_score": comps["D"]["value"],
        "a_score": comps["A"]["value"], "available_components": result["available"],
        "weights": result["weights"], "components": {**comps, "sensitivity": result["sensitivity"]},
        "warnings": result["warnings"], "criticality": inp["asset"]["criticality"], "data_origin": origin,
    }
    score_id = db.insert_risk_score(row, score_explanations(result))
    compute_risk_drift(db, score_id, model)
    return score_id
