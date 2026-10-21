"""Three prioritisation methods over the same stored data, for comparison:

* CVSS-only        — rank by highest open-finding CVSS in the latest scan
                     (ties: number of findings with CVSS >= 7).
* Compliance-only  — rank by count of NON_COMPLIANT checks in the latest
                     successful assessment (ties: undetermined checks).
* Proposed         — rank by the latest risk score R_t (UNKNOWN last).

Rank 1 = highest priority.  Ties share the same rank (dense ranking).
"""
from __future__ import annotations

from itertools import combinations
from typing import Any

from storage.database import Database


def _dense_rank(items: list[dict[str, Any]], key: str) -> None:
    ordered = sorted(items, key=lambda x: x[key], reverse=True)
    rank, last = 0, object()
    for it in ordered:
        if it[key] != last:
            rank += 1
            last = it[key]
        it[f"rank_{key}"] = rank


def prioritization_table(db: Database, data_origin: str | None = None) -> list[dict[str, Any]]:
    assets = db.list_assets()
    if data_origin:
        assets = [a for a in assets if a["data_origin"] == data_origin]
    rows = []
    for a in assets:
        aid = a["asset_id"]
        scan = db.latest_scan(aid)
        findings = [f for f in db.findings_for_scan(scan["scan_id"])] if scan else []
        open_cvss = [f["cvss_score"] for f in findings if f["status"] == "OPEN" and f["cvss_score"] is not None]
        run = db.latest_successful_run(aid)
        results = db.check_results(run["run_id"]) if run else {}
        nc = sum(1 for r in results.values() if r["status"] == "NON_COMPLIANT")
        und = sum(1 for r in results.values() if r["status"] in ("UNKNOWN", "ERROR"))
        sc = db.query("SELECT score, status, band FROM risk_scores WHERE asset_id=? ORDER BY score_id DESC LIMIT 1", (aid,))
        score = sc[0]["score"] if sc else None
        rows.append({
            "asset_id": aid, "criticality": a["criticality"], "data_origin": a["data_origin"],
            "max_cvss": max(open_cvss) if open_cvss else (0.0 if scan else None),
            "high_findings": sum(1 for c in open_cvss if c >= 7.0), "has_scan": scan is not None,
            "non_compliant": nc if run else None, "undetermined": und if run else None,
            "risk_score": score, "risk_status": sc[0]["status"] if sc else None, "risk_band": sc[0]["band"] if sc else None,
            # sort keys (missing data sorts last, never "safest-first by accident")
            "cvss_key": ((max(open_cvss) if open_cvss else 0.0), sum(1 for c in open_cvss if c >= 7.0)) if scan else (-1, -1),
            "compliance_key": (nc, und) if run else (-1, -1),
            "risk_key": score if score is not None else -1,
        })
    _dense_rank(rows, "cvss_key")
    _dense_rank(rows, "compliance_key")
    _dense_rank(rows, "risk_key")
    for r in rows:
        r["rank_cvss_only"] = r.pop("rank_cvss_key")
        r["rank_compliance_only"] = r.pop("rank_compliance_key")
        r["rank_proposed"] = r.pop("rank_risk_key")
        for k in ("cvss_key", "compliance_key", "risk_key"):
            r.pop(k)
    return sorted(rows, key=lambda r: r["rank_proposed"])


def kendall_tau(a: list[float], b: list[float]) -> float | None:
    """Kendall tau-a between two rank lists (no external dependency)."""
    n = len(a)
    if n < 2:
        return None
    conc = disc = 0
    for i, j in combinations(range(n), 2):
        s = (a[i] - a[j]) * (b[i] - b[j])
        if s > 0:
            conc += 1
        elif s < 0:
            disc += 1
    return round((conc - disc) / (n * (n - 1) / 2), 3)


def top_k_overlap(rows: list[dict[str, Any]], key_a: str, key_b: str, k: int) -> float:
    ta = {r["asset_id"] for r in rows if r[key_a] <= k}
    tb = {r["asset_id"] for r in rows if r[key_b] <= k}
    return round(len(ta & tb) / max(1, len(ta | tb)), 3)
