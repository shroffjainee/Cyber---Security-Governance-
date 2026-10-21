"""Configuration drift detection between consecutive comparable assessments.

Comparable = same asset, same data_origin, previous run with status
COMPLETE or PARTIAL (failed runs are never used as a reference).

Normalization prevents false drift: timestamps are removed, lists of scalars
are sorted, strings are whitespace-collapsed, and config line numbers are
stripped from provenance fields (editing a comment above a directive must
not look like a configuration change).

The first comparable assessment produces a single BASELINE record, which is
*not* drift and carries no risk weight.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from core.catalog import CHECKS
from storage.database import Database

VOLATILE_KEYS = {"collected_at"}
# Collection metadata: HOW a value was obtained (sshd -T vs config parsing, systemd vs /proc, which file/line).
# A change here (e.g. running once with and once without root) is not a configuration change, so it is
# kept in the stored evidence but excluded from configuration-drift comparison. The values themselves
# are still compared.
COLLECTION_META_KEYS = {"method", "value_origin"}
_LINE_SUFFIX = re.compile(r":\d+$")
DETERMINED = ("COMPLIANT", "NON_COMPLIANT")
UNDETERMINED = ("UNKNOWN", "ERROR")
MAX_VALUE_ITEMS = 50


def _norm(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {k: _norm(v, k) for k, v in sorted(value.items()) if k not in VOLATILE_KEYS}
    if isinstance(value, list):
        items = [_norm(v, key) for v in value]
        if all(not isinstance(i, (dict, list)) for i in items):
            return sorted(items, key=lambda x: (x is None, str(x)))
        return items
    if isinstance(value, str):
        return " ".join(value.split())
    return value


def _strip_origin_lines(ev: Any, key: str = "") -> Any:
    if isinstance(ev, dict):
        return {k: _strip_origin_lines(v, k if k in ("value_origin", "match_overrides") else key) for k, v in ev.items()}
    if isinstance(ev, list):
        return [_strip_origin_lines(v, key) for v in ev]
    if isinstance(ev, str) and key in ("value_origin", "match_overrides"):
        return _LINE_SUFFIX.sub("", ev)
    return ev


def normalize_check(check: dict[str, Any] | None) -> dict[str, Any] | None:
    """Normalized, drift-relevant view of one check's evidence (no timestamps, no sources)."""
    if check is None:
        return None
    ev = {k: v for k, v in (check.get("evidence") or {}).items() if k not in COLLECTION_META_KEYS}
    return _norm({"collector_status": check.get("collector_status"), "evidence": _strip_origin_lines(ev)})


def normalize_evidence(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "asset_id": doc.get("asset", {}).get("asset_id"),
        "os_release": _norm(doc.get("asset", {}).get("os_release", {})),
        "policy_params": _norm(doc.get("policy_params", {})),
        "checks": {cid: normalize_check(doc.get("checks", {}).get(cid)) for cid in CHECKS},
    }


def canonical_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else k))
    else:
        out[prefix] = obj
    return out


def evidence_diff(prev: dict[str, Any] | None, cur: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (previous_values, current_values) for keys whose values differ."""
    fp, fc = _flatten(prev or {}), _flatten(cur or {})
    before, after = {}, {}
    for key in sorted(set(fp) | set(fc)):
        a, b = fp.get(key), fc.get(key)
        if a == b:
            continue
        if isinstance(a, list) and isinstance(b, list):
            removed = [x for x in a if x not in b][:MAX_VALUE_ITEMS]
            added = [x for x in b if x not in a][:MAX_VALUE_ITEMS]
            before[key] = {"removed": removed}
            after[key] = {"added": added}
        else:
            before[key], after[key] = a, b
    return before, after


def _event(run: dict[str, Any], prev_run_id: int | None, category: str, priority: str, explanation: str,
           check_id: str | None = None, prev_status: str | None = None, cur_status: str | None = None,
           prev_value: Any = None, cur_value: Any = None) -> dict[str, Any]:
    return {"asset_id": run["asset_id"], "run_id": run["run_id"], "previous_run_id": prev_run_id,
            "check_id": check_id, "category": category, "priority": priority,
            "previous_status": prev_status, "current_status": cur_status,
            "previous_value": prev_value, "current_value": cur_value, "explanation": explanation,
            "detected_at": run.get("completed_at") or run["started_at"]}


def classify_check(run: dict[str, Any], prev_run_id: int, cid: str, prev: dict[str, Any] | None,
                   cur: dict[str, Any] | None, prev_ev: dict[str, Any] | None,
                   cur_ev: dict[str, Any] | None) -> list[dict[str, Any]]:
    title = CHECKS[cid]["title"]
    severity = CHECKS[cid]["severity"]
    ps = prev["status"] if prev else None
    cs = cur["status"] if cur else None
    before, after = evidence_diff(prev_ev, cur_ev)
    reason = (cur or {}).get("reason") or ""
    if cs is None:
        return [_event(run, prev_run_id, "MISSING_EVIDENCE", "MEDIUM",
                       f"{cid} ({title}) has no result in this assessment; previous status was {ps}.",
                       cid, ps, None, before, after)]
    if ps is None:
        return []
    if ps == cs:
        if not before and not after:
            return []
        prio = "MEDIUM" if cs == "NON_COMPLIANT" else "LOW"
        return [_event(run, prev_run_id, "CONFIGURATION_CHANGE", prio,
                       f"{cid} ({title}) evidence changed while status stayed {cs}: {', '.join(sorted(set(before) | set(after)))[:300]}. "
                       "Review whether the change was authorised.", cid, ps, cs, before, after)]
    if ps == "COMPLIANT" and cs == "NON_COMPLIANT":
        return [_event(run, prev_run_id, "NEW_NON_COMPLIANCE", severity,
                       f"{cid} ({title}) changed from COMPLIANT to NON_COMPLIANT: {reason}", cid, ps, cs, before, after)]
    if ps == "NON_COMPLIANT" and cs == "COMPLIANT":
        return [_event(run, prev_run_id, "CORRECTED", "INFO",
                       f"{cid} ({title}) was remediated and is now COMPLIANT.", cid, ps, cs, before, after)]
    if ps in DETERMINED and cs in UNDETERMINED:
        return [_event(run, prev_run_id, "MISSING_EVIDENCE", "MEDIUM",
                       f"{cid} ({title}) was {ps} but is now {cs}; the control can no longer be verified: {reason}",
                       cid, ps, cs, before, after)]
    if ps in UNDETERMINED and cs == "COMPLIANT":
        return [_event(run, prev_run_id, "EVIDENCE_RESTORED", "INFO",
                       f"{cid} ({title}) evidence is available again and the control is COMPLIANT.", cid, ps, cs, before, after)]
    if ps in UNDETERMINED and cs == "NON_COMPLIANT":
        return [_event(run, prev_run_id, "COMPLIANCE_TRANSITION", severity,
                       f"{cid} ({title}) is NON_COMPLIANT; it was previously {ps}, so it is unknown whether the "
                       f"violation is new: {reason}", cid, ps, cs, before, after)]
    return [_event(run, prev_run_id, "COMPLIANCE_TRANSITION", "LOW",
                   f"{cid} ({title}) changed from {ps} to {cs}: {reason}", cid, ps, cs, before, after)]


def detect_drift(db: Database, run_id: int) -> list[dict[str, Any]]:
    """Compute and store drift events for ``run_id``. Returns the stored events."""
    run = db.get_run(run_id)
    if run is None:
        raise ValueError(f"run {run_id} not found")
    prev = db.previous_comparable_run(run["asset_id"], run_id, run["data_origin"])
    prev_id = prev["run_id"] if prev else None
    events: list[dict[str, Any]] = []

    if run["status"] == "FAILED":
        events.append(_event(run, prev_id, "ASSESSMENT_FAILED", "HIGH",
                             f"Assessment failed: {run.get('error_message') or 'unknown error'}. No compliance "
                             "conclusions can be drawn; the previous successful result is not assumed to still hold."))
        db.insert_drift_events(events)
        return events

    cur_results = db.check_results(run_id)
    undetermined = sorted(c for c, r in cur_results.items() if r["status"] in UNDETERMINED)

    if prev is None:
        events.append(_event(run, None, "BASELINE", "INFO",
                             "First comparable assessment for this asset: baseline recorded (not drift)."))
        if undetermined:
            events.append(_event(run, None, "ASSESSMENT_INCOMPLETE", "MEDIUM",
                                 f"Baseline has undetermined checks: {', '.join(undetermined)}."))
        db.insert_drift_events(events)
        return events

    if run["policy_version"] != prev["policy_version"]:
        events.append(_event(run, prev_id, "POLICY_CHANGE", "LOW",
                             f"Policy version changed {prev['policy_version']} -> {run['policy_version']}; "
                             "status transitions may reflect policy changes rather than host changes.",
                             prev_value=prev["policy_version"], cur_value=run["policy_version"]))
    if run["policy_params_hash"] != prev["policy_params_hash"]:
        prev_snap, cur_snap = db.snapshot(prev_id), db.snapshot(run_id)
        b, a = evidence_diff(prev_snap["normalized_evidence"]["policy_params"] if prev_snap else {},
                             cur_snap["normalized_evidence"]["policy_params"] if cur_snap else {})
        events.append(_event(run, prev_id, "POLICY_CHANGE", "MEDIUM",
                             "Compliance policy parameters changed; transitions in this run may be policy-driven.",
                             prev_value=b, cur_value=a))
    for field in ("collector_version", "opa_version"):
        if run[field] != prev[field]:
            events.append(_event(run, prev_id, "TOOL_VERSION_CHANGE", "INFO",
                                 f"{field} changed {prev[field]} -> {run[field]}.",
                                 prev_value=prev[field], cur_value=run[field]))
    if undetermined:
        events.append(_event(run, prev_id, "ASSESSMENT_INCOMPLETE", "MEDIUM",
                             f"Assessment incomplete; undetermined checks: {', '.join(undetermined)}."))

    prev_results = db.check_results(prev_id)
    prev_snap = db.snapshot(prev_id)
    cur_snap = db.snapshot(run_id)
    prev_norm = prev_snap["normalized_evidence"]["checks"] if prev_snap else {}
    cur_norm = cur_snap["normalized_evidence"]["checks"] if cur_snap else {}
    for cid in CHECKS:
        events.extend(classify_check(run, prev_id, cid, prev_results.get(cid), cur_results.get(cid),
                                     prev_norm.get(cid), cur_norm.get(cid)))
    db.insert_drift_events(events)
    return events
