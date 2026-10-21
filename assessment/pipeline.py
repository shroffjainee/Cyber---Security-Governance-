"""End-to-end assessment pipeline.

collect (or load) evidence -> validate -> OPA evaluation -> normalize ->
store run/snapshot/results (one transaction) -> configuration drift ->
(optional) risk score + risk drift.
"""
from __future__ import annotations

from typing import Any

from collector import collect_evidence, validate_evidence
from collector.common import COLLECTOR_VERSION, Context
from core.config import find_asset
from drift.drift_detector import canonical_hash, detect_drift, normalize_evidence
from policy_engine.opa_runner import OPAError, OPARunner, merge_results
from risk.risk_score import score_asset
from storage.database import Database


def register_asset(db: Database, asset: dict[str, Any], data_origin: str = "HOST", changed_at: str | None = None) -> None:
    db.upsert_asset(asset["asset_id"], asset["criticality"], asset.get("hostname"), asset.get("ip_address"),
                    asset.get("description"), data_origin, changed_at)


def store_evidence_assessment(db: Database, evidence: dict[str, Any], runner: OPARunner | None) -> int:
    """Evaluate already-collected evidence and persist everything. Returns run_id."""
    validate_evidence(evidence)
    asset_id = evidence["asset"]["asset_id"]
    if db.get_asset(asset_id) is None:
        raise ValueError(f"asset {asset_id} is not registered")
    norm = normalize_evidence(evidence)
    check_hashes = {cid: canonical_hash(c) for cid, c in norm["checks"].items() if c is not None}
    run: dict[str, Any] = {
        "asset_id": asset_id, "started_at": evidence["collected_at"], "completed_at": evidence["collected_at"],
        "collector_version": evidence.get("collector_version", COLLECTOR_VERSION),
        "policy_params_hash": canonical_hash(norm["policy_params"]), "data_origin": evidence["data_origin"],
        "evidence_hash": canonical_hash(norm), "policy_version": None, "opa_version": None, "error_message": None,
    }
    snapshot = {"asset_id": asset_id, "collected_at": evidence["collected_at"],
                "normalized_evidence": _dumps(norm), "evidence_hash": run["evidence_hash"]}
    results: list[dict[str, Any]] = []
    try:
        if runner is None:
            raise OPAError("OPA not available")
        run["opa_version"] = runner.version()
        run["policy_version"] = runner.policy_version()
        decisions = runner.evaluate(evidence)
        results = merge_results(evidence, decisions, check_hashes)
        determined = [r for r in results if r["status"] in ("COMPLIANT", "NON_COMPLIANT")]
        if len(determined) == len(results):
            run["status"] = "COMPLETE"
        elif determined:
            run["status"] = "PARTIAL"
        else:
            run["status"] = "FAILED"
            run["error_message"] = "No check could be determined (all UNKNOWN/ERROR)."
    except OPAError as exc:
        run["status"] = "FAILED"
        run["error_message"] = f"Policy evaluation failed: {exc}"
        results = []
    run_id = db.store_assessment(run, snapshot, results)
    detect_drift(db, run_id)
    return run_id


def assess_host(db: Database, cfg: dict[str, Any], asset_id: str, runner: OPARunner | None,
                root: str = "/", model: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect from the live host (read-only), evaluate, store, detect drift, optionally score."""
    asset = find_asset(cfg, asset_id)
    register_asset(db, asset, "HOST")
    ctx = Context(root=root, timeout=float(cfg["collector"].get("command_timeout_seconds", 15)),
                  max_bytes=int(cfg["collector"].get("max_file_bytes", 1_048_576)),
                  policy_params=cfg["policy_params"])
    evidence = collect_evidence(ctx, asset_id, "HOST")
    run_id = store_evidence_assessment(db, evidence, runner)
    out: dict[str, Any] = {"run_id": run_id, "evidence": evidence}
    if model is not None:
        out["score_id"] = score_asset(db, asset_id, model)
    return out


def _dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
