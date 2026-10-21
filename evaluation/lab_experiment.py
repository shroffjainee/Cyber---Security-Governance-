"""Analysis of the controlled lab drift experiment (REAL host evidence).

`lab/drift_experiment.sh all` runs nine real assessments on a lab host:
R1 hardened baseline, R2 no change, R3-R7 one injected configuration change
each, R8 remediation, R9 no change.  This module reads the resulting SQLite
database and compares what the framework detected with that known ground
truth.  Nothing here is synthetic: every number is read from stored runs.

Output: evaluation/results/lab_experiment.csv, lab_experiment.md, lab_metrics.json
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from core.config import PROJECT_ROOT
from storage.database import Database

RESULTS = PROJECT_ROOT / "evaluation" / "results"

# Ground truth of one trial of lab/drift_experiment.sh (order of runs) -> expected new non-compliance
GROUND_TRUTH: list[dict[str, Any]] = [
    {"step": "R1", "action": "Hardened baseline", "inject": None, "correct": []},
    {"step": "R2", "action": "No change", "inject": None, "correct": []},
    {"step": "R3", "action": "PermitRootLogin yes", "inject": "SSH-001", "correct": []},
    {"step": "R4", "action": "UFW firewall disabled", "inject": "FW-001", "correct": []},
    {"step": "R5", "action": "Prohibited service vsftpd started", "inject": "SVC-001", "correct": []},
    {"step": "R6", "action": "/etc/shadow mode 0644", "inject": "FILE-001", "correct": []},
    {"step": "R7", "action": "SSH password authentication enabled", "inject": "SSH-002", "correct": []},
    {"step": "R8", "action": "Password minlen lowered to 8", "inject": "PWD-001", "correct": []},
    {"step": "R9", "action": "pam_faillock lockout removed", "inject": "LOCK-001", "correct": []},
    {"step": "R10", "action": "Unattended security upgrades disabled", "inject": "UPD-001", "correct": []},
    {"step": "R11", "action": "Remediation (all restored)", "inject": None,
     "correct": ["SSH-001", "FW-001", "SVC-001", "FILE-001", "SSH-002", "PWD-001", "LOCK-001", "UPD-001"]},
    {"step": "R12", "action": "No change", "inject": None, "correct": []},
]
N = len(GROUND_TRUTH)
IGNORED = ("NEW_NON_COMPLIANCE", "CORRECTED", "BASELINE", "ASSESSMENT_INCOMPLETE")


def analyse(db_path: str | Path, asset_id: str = "lab-ubuntu-container") -> dict[str, Any]:
    """Compare stored runs with the ground truth. Runs are taken in blocks of 12 (one block per trial)."""
    db = Database(db_path, read_only=True)
    runs = db.query("SELECT * FROM assessment_runs WHERE asset_id=? AND data_origin='HOST' ORDER BY run_id",
                    (asset_id,))
    trials = len(runs) // N
    if trials == 0:
        db.close()
        raise ValueError(f"expected at least {N} HOST runs for {asset_id} in {db_path}, found {len(runs)} "
                         "- run `sudo bash lab/drift_experiment.sh all` first")
    runs = runs[-trials * N:]
    score_by_run = {s["run_id"]: s for s in db.query("SELECT * FROM risk_scores WHERE asset_id=?", (asset_id,))}
    rdrift = {r["score_id"]: r for r in db.query("SELECT * FROM risk_drift_events WHERE asset_id=?", (asset_id,))}
    rows: list[dict[str, Any]] = []
    per_check = {c: {"trials": 0, "tp": 0, "fn": 0} for c in [g["inject"] for g in GROUND_TRUTH if g["inject"]]}
    tp = fn = fp = corr_ok = corr_total = 0
    stable_runs = stable_fp = 0
    for t in range(trials):
        for gt, run in zip(GROUND_TRUTH, runs[t * N:(t + 1) * N]):
            events = db.drift_events_for_run(run["run_id"])
            new_nc = sorted({e["check_id"] for e in events if e["category"] == "NEW_NON_COMPLIANCE"})
            corrected = sorted({e["check_id"] for e in events if e["category"] == "CORRECTED"})
            other = [e for e in events if e["category"] not in IGNORED]
            expected = {gt["inject"]} if gt["inject"] else set()
            tp += len(expected & set(new_nc))
            fn += len(expected - set(new_nc))
            fp += len(set(new_nc) - expected) + len(other)
            if gt["inject"]:
                pc = per_check[gt["inject"]]
                pc["trials"] += 1
                pc["tp" if gt["inject"] in new_nc else "fn"] += 1
            if gt["action"] == "No change":
                stable_runs += 1
                stable_fp += len(new_nc) + len(other)
            corr_total += len(gt["correct"])
            corr_ok += len(set(gt["correct"]) & set(corrected))
            results = db.check_results(run["run_id"])
            sc = score_by_run.get(run["run_id"], {})
            rd = rdrift.get(sc.get("score_id"), {})
            rows.append({
                "trial": t + 1, "step": gt["step"], "action": gt["action"], "run_id": run["run_id"],
                "collected_at": run["started_at"],
                "compliant": sum(1 for r in results.values() if r["status"] == "COMPLIANT"),
                "non_compliant": sum(1 for r in results.values() if r["status"] == "NON_COMPLIANT"),
                "unknown": sum(1 for r in results.values() if r["status"] in ("UNKNOWN", "ERROR")),
                "injected": gt["inject"] or "-", "detected_new_non_compliance": ",".join(new_nc) or "-",
                "corrected": ",".join(corrected) or "-", "unexpected_drift_events": len(other),
                "risk_score": sc.get("score"), "band": sc.get("band"), "delta_r": rd.get("delta"),
                "risk_direction": rd.get("direction"),
            })
    db.close()
    metrics = {
        "data_origin": "HOST (real lab evidence)", "asset_id": asset_id, "trials": trials, "runs": len(rows),
        "injected_changes": tp + fn, "detected": tp, "missed": fn, "false_drift_events": fp,
        "detection_rate_recall": round(tp / (tp + fn), 3) if tp + fn else None,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "no_change_runs": stable_runs, "false_drift_in_no_change_runs": stable_fp,
        "remediations_recognised": f"{corr_ok}/{corr_total}",
        "per_check": per_check,
        "score_min": min(r["risk_score"] for r in rows if r["risk_score"] is not None),
        "score_max": max(r["risk_score"] for r in rows if r["risk_score"] is not None),
        "note": "Vulnerability component V absent (no Greenbone scan of the lab host) - scores are PARTIAL "
                "and renormalised over C, D, A. Lab host is an Ubuntu 24.04 container (systemd not PID 1: "
                "SVC-001 uses the /proc fallback for running services).",
    }
    return {"rows": rows, "metrics": metrics}


def write(result: dict[str, Any], out_dir: Path = RESULTS) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, m = result["rows"], result["metrics"]
    with (out_dir / "lab_experiment.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    (out_dir / "lab_metrics.json").write_text(json.dumps(m, indent=2))
    last = [r for r in rows if r["trial"] == m["trials"]]
    lines = ["# Controlled lab drift experiment (REAL host evidence)", "",
             f"Asset `{m['asset_id']}` · {m['trials']} trial(s) × {N} assessments · generated by "
             "`python cli.py lab-report` from the stored runs.", "",
             f"## Run-by-run results (trial {m['trials']})", "",
             "| Step | Action | C | NC | Injected | Detected (new non-compliance) | Corrected | Risk R | Band | ΔR |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in last:
        d = "baseline" if r["delta_r"] is None else f"{r['delta_r']:+.2f}"
        lines.append(f"| {r['step']} | {r['action']} | {r['compliant']} | {r['non_compliant']} | {r['injected']} | "
                     f"{r['detected_new_non_compliance']} | {r['corrected']} | {r['risk_score']} | {r['band']} | {d} |")
    lines += ["", "## Detection per control (all trials)", "", "| Check | Trials | Detected (TP) | Missed (FN) |",
              "|---|---|---|---|"]
    for c, v in m["per_check"].items():
        lines.append(f"| {c} | {v['trials']} | {v['tp']} | {v['fn']} |")
    lines += ["", f"**Summary:** {m['detected']}/{m['injected_changes']} injected changes detected "
              f"(recall {m['detection_rate_recall']}, precision {m['precision']}); "
              f"{m['false_drift_in_no_change_runs']} drift events in {m['no_change_runs']} no-change runs; "
              f"remediations recognised {m['remediations_recognised']}.", "", f"> {m['note']}"]
    (out_dir / "lab_experiment.md").write_text("\n".join(lines) + "\n")
