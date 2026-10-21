"""Reproducible evaluation scenarios (SYNTHETIC evidence, isolated DB, real OPA).

Each scenario declares its expected check statuses, expected drift events
and expected risk direction *before* running; the harness then runs the
real pipeline (OPA evaluation, drift detection, Greenbone import, scoring)
and records what was observed.  Nothing on a real host is modified.

Run:  python cli.py evaluate-scenarios   (writes evaluation/results/)
"""
from __future__ import annotations

import csv
import json
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from assessment.pipeline import register_asset, store_evidence_assessment
from core.catalog import CHECKS
from core.config import PROJECT_ROOT, load_asset_policy, load_risk_model
from core.timeutil import iso
from evaluation import synthetic as syn
from policy_engine.opa_runner import OPARunner
from risk.risk_score import score_asset
from storage.database import Database, DatabaseError, DuplicateImportError
from vulnerability.greenbone_importer import ReportFormatError, import_report

T0 = datetime(2026, 9, 1, 8, 0, tzinfo=timezone.utc)
HOST_IP = "10.20.30.40"
RESULTS_DIR = PROJECT_ROOT / "evaluation" / "results"
IGNORED_DRIFT = {"BASELINE", "TOOL_VERSION_CHANGE", "ASSESSMENT_INCOMPLETE"}


def t(day: float) -> datetime:
    return T0 + timedelta(days=day)


@dataclass
class Observation:
    name: str
    description: str
    expected_statuses: dict[str, str]
    observed_statuses: dict[str, str] = field(default_factory=dict)
    expected_drift: set[tuple[str, str | None]] = field(default_factory=set)
    observed_drift: set[tuple[str, str | None]] = field(default_factory=set)
    expected_direction: str | None = None
    observed_direction: str | None = None
    checks: list[tuple[str, bool]] = field(default_factory=list)
    eval_ms: list[float] = field(default_factory=list)
    risk_scores: list[float | None] = field(default_factory=list)
    deltas: list[float | None] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return (self.expected_statuses == {k: self.observed_statuses.get(k) for k in self.expected_statuses}
                and self.expected_drift == self.observed_drift
                and (self.expected_direction is None or self.expected_direction == self.observed_direction)
                and all(ok for _, ok in self.checks))


class Harness:
    def __init__(self, workdir: Path, criticality: str = "High"):
        self.cfg = load_asset_policy()
        self.model = load_risk_model()
        self.runner = OPARunner()
        self.db = Database(":memory:")
        self.db.init_schema()
        self.workdir = workdir
        self.asset = {"asset_id": "syn-asset", "criticality": criticality, "ip_address": HOST_IP, "hostname": "syn-asset"}
        register_asset(self.db, self.asset, "SYNTHETIC", iso(t(-1)))
        self.base = syn.compliant_evidence("syn-asset", iso(t(0)), self.cfg["policy_params"])
        self.last_run: int | None = None
        self._n = 0

    def assess(self, doc: dict[str, Any], obs: Observation) -> int:
        start = time.perf_counter()
        run_id = store_evidence_assessment(self.db, doc, self.runner)
        obs.eval_ms.append((time.perf_counter() - start) * 1000)
        self.last_run = run_id
        return run_id

    def scan(self, day: float, findings: list[dict[str, Any]], fmt: str = "xml") -> dict[str, Any]:
        self._n += 1
        path = self.workdir / f"scan{self._n}.{fmt}"
        if fmt == "xml":
            path.write_text(syn.greenbone_xml(f"syn-report-{self._n}", HOST_IP, iso(t(day - 0.1)), iso(t(day)), findings))
        else:
            path.write_text(syn.greenbone_csv(HOST_IP, iso(t(day)), findings))
        return import_report(self.db, path, "syn-asset", "SYNTHETIC")

    def score(self, day: float, obs: Observation) -> int:
        sid = score_asset(self.db, "syn-asset", self.model, now=t(day) + timedelta(minutes=5))
        s = self.db.get_score(sid)
        obs.risk_scores.append(s["score"])
        ev = self.db.query("SELECT direction, delta FROM risk_drift_events WHERE score_id=?", (sid,))[0]
        obs.observed_direction = ev["direction"]
        obs.deltas.append(ev["delta"])
        return sid

    def observe(self, obs: Observation) -> None:
        res = self.db.check_results(self.last_run) if self.last_run else {}
        obs.observed_statuses = {cid: r["status"] for cid, r in res.items()}
        obs.observed_drift = {(e["category"], e["check_id"]) for e in self.db.query(
            "SELECT category, check_id FROM config_drift_events") if e["category"] not in IGNORED_DRIFT}


ALL_OK = {cid: "COMPLIANT" for cid in CHECKS}


def _with(**over: str) -> dict[str, str]:
    return {**ALL_OK, **{k.replace("_", "-"): v for k, v in over.items()}}


# ---------------------------------------------------------------- scenarios
def sc_all_compliant(h: Harness) -> Observation:
    o = Observation("all_compliant", "Fully compliant host, first assessment establishes baseline", ALL_OK)
    h.scan(0, syn.SAMPLE_FINDINGS[1:])
    h.assess(h.base, o)
    h.score(0, o)
    o.expected_direction = "BASELINE"
    o.checks.append(("only BASELINE drift recorded", [e["category"] for e in h.db.query("SELECT category FROM config_drift_events")] == ["BASELINE"]))
    return o


def _violation(name: str, desc: str, cid: str, changes: dict[str, Any]) -> Callable[[Harness], Observation]:
    def run(h: Harness) -> Observation:
        o = Observation(name, desc, {**ALL_OK, cid: "NON_COMPLIANT"}, expected_drift={("NEW_NON_COMPLIANCE", cid)},
                        expected_direction="INCREASED")
        h.scan(0, syn.SAMPLE_FINDINGS[1:])
        h.assess(h.base, o)
        h.score(0, o)
        h.assess(syn.mutate(h.base, cid, ts=iso(t(1)), **changes), o)
        h.score(1, o)
        return o
    return run


def sc_file_permission(h: Harness) -> Observation:
    o = Observation("file_permission_violation", "/etc/shadow made world-readable (0644)",
                    {**ALL_OK, "FILE-001": "NON_COMPLIANT"}, expected_drift={("NEW_NON_COMPLIANCE", "FILE-001")},
                    expected_direction="INCREASED")
    h.scan(0, syn.SAMPLE_FINDINGS[1:])
    h.assess(h.base, o)
    h.score(0, o)
    files = json.loads(json.dumps(h.base["checks"]["FILE-001"]["evidence"]["files"]))
    files["/etc/shadow"].update(mode=0o644, mode_octal="0644")
    h.assess(syn.mutate(h.base, "FILE-001", ts=iso(t(1)), files=files), o)
    h.score(1, o)
    return o


def sc_remediation(h: Harness) -> Observation:
    o = Observation("remediation", "Root login violation corrected in the next assessment", ALL_OK,
                    expected_drift={("NEW_NON_COMPLIANCE", "SSH-001"), ("CORRECTED", "SSH-001")},
                    expected_direction="DECREASED")
    h.scan(0, syn.SAMPLE_FINDINGS[1:])
    h.assess(h.base, o)
    h.score(0, o)
    h.assess(syn.mutate(h.base, "SSH-001", ts=iso(t(1)), permit_root_login="yes"), o)
    h.score(1, o)
    h.assess(syn.with_time(h.base, iso(t(2))), o)
    h.score(2, o)
    return o


def sc_new_vulnerability(h: Harness) -> Observation:
    o = Observation("new_vulnerability", "Second Greenbone import adds a CVSS 9.8 finding", ALL_OK,
                    expected_direction="INCREASED")
    h.scan(0, syn.SAMPLE_FINDINGS[1:])
    h.assess(h.base, o)
    h.score(0, o)
    h.scan(1, syn.SAMPLE_FINDINGS)
    sid = h.score(1, o)
    rows = h.db.query("SELECT factor, evidence_ref FROM risk_explanations WHERE score_id=? AND kind='DRIFT'", (sid,))
    o.checks.append(("explanation cites the new finding", any(r["factor"] == "new_vulnerability" and
                                                                 (r["evidence_ref"] or "").startswith("vulnerability_findings:") for r in rows)))
    return o


def sc_missing_cvss(h: Harness) -> Observation:
    o = Observation("missing_cvss", "Imported finding without CVSS uses labelled fallback and is flagged", ALL_OK)
    f = dict(syn.SAMPLE_FINDINGS[0], severity=None, threat="High", id="nocvss")
    summary = h.scan(0, [f], fmt="csv")
    h.assess(h.base, o)
    sid = h.score(0, o)
    s = h.db.get_score(sid)
    o.checks.append(("importer counts missing CVSS", summary["missing_cvss"] == 1))
    o.checks.append(("stored CVSS is NULL (not 0)", h.db.query("SELECT cvss_score FROM vulnerability_findings")[0]["cvss_score"] is None))
    o.checks.append(("V uses label fallback, flagged estimated", s["components"]["V"]["details"]["estimated_cvss"] == 1
                     and s["v_score"] > 0))
    return o


def sc_criticality(h: Harness) -> Observation:
    o = Observation("criticality_change", "Asset criticality raised Medium -> Critical", ALL_OK,
                    expected_direction="INCREASED")
    h.db.upsert_asset("syn-asset", "Medium", changed_at=iso(t(-0.5)))
    h.scan(0, syn.SAMPLE_FINDINGS[1:])
    h.assess(h.base, o)
    h.score(0, o)
    h.db.upsert_asset("syn-asset", "Critical", changed_at=iso(t(1)))
    sid = h.score(1, o)
    rows = h.db.query("SELECT factor FROM risk_explanations WHERE score_id=? AND kind='DRIFT'", (sid,))
    o.checks.append(("explanation cites criticality change", any(r["factor"] == "criticality_change" for r in rows)))
    return o


def sc_no_change(h: Harness) -> Observation:
    o = Observation("no_meaningful_change", "Re-assessment with only timestamps, ordering and whitespace changed",
                    ALL_OK, expected_direction="UNCHANGED")
    h.scan(0, syn.SAMPLE_FINDINGS[1:])
    h.assess(h.base, o)
    h.score(0, o)
    doc = syn.with_time(h.base, iso(t(1)))
    svc = doc["checks"]["SVC-001"]["evidence"]
    svc["running_units"] = list(reversed(svc["running_units"]))
    doc["checks"]["FW-001"]["evidence"]["rules"] = ["22/tcp  |  ALLOW IN |   Anywhere"]
    doc["checks"]["SSH-001"]["evidence"]["value_origin"] = "effective (sshd -T)"
    h.assess(doc, o)
    h.score(1, o)
    return o


def sc_missing_evidence(h: Harness) -> Observation:
    o = Observation("missing_evidence_and_collector_failure",
                    "UPD-001 collector crashes and FW-001 evidence is absent",
                    {**ALL_OK, "UPD-001": "ERROR", "FW-001": "UNKNOWN"},
                    expected_drift={("MISSING_EVIDENCE", "UPD-001"), ("MISSING_EVIDENCE", "FW-001")})
    h.scan(0, syn.SAMPLE_FINDINGS[1:])
    h.assess(h.base, o)
    h.score(0, o)
    doc = syn.collector_error(syn.with_time(h.base, iso(t(1))), "UPD-001")
    doc["checks"]["FW-001"]["evidence"] = {"firewall_tool": "ufw", "installed": True, "active": None,
                                          "default_incoming": None, "method": "config_files"}
    doc["checks"]["FW-001"]["collector_status"] = "PARTIAL"
    run = h.assess(doc, o)
    sid = h.score(1, o)
    s = h.db.get_score(sid)
    o.checks.append(("run marked PARTIAL", h.db.get_run(run)["status"] == "PARTIAL"))
    o.checks.append(("score PARTIAL with widened bounds", s["status"] == "PARTIAL" and s["score_upper"] > s["score_lower"]))
    o.checks.append(("risk drift not compared across different reliability", o.observed_direction in ("INCREASED", "NOT_COMPARABLE", "BASELINE")))
    return o


def sc_stale_scan(h: Harness) -> Observation:
    o = Observation("stale_vulnerability_scan", "Latest Greenbone scan is 60 days old", ALL_OK)
    h.scan(-60, syn.SAMPLE_FINDINGS)
    h.assess(h.base, o)
    sid = h.score(0, o)
    s = h.db.get_score(sid)
    o.checks.append(("V flagged stale", bool(s["components"]["V"]["stale"])))
    o.checks.append(("score not COMPLETE", s["status"] == "PARTIAL"))
    o.checks.append(("warning mentions stale", any("stale" in w.lower() for w in s["warnings"])))
    return o


def sc_no_scan(h: Harness) -> Observation:
    o = Observation("no_vulnerability_data", "No scan imported: V must not silently become 0", ALL_OK)
    h.assess(h.base, o)
    sid = h.score(0, o)
    s = h.db.get_score(sid)
    o.checks.append(("V unavailable (NULL)", s["v_score"] is None))
    o.checks.append(("upper bound reflects possible V=100", s["score_upper"] >= s["score_lower"] + 40))
    return o


def sc_malformed_report(h: Harness) -> Observation:
    o = Observation("malformed_report", "Truncated XML, non-Greenbone CSV and XXE payload are rejected", {})
    bad = {"trunc.xml": "<report id='x'><results><result>", "other.csv": "a,b,c\n1,2,3\n",
           "xxe.xml": '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><report><results/></report>'}
    for name, text in bad.items():
        p = h.workdir / name
        p.write_text(text)
        try:
            import_report(h.db, p, "syn-asset", "SYNTHETIC")
            o.checks.append((f"{name} rejected", False))
        except ReportFormatError:
            o.checks.append((f"{name} rejected", True))
    o.checks.append(("no scan rows stored", h.db.query("SELECT COUNT(*) n FROM vulnerability_scans")[0]["n"] == 0))
    return o


def sc_database_errors(h: Harness) -> Observation:
    o = Observation("database_errors", "Duplicate import refused; failed transaction rolls back", {})
    h.scan(0, syn.SAMPLE_FINDINGS)
    try:
        import_report(h.db, h.workdir / "scan1.xml", "syn-asset", "SYNTHETIC")
        o.checks.append(("duplicate import refused", False))
    except DuplicateImportError:
        o.checks.append(("duplicate import refused", True))
    before = h.db.query("SELECT COUNT(*) n FROM vulnerability_scans")[0]["n"]
    try:
        h.db.store_scan({"asset_id": "syn-asset", "source_report_id": "rb", "source_file": "x", "file_sha256": "rb",
                         "report_format": "GREENBONE_XML", "imported_at": iso(t(0)), "data_origin": "SYNTHETIC"},
                        [{"finding_key": "k", "cvss_score": 11.0}])
        o.checks.append(("invalid CVSS rejected by schema", False))
    except DatabaseError:
        o.checks.append(("invalid CVSS rejected by schema", True))
    after = h.db.query("SELECT COUNT(*) n FROM vulnerability_scans")[0]["n"]
    o.checks.append(("partial scan rolled back", before == after))
    return o


def sc_opa_failure(h: Harness) -> Observation:
    o = Observation("policy_engine_failure", "OPA unavailable: run FAILED, never compliant", {},
                    expected_drift={("ASSESSMENT_FAILED", None)})
    h.assess(h.base, o)
    run = store_evidence_assessment(h.db, syn.with_time(h.base, iso(t(1))), None)
    h.last_run = run
    o.checks.append(("run FAILED", h.db.get_run(run)["status"] == "FAILED"))
    o.checks.append(("no check results stored", h.db.check_results(run) == {}))
    h.last_run = None
    return o


SCENARIOS: list[Callable[[Harness], Observation]] = [
    sc_all_compliant,
    _violation("ssh_root_login_violation", "PermitRootLogin changed to yes", "SSH-001", {"permit_root_login": "yes"}),
    _violation("ssh_password_auth_violation", "PasswordAuthentication enabled (e.g. cloud-init drop-in)", "SSH-002",
               {"password_authentication": "yes"}),
    _violation("firewall_disabled", "UFW disabled", "FW-001", {"active": False}),
    sc_file_permission,
    _violation("prohibited_service", "telnet socket enabled and listening", "SVC-001",
               {"running_units": ["cron", "ssh", "telnet"], "enabled_units": ["cron", "ssh", "telnet"]}),
    sc_remediation,
    sc_new_vulnerability,
    sc_missing_cvss,
    sc_criticality,
    sc_no_change,
    sc_missing_evidence,
    sc_stale_scan,
    sc_no_scan,
    sc_malformed_report,
    sc_database_errors,
    sc_opa_failure,
]


def run_all() -> list[Observation]:
    out = []
    for fn in SCENARIOS:
        with tempfile.TemporaryDirectory() as tmp:
            h = Harness(Path(tmp))
            obs = fn(h)
            h.observe(obs)
            h.db.close()
            out.append(obs)
    return out


def metrics(observations: list[Observation]) -> dict[str, Any]:
    tp = fp = fn = tn = und_ok = und_total = 0
    for o in observations:
        for cid, exp in o.expected_statuses.items():
            got = o.observed_statuses.get(cid)
            if exp in ("UNKNOWN", "ERROR"):
                und_total += 1
                und_ok += int(got == exp)
            elif exp == "NON_COMPLIANT":
                tp += int(got == "NON_COMPLIANT")
                fn += int(got != "NON_COMPLIANT")
            else:
                fp += int(got == "NON_COMPLIANT")
                tn += int(got == "COMPLIANT")
    dtp = sum(len(o.expected_drift & o.observed_drift) for o in observations)
    dfp = sum(len(o.observed_drift - o.expected_drift) for o in observations)
    dfn = sum(len(o.expected_drift - o.observed_drift) for o in observations)
    dirs = [o for o in observations if o.expected_direction]
    ms = [m for o in observations for m in o.eval_ms]
    return {
        "scenarios": len(observations), "scenarios_passed": sum(o.passed for o in observations),
        "check_tp": tp, "check_fp": fp, "check_fn": fn, "check_tn": tn,
        "check_precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "check_recall": round(tp / (tp + fn), 3) if tp + fn else None,
        "undetermined_correct": f"{und_ok}/{und_total}",
        "drift_tp": dtp, "drift_fp": dfp, "drift_fn": dfn,
        "risk_direction_correct": f"{sum(o.expected_direction == o.observed_direction for o in dirs)}/{len(dirs)}",
        "assessments_timed": len(ms),
        "mean_assessment_ms": round(sum(ms) / len(ms), 1) if ms else None,
        "max_assessment_ms": round(max(ms), 1) if ms else None,
    }


def write_results(observations: list[Observation], out_dir: Path = RESULTS_DIR) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    m = metrics(observations)
    with (out_dir / "scenario_results.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["scenario", "passed", "expected_direction", "observed_direction", "risk_scores", "deltas",
                    "status_mismatches", "drift_missing", "drift_unexpected", "failed_checks", "mean_eval_ms"])
        for o in observations:
            mism = {k: (v, o.observed_statuses.get(k)) for k, v in o.expected_statuses.items()
                    if o.observed_statuses.get(k) != v}
            w.writerow([o.name, o.passed, o.expected_direction, o.observed_direction, o.risk_scores, o.deltas, mism,
                        sorted(o.expected_drift - o.observed_drift, key=str), sorted(o.observed_drift - o.expected_drift, key=str),
                        [d for d, ok in o.checks if not ok],
                        round(sum(o.eval_ms) / len(o.eval_ms), 1) if o.eval_ms else ""])
    (out_dir / "metrics.json").write_text(json.dumps(m, indent=2))
    return m
