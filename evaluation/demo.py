"""Populate a separate SYNTHETIC demonstration database for the dashboard.

Every asset, run, scan and score created here has data_origin='SYNTHETIC'
and asset ids prefixed 'syn-'.  The dashboard labels them as synthetic.
Use a different database file from your real assessments (default:
data/demo_synthetic.sqlite3).
"""
from __future__ import annotations

import tempfile
from datetime import timedelta
from pathlib import Path

from assessment.pipeline import register_asset, store_evidence_assessment
from core.config import load_asset_policy, load_risk_model
from core.timeutil import iso
from evaluation import synthetic as syn
from evaluation.baselines import MED, build_portfolio
from core.timeutil import utc_now
from policy_engine.opa_runner import OPARunner
from risk.risk_score import score_asset
from storage.database import Database
from vulnerability.greenbone_importer import import_report


def build_demo(db_path: str | Path) -> None:
    db_path = Path(db_path)
    if db_path.exists():
        db_path.unlink()
    db = Database(db_path)
    db.init_schema()
    cfg, model, runner = load_asset_policy(), load_risk_model(), OPARunner()
    # Demo timeline ends today so the dashboard shows current (not stale) synthetic data.
    anchor = utc_now().replace(hour=8, minute=0, second=0) - timedelta(days=13)

    def t(day: float):
        return anchor + timedelta(days=day)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        build_portfolio(db, work, tf=lambda d: t(d + 11))
        aid, ip = "syn-timeline", "10.99.1.1"
        register_asset(db, {"asset_id": aid, "criticality": "Medium", "ip_address": ip,
                            "description": "SYNTHETIC timeline for dashboard demonstration"}, "SYNTHETIC", iso(t(-1)))
        base = syn.compliant_evidence(aid, iso(t(0)), cfg["policy_params"])

        def scan(day: float, findings: list) -> None:
            p = work / f"tl-{day}.xml"
            p.write_text(syn.greenbone_xml(f"syn-tl-{day}", ip, iso(t(day - 0.1)), iso(t(day)), findings))
            import_report(db, p, aid, "SYNTHETIC")

        def step(day: float, doc=None) -> None:
            if doc is not None:
                store_evidence_assessment(db, syn.with_time(doc, iso(t(day))), runner)
            score_asset(db, aid, model, now=t(day) + timedelta(minutes=5))

        scan(0, [syn.SAMPLE_FINDINGS[2]])
        step(0, base)                                                         # baseline
        step(2, syn.mutate(base, "SSH-002", password_authentication="yes"))   # drift: password auth
        scan(4, [syn.SAMPLE_FINDINGS[2], MED, syn.SAMPLE_FINDINGS[0]])       # new critical vuln
        step(4)
        fw_off = syn.mutate(syn.mutate(base, "SSH-002", password_authentication="yes"), "FW-001", active=False)
        step(6, fw_off)                                                       # firewall disabled
        step(8, base)                                                         # remediation of both
        db.upsert_asset(aid, "Critical", changed_at=iso(t(9)))                # criticality raised
        step(9)
        scan(11, [syn.SAMPLE_FINDINGS[2]])                                    # vuln patched
        step(11)
        step(12, syn.collector_error(base, "UPD-001"))                        # collector failure
    db.close()
