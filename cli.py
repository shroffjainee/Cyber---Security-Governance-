#!/usr/bin/env python3
"""Command-line entry point for the Risk Drift Framework.

Examples (run from the project directory):
  python cli.py init-db
  sudo -E python cli.py assess --asset-id ubuntu-vm-01          # live, read-only collection
  python cli.py collect --asset-id ubuntu-vm-01 --out evidence.json
  python cli.py evaluate --evidence evidence.json
  python cli.py import-greenbone --asset-id ubuntu-vm-01 --file report.xml
  python cli.py score --asset-id ubuntu-vm-01
  python cli.py set-criticality --asset-id ubuntu-vm-01 --level Critical
  python cli.py demo                                             # SYNTHETIC demo DB
  python cli.py evaluate-scenarios && python cli.py evaluate-baselines
  streamlit run app.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from core.config import DEFAULT_DB_PATH, PROJECT_ROOT, ConfigError, find_asset, load_asset_policy, load_risk_model


def _db(args):
    from storage.database import Database
    db = Database(args.db)
    db.init_schema()
    return db


def _runner():
    from policy_engine.opa_runner import OPAError, OPARunner
    try:
        return OPARunner()
    except OPAError as exc:
        print(f"WARNING: {exc} — assessment will be stored as FAILED.", file=sys.stderr)
        return None


def cmd_init_db(args) -> int:
    from assessment.pipeline import register_asset
    cfg = load_asset_policy()
    db = _db(args)
    for asset in cfg["assets"]:
        register_asset(db, asset, "HOST")
    print(f"Database ready at {args.db}; {len(cfg['assets'])} asset(s) registered.")
    return 0


def cmd_collect(args) -> int:
    from collector import collect_evidence
    from collector.common import Context
    cfg = load_asset_policy()
    find_asset(cfg, args.asset_id)
    ctx = Context(root=args.root, timeout=float(cfg["collector"]["command_timeout_seconds"]),
                  max_bytes=int(cfg["collector"]["max_file_bytes"]), policy_params=cfg["policy_params"])
    doc = collect_evidence(ctx, args.asset_id, "HOST")
    text = json.dumps(doc, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text)
        print(f"Evidence written to {args.out}")
    else:
        print(text)
    return 0


def cmd_evaluate(args) -> int:
    from collector import load_evidence
    from policy_engine.opa_runner import OPARunner
    doc = load_evidence(args.evidence)
    results = OPARunner().evaluate(doc)
    for cid, r in results.items():
        print(f"{cid:9} {r['status']:14} {r['reason']}")
    return 0


def cmd_assess(args) -> int:
    from assessment.pipeline import assess_host, register_asset, store_evidence_assessment
    from collector import load_evidence
    from risk.risk_score import score_asset
    cfg, model = load_asset_policy(), load_risk_model()
    db = _db(args)
    runner = _runner()
    if os.geteuid() != 0 and not args.evidence:
        print("NOTE: not running as root — some evidence (sshd -T, ufw status) will be unavailable and reported "
              "as limitations/UNKNOWN, never as compliant.", file=sys.stderr)
    if args.evidence:
        doc = load_evidence(args.evidence)
        if doc["asset"]["asset_id"] != args.asset_id:
            raise SystemExit("evidence asset_id does not match --asset-id")
        register_asset(db, find_asset(cfg, args.asset_id), "HOST")
        run_id = store_evidence_assessment(db, doc, runner)
        score_id = None if args.no_score else score_asset(db, args.asset_id, model)
    else:
        out = assess_host(db, cfg, args.asset_id, runner, root="/", model=None if args.no_score else model)
        run_id, score_id = out["run_id"], out.get("score_id")
    run = db.get_run(run_id)
    print(f"Run {run_id}: {run['status']} {run.get('error_message') or ''}")
    for cid, r in db.check_results(run_id).items():
        print(f"  {cid:9} {r['status']:14} {r['reason']}")
    for ev in db.drift_events_for_run(run_id):
        print(f"  DRIFT {ev['category']:22} {ev['priority']:8} {ev['explanation'][:120]}")
    if score_id:
        s = db.get_score(score_id)
        print(f"Risk score: {s['score']} ({s['status']}, band {s['band']}, bounds {s['score_lower']}-{s['score_upper']})")
        for w in s["warnings"]:
            print(f"  ! {w}")
    return 0 if run["status"] != "FAILED" else 2


def cmd_import(args) -> int:
    from risk.risk_score import score_asset
    from storage.database import DuplicateImportError
    from vulnerability.greenbone_importer import ReportFormatError, import_report
    db = _db(args)
    try:
        summary = import_report(db, args.file, args.asset_id, "SYNTHETIC" if args.synthetic else "HOST",
                                filter_by_asset_host=not args.no_host_filter)
    except (ReportFormatError, DuplicateImportError, ValueError) as exc:
        print(f"Import failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2))
    if not args.no_score:
        sid = score_asset(db, args.asset_id, load_risk_model())
        s = db.get_score(sid)
        print(f"Risk score: {s['score']} ({s['status']})")
    return 0


def cmd_score(args) -> int:
    from risk.risk_score import score_asset
    db = _db(args)
    sid = score_asset(db, args.asset_id, load_risk_model())
    s = db.get_score(sid)
    print(json.dumps({k: s[k] for k in ("score_id", "status", "score", "score_lower", "score_upper", "band",
                                        "v_score", "c_score", "d_score", "a_score", "warnings")}, indent=2))
    return 0


def cmd_set_criticality(args) -> int:
    db = _db(args)
    if db.get_asset(args.asset_id) is None:
        raise SystemExit("unknown asset; run init-db first")
    db.upsert_asset(args.asset_id, args.level)
    print(f"{args.asset_id} criticality set to {args.level} (also update config/asset_policy.json to keep it).")
    return 0


def cmd_demo(args) -> int:
    from evaluation.demo import build_demo
    build_demo(args.db)
    print(f"SYNTHETIC demonstration database written to {args.db}\n"
          f"View it with:  RDF_DB={args.db} streamlit run app.py")
    return 0


def cmd_build_site(args) -> int:
    from dashboard.export import build_site
    out = build_site(args.db, args.out)
    print(f"Web console written to {out} (open it in a browser, or publish the folder with GitHub Pages)")
    return 0


def cmd_monitor(args) -> int:
    """Continuous compliance monitoring: re-assess every --interval seconds (Ctrl+C to stop)."""
    import time
    n = 0
    print(f"Continuous monitoring of {args.asset_id} every {args.interval}s "
          f"({'until stopped' if not args.count else f'{args.count} cycles'}); DB {args.db}")
    try:
        while True:
            n += 1
            print(f"\n--- cycle {n} ---")
            rc = cmd_assess(argparse.Namespace(db=args.db, asset_id=args.asset_id, evidence=None, no_score=False))
            if rc == 2:
                print("Assessment FAILED in this cycle (stored as FAILED); monitoring continues.", file=sys.stderr)
            if args.count and n >= args.count:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")
    return 0


def cmd_lab_report(args) -> int:
    from evaluation.lab_experiment import analyse, write
    if not Path(args.db).exists():
        print(f"lab-report: database {args.db} not found - run `sudo bash lab/drift_experiment.sh all` first",
              file=sys.stderr)
        return 2
    try:
        res = analyse(args.db, args.asset_id)
    except ValueError as exc:
        print(f"lab-report: {exc}", file=sys.stderr)
        return 2
    write(res)
    print((PROJECT_ROOT / "evaluation" / "results" / "lab_experiment.md").read_text())
    return 0


def cmd_figures(args) -> int:
    from evaluation.figures import build_all
    for path in build_all(args.db, args.lab_db, args.out):
        print(f"  wrote {path}")
    return 0


def cmd_eval_scenarios(args) -> int:
    from evaluation.scenarios import run_all, write_results
    obs = run_all()
    m = write_results(obs)
    for o in obs:
        print(f"{'PASS' if o.passed else 'FAIL'}  {o.name}")
    print(json.dumps(m, indent=2))
    return 0 if m["scenarios_passed"] == m["scenarios"] else 1


def cmd_eval_baselines(args) -> int:
    from evaluation.baselines import run_comparison
    res = run_comparison()
    print((PROJECT_ROOT / "evaluation" / "results" / "baseline_comparison.md").read_text())
    return 0 if res else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Continuous Compliance Monitoring & Risk Drift Detection Framework")
    p.add_argument("--db", default=os.environ.get("RDF_DB", str(DEFAULT_DB_PATH)), help="SQLite database path")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db").set_defaults(fn=cmd_init_db)
    s = sub.add_parser("collect")
    s.add_argument("--asset-id", required=True)
    s.add_argument("--out")
    s.add_argument("--root", default="/", help="filesystem root (fixtures/testing only)")
    s.set_defaults(fn=cmd_collect)
    s = sub.add_parser("evaluate")
    s.add_argument("--evidence", required=True)
    s.set_defaults(fn=cmd_evaluate)
    s = sub.add_parser("assess")
    s.add_argument("--asset-id", required=True)
    s.add_argument("--evidence", help="use a previously collected evidence file instead of collecting")
    s.add_argument("--no-score", action="store_true")
    s.set_defaults(fn=cmd_assess)
    s = sub.add_parser("import-greenbone")
    s.add_argument("--asset-id", required=True)
    s.add_argument("--file", required=True)
    s.add_argument("--synthetic", action="store_true", help="label the import as SYNTHETIC test data")
    s.add_argument("--no-host-filter", action="store_true", help="attribute findings for all hosts to this asset")
    s.add_argument("--no-score", action="store_true")
    s.set_defaults(fn=cmd_import)
    s = sub.add_parser("score")
    s.add_argument("--asset-id", required=True)
    s.set_defaults(fn=cmd_score)
    s = sub.add_parser("set-criticality")
    s.add_argument("--asset-id", required=True)
    s.add_argument("--level", required=True, choices=["Low", "Medium", "High", "Critical"])
    s.set_defaults(fn=cmd_set_criticality)
    s = sub.add_parser("demo")
    s.set_defaults(fn=cmd_demo, db_override=True)
    s = sub.add_parser("build-site", help="export the database as a static web console (docs/index.html)")
    s.add_argument("--out", default=str(PROJECT_ROOT / "docs" / "index.html"))
    s.set_defaults(fn=cmd_build_site)
    s = sub.add_parser("monitor", help="continuous monitoring: assess repeatedly at a fixed interval")
    s.add_argument("--asset-id", required=True)
    s.add_argument("--interval", type=int, default=3600, help="seconds between assessments (default 3600)")
    s.add_argument("--count", type=int, default=0, help="stop after N cycles (0 = run until Ctrl+C)")
    s.set_defaults(fn=cmd_monitor)
    s = sub.add_parser("lab-report", help="analyse the controlled lab drift experiment (real host runs)")
    s.add_argument("--asset-id", default="lab-ubuntu-container")
    s.set_defaults(fn=cmd_lab_report)
    s = sub.add_parser("figures", help="generate research-paper figures (PNG) from stored results")
    s.add_argument("--lab-db", default=str(PROJECT_ROOT / "data" / "real_lab.sqlite3"))
    s.add_argument("--out", default=str(PROJECT_ROOT / "figures"))
    s.set_defaults(fn=cmd_figures)
    sub.add_parser("evaluate-scenarios").set_defaults(fn=cmd_eval_scenarios)
    sub.add_parser("evaluate-baselines").set_defaults(fn=cmd_eval_baselines)
    args = p.parse_args(argv)
    if args.cmd == "demo" and "--db" not in (argv or sys.argv):
        args.db = str(PROJECT_ROOT / "data" / "demo_synthetic.sqlite3")
    try:
        return args.fn(args)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
