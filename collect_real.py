"""Collect ONE real scan of this Ubuntu machine and update risk drift.

Run once per day/week (manually or via cron):

    sudo -E python3 collect_real.py --criticality 4 --exposure public

Each run = one period. After two or more runs, Risk Drift(t) is available.
Options:
    --skip-oscap / --oscap-results FILE   use an existing OpenSCAP results XML
    --skip-trivy / --vuln-csv FILE / --openvas-csv FILE
    --tls host:port (repeatable)          TLS certificate checks
"""
import argparse
import datetime as dt
import socket
import sys

import pandas as pd

from ccm import ROOT, db, load_config
from ccm.collectors import certs, drift, openscap, vulns
from ccm.privacy import pseudonym
from ccm.risk import score_run

RUN_ID = "real"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--asset-name", default=socket.gethostname())
    ap.add_argument("--role", default="server")
    ap.add_argument("--criticality", type=int, default=3, choices=range(1, 6))
    ap.add_argument("--exposure", default="internal", choices=["internal", "public"])
    ap.add_argument("--regulated", action="store_true")
    ap.add_argument("--db", default=str(ROOT / "data" / "real.db"))
    ap.add_argument("--skip-oscap", action="store_true")
    ap.add_argument("--oscap-results")
    ap.add_argument("--skip-trivy", action="store_true")
    ap.add_argument("--vuln-csv")
    ap.add_argument("--openvas-csv")
    ap.add_argument("--tls", action="append", default=[])
    ap.add_argument("--no-epss", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    rm = cfg["real_mode"]
    con = db.connect(args.db)
    workdir = ROOT / "data" / "scans"
    workdir.mkdir(parents=True, exist_ok=True)

    aid = pseudonym(args.asset_name, cfg["privacy"]["secret_env_var"]) \
        if cfg["privacy"]["pseudonymize_hostnames"] else args.asset_name
    con.execute("INSERT OR REPLACE INTO assets VALUES (?,?,?,?,?,?)",
                (aid, aid, args.role, args.criticality, args.exposure, int(args.regulated)))
    prev = con.execute("SELECT MAX(period) FROM scans WHERE run_id=?", (RUN_ID,)).fetchone()[0]
    period = 0 if prev is None else prev + 1
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    print(f"Asset {aid} (pseudonymised)  period {period}")

    comp_rows = []
    if args.oscap_results:
        comp_rows = openscap.parse_results(args.oscap_results)
    elif not args.skip_oscap:
        xml = workdir / f"oscap-{stamp}.xml"
        try:
            openscap.run_oscap(rm["openscap_datastream"], rm["openscap_profile"], xml)
            comp_rows = openscap.parse_results(xml)
        except RuntimeError as e:
            print(f"[warn] OpenSCAP skipped: {e}")
    print(f"  OpenSCAP rules evaluated: {len(comp_rows)}  failed: {sum(r['result']=='fail' for r in comp_rows)}")

    tls_targets = args.tls or (rm["tls_targets"] if args.exposure == "public" else [])
    for t in tls_targets:
        try:
            rows, info = certs.check(t)
            comp_rows += rows
            print(f"  TLS {info['target']}: {info['days_left']} days left, trusted={info['trusted']}, {info['key']}")
        except Exception as e:
            print(f"[warn] TLS check {t} failed: {e}")

    conf_rows = drift.collect(ROOT / "data" / "real_baseline.json")
    print(f"  Security settings deviating: "
          f"{sum(r['deviates'] for r in conf_rows if r['security'])} -> "
          f"{[r['item'] for r in conf_rows if r['security'] and r['deviates']]}")

    v_rows = []
    if args.vuln_csv:
        v_rows = vulns.parse_generic_csv(args.vuln_csv)
    elif args.openvas_csv:
        v_rows = vulns.parse_openvas_csv(args.openvas_csv)
    elif not args.skip_trivy and rm.get("trivy_enabled", True):
        out = workdir / f"trivy-{stamp}.json"
        try:
            vulns.run_trivy(out)
            v_rows = vulns.parse_trivy(out)
        except Exception as e:
            print(f"[warn] Trivy skipped: {e}")
    if v_rows and not args.no_epss:
        v_rows = vulns.enrich_epss(v_rows)
    print(f"  Open vulnerabilities: {len(v_rows)}")

    def frame(rows, cols):
        df = pd.DataFrame(rows, columns=cols) if rows else pd.DataFrame(columns=cols)
        df.insert(0, "asset_id", aid)
        df.insert(0, "period", period)
        df.insert(0, "run_id", RUN_ID)
        return df

    db.write(con, "scans", pd.DataFrame([dict(run_id=RUN_ID, period=period, ts=dt.datetime.now().isoformat())]))
    db.write(con, "compliance", frame(comp_rows, ["rule_id", "severity", "result"]))
    db.write(con, "config", frame(conf_rows, ["item", "value", "baseline", "deviates", "security", "severity"]))
    db.write(con, "vulns", frame(v_rows, ["vuln_id", "cvss", "epss", "status"]))
    con.commit()

    # rescore the whole history so drift is consistent
    assets = db.read(con, "assets")
    comp, conf, vul = (db.read(con, t, RUN_ID) for t in ("compliance", "config", "vulns"))
    scores = score_run(assets, comp, conf, vul, cfg, RUN_ID)
    db.clear_scores(con, RUN_ID)
    db.write(con, "scores", scores)
    con.commit()
    last = scores[(scores.method == "P_full") & (scores.asset_id == aid)].sort_values("period").iloc[-1]
    print(f"\nRisk(t) = {last.risk:.1f}   Risk Drift(t) = {last.drift:+.1f}   trend = {last.trend}"
          f"   alert = {'YES (' + last.alert_reason + ')' if last.alert else 'no'}")
    print(f"Saved to {args.db}. Open the dashboard: streamlit run app.py")


if __name__ == "__main__":
    sys.exit(main())
