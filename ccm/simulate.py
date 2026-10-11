"""Scenario simulator for a small enterprise (weekly scans).

Why a simulator: real organisations do not share time-series of their
vulnerabilities and misconfigurations, and an M.Tech student cannot wait months
for real incidents. The simulator produces evidence in EXACTLY the same tables
and formats as the real collectors (OpenSCAP rule results, config values,
CVE/EPSS records), and additionally records every injected event as labelled
ground truth so that detection and prioritisation can be measured.

Ground truth labelling (fixed by the scenario design, independent of the
scoring formula):
  sev_class 3 = high, 2 = medium, 1 = low
  harmful   = sev_class >= 2
  config event   -> sev_class from the control's severity
  CVE event      -> high if CVSS>=9 and EPSS>=0.3; medium if CVSS>=7 and EPSS>=0.1; else low
  certificate    -> expired/untrusted = high, expiring/weak key = medium
  operational setting change -> low (not harmful)
  business value(asset) = criticality x 1.5 (if public) x 1.2 (if regulated)
  GT priority(asset, t) = sum over active harmful events of sev_class x value
"""
import numpy as np
import pandas as pd

from .catalog import CONFIG_ITEMS, CERT_RULES, bad_value

SEV = {"high": 3, "medium": 2, "low": 1}

ASSET_TEMPLATES = [
    # role, criticality, exposure, regulated, count
    ("payment-gateway", 5, "public", 1, 2),
    ("customer-web-app", 4, "public", 0, 3),
    ("public-api", 4, "public", 0, 2),
    ("vpn-gateway", 5, "public", 0, 1),
    ("core-database", 5, "internal", 1, 2),
    ("hr-portal", 3, "internal", 1, 2),
    ("log-server", 3, "internal", 0, 1),
    ("build-server", 3, "internal", 0, 1),
    ("internal-wiki", 2, "internal", 0, 3),
    ("dev-test-box", 1, "internal", 0, 3),
]

P = dict(control_disabled=0.035, control_weakened_low=0.05, unmanaged_drift=0.025,
         cve=0.06, cert=0.03, operational=0.10)
FIX = dict(config=0.35, unmanaged=0.30, cve=0.30, cert=0.40, benign=0.30)

RULE_ITEMS = [k for k, v in CONFIG_ITEMS.items() if v["rule"]]
HM_RULE_ITEMS = [k for k in RULE_ITEMS if CONFIG_ITEMS[k]["severity"] in ("high", "medium")]
LOW_RULE_ITEMS = [k for k in RULE_ITEMS if CONFIG_ITEMS[k]["severity"] == "low"]
UNMANAGED = [k for k, v in CONFIG_ITEMS.items() if v["rule"] is None and v["security"]]
OPERATIONAL = [k for k, v in CONFIG_ITEMS.items() if not v["security"]]


def make_assets():
    rows = []
    for role, crit, exp, reg, n in ASSET_TEMPLATES:
        for i in range(1, n + 1):
            rows.append(dict(asset_id=f"{role}-{i:02d}", label=f"{role}-{i:02d}", role=role,
                             criticality=crit, exposure=exp, regulated=reg))
    return pd.DataFrame(rows)


def business_value(a):
    return a["criticality"] * (1.5 if a["exposure"] == "public" else 1.0) * (1.2 if a["regulated"] else 1.0)


def _cve_draw(rng):
    u = rng.random()
    if u < 0.30:   # actively-exploitable critical
        return round(rng.uniform(8.8, 9.8), 1), round(rng.uniform(0.30, 0.95), 3)
    if u < 0.70:   # serious, moderate exploitation likelihood
        return round(rng.uniform(7.0, 8.7), 1), round(rng.uniform(0.10, 0.30), 3)
    return round(rng.uniform(5.0, 7.8), 1), round(rng.uniform(0.001, 0.05), 3)  # high CVSS, rarely exploited


def _cve_sev(cvss, epss):
    if cvss >= 9.0 and epss >= 0.3:
        return 3
    if cvss >= 7.0 and epss >= 0.1:
        return 2
    return 1


def simulate(seed, n_periods=16):
    rng = np.random.default_rng(seed)
    run_id = f"sim-{seed}"
    assets = make_assets()
    events = []
    ev_n = 0

    # onboarding state: hardened baseline with a few accepted pre-existing gaps
    pre_dev, bg_vulns, vuln_n = {}, {}, 0
    for _, a in assets.iterrows():
        aid = a["asset_id"]
        # only LOW-severity exceptions are accepted at onboarding; medium/high
        # gaps would be real (unlabelled) problems, so the baseline starts clean
        pre_dev[aid] = {k for k in LOW_RULE_ITEMS if rng.random() < 0.15}
        bg_vulns[aid] = []
        for _ in range(rng.integers(0, 4)):
            vuln_n += 1
            bg_vulns[aid].append((f"SIM-CVE-{vuln_n:05d}", round(rng.uniform(3.5, 6.9), 1),
                                  round(rng.uniform(0.0005, 0.03), 4)))

    # schedule events (start at period >= 1, remediation is random)
    def add(aid, kind, start, fix_p, sev, payload, desc):
        nonlocal ev_n
        end = start
        while end + 1 < n_periods and rng.random() > fix_p:
            end += 1
        ev_n += 1
        events.append(dict(run_id=run_id, event_id=f"E{ev_n:04d}", asset_id=aid, kind=kind, start=start,
                           end=end, sev_class=sev, harmful=int(sev >= 2), description=desc,
                           payload=payload))

    for _, a in assets.iterrows():
        aid = a["asset_id"]
        for t in range(1, n_periods):
            if rng.random() < P["control_disabled"]:
                it = HM_RULE_ITEMS[rng.integers(len(HM_RULE_ITEMS))]
                add(aid, "control-disabled", t, FIX["config"], SEV[CONFIG_ITEMS[it]["severity"]],
                    ("config", it), f"{it} changed to {bad_value(it)}")
            if rng.random() < P["control_weakened_low"]:
                it = LOW_RULE_ITEMS[rng.integers(len(LOW_RULE_ITEMS))]
                add(aid, "minor-control-change", t, FIX["benign"], 1, ("config", it),
                    f"{it} changed to {bad_value(it)}")
            if rng.random() < P["unmanaged_drift"]:
                it = UNMANAGED[rng.integers(len(UNMANAGED))]
                add(aid, "unmanaged-drift", t, FIX["unmanaged"], SEV[CONFIG_ITEMS[it]["severity"]],
                    ("config", it), f"{it} detected (not covered by any OpenSCAP rule)")
            if rng.random() < P["cve"]:
                cvss, epss = _cve_draw(rng)
                vuln_n += 1
                vid = f"SIM-CVE-{vuln_n:05d}"
                add(aid, "cve-disclosed", t, FIX["cve"], _cve_sev(cvss, epss), ("vuln", (vid, cvss, epss)),
                    f"{vid} CVSS {cvss} EPSS {epss}")
            if a["exposure"] == "public" and rng.random() < P["cert"]:
                rule = list(CERT_RULES)[rng.integers(len(CERT_RULES))]
                add(aid, "certificate-issue", t, FIX["cert"], SEV[CERT_RULES[rule]["severity"]],
                    ("cert", rule), f"TLS control {rule} failing")
            if rng.random() < P["operational"]:
                it = OPERATIONAL[rng.integers(len(OPERATIONAL))]
                add(aid, "operational-change", t, FIX["benign"], 1, ("config", it),
                    f"{it} changed (operational, not security)")

    # materialise evidence tables
    comp_rows, conf_rows, vuln_rows = [], [], []
    by_asset = {}
    for e in events:
        by_asset.setdefault(e["asset_id"], []).append(e)
    for _, a in assets.iterrows():
        aid = a["asset_id"]
        public = a["exposure"] == "public"
        for t in range(n_periods):
            active = [e for e in by_asset.get(aid, []) if e["start"] <= t <= e["end"]]
            dev_items = set(pre_dev[aid])
            failing_cert = set()
            open_v = list(bg_vulns[aid])
            for e in active:
                kind, val = e["payload"]
                if kind == "config":
                    dev_items.add(val)
                elif kind == "cert":
                    failing_cert.add(val)
                else:
                    open_v.append(val)
            for item, meta in CONFIG_ITEMS.items():
                dev = item in dev_items
                conf_rows.append((run_id, t, aid, item, bad_value(item) if dev else meta["baseline"],
                                  meta["baseline"], int(dev), int(meta["security"]), meta["severity"]))
                if meta["rule"]:
                    comp_rows.append((run_id, t, aid, meta["rule"], meta["severity"], "fail" if dev else "pass"))
            if public:
                for rule, meta in CERT_RULES.items():
                    comp_rows.append((run_id, t, aid, rule, meta["severity"],
                                      "fail" if rule in failing_cert else "pass"))
            for vid, cvss, epss in open_v:
                vuln_rows.append((run_id, t, aid, vid, cvss, epss, "open"))

    compliance = pd.DataFrame(comp_rows, columns=["run_id", "period", "asset_id", "rule_id", "severity", "result"])
    config = pd.DataFrame(conf_rows, columns=["run_id", "period", "asset_id", "item", "value", "baseline",
                                              "deviates", "security", "severity"])
    vulns = pd.DataFrame(vuln_rows, columns=["run_id", "period", "asset_id", "vuln_id", "cvss", "epss", "status"])
    ev = pd.DataFrame(events).drop(columns=["payload"]) if events else pd.DataFrame(
        columns=["run_id", "event_id", "asset_id", "kind", "start", "end", "sev_class", "harmful", "description"])
    scans = pd.DataFrame({"run_id": run_id, "period": range(n_periods),
                          "ts": [f"week-{t:02d}" for t in range(n_periods)]})
    return dict(run_id=run_id, assets=assets, compliance=compliance, config=config, vulns=vulns,
                events=ev, scans=scans)


def ground_truth(assets, events, n_periods):
    """Per (asset, period): harmful_active flag and GT priority."""
    val = {r["asset_id"]: business_value(r) for _, r in assets.iterrows()}
    rows = []
    for aid in assets["asset_id"]:
        ev = events[(events["asset_id"] == aid) & (events["harmful"] == 1)]
        for t in range(n_periods):
            act = ev[(ev["start"] <= t) & (ev["end"] >= t)]
            rows.append((aid, t, int(len(act) > 0), float((act["sev_class"] * val[aid]).sum())))
    return pd.DataFrame(rows, columns=["asset_id", "period", "gt_harmful", "gt_priority"])
