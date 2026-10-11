"""Risk scoring and risk-drift detection.

Proposed method (Phase-II contribution)
---------------------------------------
For every asset a and scan period t:

  C(a,t) = 1 - (1 - Ckey)(1 - h*H)
           Ckey = 1 - exp(-k * sum of severity weights of FAILED key-control rules)
           H    = weighted share of all other (hygiene) rules that fail
  D(a,t) = 1 - exp(-k * sum of severity weights of DEVIATING security settings)
           (includes settings no OpenSCAP rule covers -> "unmanaged drift")
  V(a,t) = 1 - prod_i (1 - (CVSS_i/10) * (f + (1-f) * EPSS_i))   over open vulns

  T(a,t)   = wC*C + wD*D + wV*V                        technical score, 0..1
  ctx(a)   = (b + g*criticality/5) * public_mult * regulated_mult
  Risk(a,t)= min(100, 100 * T * ctx)

  RiskDrift(t)      = Risk(t) - Risk(t-1)               (Phase-I, Eq. 3.1)
  CumDrift_w(t)     = Risk(t) - Risk(t-w)              (catches slow creep)

Alert logic (temporal, with persistence):
  open an alert when RiskDrift >= theta, CumDrift >= theta_cum, or Risk >= high;
  keep it open until Risk returns to within theta/2 of the pre-alert reference.
  So a partial fix (risk falls but the asset is still worse than before) keeps
  the asset flagged as "improving - unresolved" instead of dropping it early.

Comparison methods
------------------
  B0_compliance_only  : base paper style (Moric et al., 2026) - OpenSCAP compliance
                        monitoring; alerts on new failed rules / low score.
  B1_compliance_cvss  : B0 plus a point-in-time vulnerability scanner (CVSS >= 7).
  P_no_context        : proposed, but every asset treated the same (ablation).
  P_no_temporal       : proposed score, static "Risk >= high" alert only (ablation).
  P_full              : proposed framework.
"""
import math

import numpy as np
import pandas as pd

from .catalog import KEY_RULES

METHODS = ["B0_compliance_only", "B1_compliance_cvss", "P_no_context", "P_no_temporal", "P_full"]
METHOD_LABELS = {
    "B0_compliance_only": "Base paper (compliance only)",
    "B1_compliance_cvss": "Compliance + CVSS scanner",
    "P_no_context": "Proposed without context",
    "P_no_temporal": "Proposed without temporal logic",
    "P_full": "Proposed risk-drift framework",
}


def _sat(x, k):
    return 1.0 - math.exp(-k * x)


def context_factor(asset, cfg):
    c = cfg["context"]
    f = c["base"] + c["criticality_gain"] * float(asset["criticality"]) / 5.0
    if asset["exposure"] == "public":
        f *= c["public_exposure_multiplier"]
    if int(asset["regulated"]):
        f *= c["regulated_multiplier"]
    return f


def evidence_features(compliance, config, vulns, cfg):
    """Aggregate raw evidence into one row per (period, asset_id)."""
    w = cfg["severity_weight"]
    k = cfg["saturation_k"]

    keys = pd.concat([d[["period", "asset_id"]] for d in (compliance, config, vulns) if len(d)])
    idx = pd.MultiIndex.from_frame(keys.drop_duplicates().sort_values(["period", "asset_id"]))
    f = pd.DataFrame(index=idx)

    comp = compliance.copy()
    comp["w"] = comp["severity"].map(w).fillna(w["low"])
    comp["failed"] = (comp["result"] == "fail").astype(int)
    comp["key"] = comp["rule_id"].isin(KEY_RULES) | (comp["severity"] == "high")
    comp["fw"] = comp["w"] * comp["failed"]
    comp["fw_key"] = comp["fw"] * comp["key"]
    comp["fw_hyg"] = comp["fw"] * (~comp["key"])
    comp["w_hyg"] = comp["w"] * (~comp["key"])
    g = comp.groupby(["period", "asset_id"])
    f["failed_w"] = g["fw"].sum()
    f["failed_w_key"] = g["fw_key"].sum()
    hyg_total = g["w_hyg"].sum()
    f["hygiene"] = (g["fw_hyg"].sum() / hyg_total.where(hyg_total > 0)).fillna(0.0)
    f[["failed_w_key", "hygiene"]] = f[["failed_w_key", "hygiene"]].fillna(0.0)
    f["n_rules"] = g["rule_id"].count()
    f["n_failed"] = g["failed"].sum()
    f[["failed_w", "n_failed"]] = f[["failed_w", "n_failed"]].fillna(0.0)
    f["compliance_score"] = (100.0 * (1 - f["n_failed"] / f["n_rules"])).fillna(100.0)
    failed_sets = comp[comp["failed"] == 1].groupby(["period", "asset_id"])["rule_id"].apply(frozenset)
    f["failed_set"] = failed_sets
    f["failed_set"] = f["failed_set"].apply(lambda s: s if isinstance(s, frozenset) else frozenset())

    conf = config[(config["security"] == 1) & (config["deviates"] == 1)].copy()
    conf["w"] = conf["severity"].map(w)
    dsum = conf.groupby(["period", "asset_id"])["w"].sum()
    f["drift_w"] = dsum
    f["drift_w"] = f["drift_w"].fillna(0.0)

    v = vulns[vulns["status"] == "open"].copy()
    floor = cfg["epss_floor"]
    v["epss"] = v["epss"].fillna(cfg["default_epss_if_unknown"])
    v["s"] = (v["cvss"] / 10.0).clip(0, 1) * (floor + (1 - floor) * v["epss"].clip(0, 1))
    vg = v.groupby(["period", "asset_id"])
    f["V"] = vg["s"].apply(lambda s: 1.0 - float(np.prod(1.0 - s.values)))
    f["max_cvss"] = vg["cvss"].max()
    f["cvss_set"] = v[v["cvss"] >= cfg["baseline"]["cvss_alert_threshold"]].groupby(
        ["period", "asset_id"])["vuln_id"].apply(frozenset)
    f["V"] = f["V"].fillna(0.0)
    f["max_cvss"] = f["max_cvss"].fillna(0.0)
    f["cvss_set"] = f["cvss_set"].apply(lambda s: s if isinstance(s, frozenset) else frozenset())

    c_key = f["failed_w_key"].apply(lambda x: _sat(x, k))
    f["C"] = 1.0 - (1.0 - c_key) * (1.0 - cfg.get("hygiene_weight", 0.3) * f["hygiene"])
    f["D"] = f["drift_w"].apply(lambda x: _sat(x, k))
    return f.reset_index()


def _temporal_alerts(risk, cfg):
    """Risk-drift alert logic for one asset (risk is a list ordered by period)."""
    theta = cfg["drift_threshold"]
    theta_cum = cfg["cumulative_threshold"]
    high = cfg["high_risk_threshold"]
    w = cfg["cumulative_window"]
    out = []
    ref = risk[0]
    is_open = risk[0] >= high
    for t, r in enumerate(risk):
        drift = 0.0 if t == 0 else r - risk[t - 1]
        cum = 0.0 if t == 0 else r - risk[max(0, t - w)]
        reason = "high-risk-at-onboarding" if (t == 0 and is_open) else ""
        if t > 0:
            triggers = []
            if drift >= theta:
                triggers.append("drift")
            if cum >= theta_cum:
                triggers.append("cumulative")
            if r >= high:
                triggers.append("high-risk")
            if not is_open and triggers:
                is_open = True
                reason = "+".join(triggers)
            elif is_open:
                if r <= ref + theta / 2 and r < high:
                    is_open = False
                    ref = r
                else:
                    reason = "+".join(triggers) if triggers else "unresolved"
            else:
                ref = r
        trend = "rising" if drift >= theta else ("falling" if drift <= -theta else "stable")
        if is_open and trend == "falling":
            trend = "improving-unresolved"
        out.append((drift, cum, trend, int(is_open), reason, r + 0.5 * max(0.0, cum)))
    return out


def score_run(assets, compliance, config, vulns, cfg, run_id, methods=METHODS):
    feats = evidence_features(compliance, config, vulns, cfg)
    tw = cfg["technical_weights"]
    feats["T"] = tw["compliance"] * feats["C"] + tw["drift"] * feats["D"] + tw["vulnerability"] * feats["V"]
    amap = assets.set_index("asset_id").to_dict("index")
    rows = []
    for aid, grp in feats.groupby("asset_id"):
        grp = grp.sort_values("period").reset_index(drop=True)
        a = amap[aid]
        ctx = context_factor(a, cfg)
        periods = grp["period"].tolist()
        base_failed = grp.loc[0, "failed_set"]
        base_cvss = grp.loc[0, "cvss_set"]

        for m in methods:
            if m.startswith("P_"):
                c = 1.0 if m == "P_no_context" else ctx
                risk = (100.0 * grp["T"] * c).clip(upper=100.0).tolist()
                if m == "P_no_temporal":
                    res = []
                    for t, r in enumerate(risk):
                        d = 0.0 if t == 0 else r - risk[t - 1]
                        trend = "rising" if d >= cfg["drift_threshold"] else (
                            "falling" if d <= -cfg["drift_threshold"] else "stable")
                        al = int(r >= cfg["high_risk_threshold"])
                        res.append((d, 0.0, trend, al, "high-risk" if al else "", r))
                else:
                    res = _temporal_alerts(risk, cfg)
                for i, t in enumerate(periods):
                    d, cum, trend, al, reason, prio = res[i]
                    rows.append((run_id, t, aid, m, grp.loc[i, "C"], grp.loc[i, "D"], grp.loc[i, "V"], c,
                                 risk[i], d, cum, trend, al, reason, prio))
            else:
                prev_score = None
                for i, t in enumerate(periods):
                    score = grp.loc[i, "compliance_score"]
                    new_fail = grp.loc[i, "failed_set"] - base_failed
                    reasons = []
                    if i > 0 and cfg["baseline"]["alert_on_new_failed_rule"] and new_fail:
                        reasons.append("new-failed-rule")
                    if score < cfg["baseline"]["low_score_threshold"]:
                        reasons.append("low-score")
                    prio = grp.loc[i, "failed_w"]
                    if m == "B1_compliance_cvss":
                        new_cvss = grp.loc[i, "cvss_set"] - base_cvss
                        if i > 0 and new_cvss:
                            reasons.append("cvss>=7")
                        prio = prio + grp.loc[i, "max_cvss"] / 2.0
                    d = 0.0 if prev_score is None else -(score - prev_score)
                    prev_score = score
                    rows.append((run_id, t, aid, m, grp.loc[i, "C"], grp.loc[i, "D"], grp.loc[i, "V"], 1.0,
                                 100.0 - score, d, 0.0, "", int(bool(reasons)), "+".join(reasons), prio))
    cols = ["run_id", "period", "asset_id", "method", "C", "D", "V", "ctx", "risk", "drift", "cum_drift",
            "trend", "alert", "alert_reason", "priority"]
    return pd.DataFrame(rows, columns=cols)
