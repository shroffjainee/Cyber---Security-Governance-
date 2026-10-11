"""Run the full Phase-II experiment.

    python run_experiment.py            # 30 runs (default)
    python run_experiment.py --runs 10  # quicker

Outputs (in results/):
    per_run_metrics.csv     every metric, every method, every run
    summary_table.csv       mean and std per method  (use in Chapter 5 tables)
    significance_tests.csv  Wilcoxon signed-rank tests, proposed vs baselines
    sensitivity_theta.csv   effect of the drift threshold
    fig_*.png               charts for the report / PPT
    summary.md              human-readable summary
and data/simulation.db for the dashboard.
"""
import argparse
import copy
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import wilcoxon

from ccm import ROOT, load_config, db
from ccm.metrics import evaluate_run
from ccm.risk import METHODS, METHOD_LABELS, score_run
from ccm.simulate import ground_truth, simulate

RES = ROOT / "results"
SHORT = {"B0_compliance_only": "B0\nbase paper", "B1_compliance_cvss": "B1\n+CVSS scan",
         "P_no_context": "P\nno context", "P_no_temporal": "P\nno temporal", "P_full": "P-full\nproposed"}
N_PERIODS = 16
COLORS = {"B0_compliance_only": "#8a8f98", "B1_compliance_cvss": "#5b6b7f",
          "P_no_context": "#9cc5c0", "P_no_temporal": "#4f9a94", "P_full": "#1f5f8b"}


def one_run(seed, cfg, con=None):
    sim = simulate(seed, N_PERIODS)
    scores = score_run(sim["assets"], sim["compliance"], sim["config"], sim["vulns"], cfg, sim["run_id"])
    gt = ground_truth(sim["assets"], sim["events"], N_PERIODS)
    met = evaluate_run(scores, sim["events"], gt, sim["assets"], seed=seed)
    met["seed"] = seed
    if con is not None:
        db.clear_run(con, sim["run_id"])
        for t in ("scans", "compliance", "config", "vulns", "events"):
            db.write(con, t, sim[t])
        db.write(con, "scores", scores)
    return sim, scores, gt, met


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=30)
    ap.add_argument("--start-seed", type=int, default=1000)
    args = ap.parse_args()
    cfg = load_config()
    RES.mkdir(exist_ok=True)
    dbpath = ROOT / "data" / "simulation.db"
    if dbpath.exists():
        dbpath.unlink()
    con = db.connect(dbpath)

    seeds = list(range(args.start_seed, args.start_seed + args.runs))
    all_met, first = [], None
    for i, s in enumerate(seeds):
        sim, scores, gt, met = one_run(s, cfg, con if i < 5 else None)  # keep 5 runs for the dashboard
        if first is None:
            first = (sim, scores, gt)
            sim["assets"].to_sql("assets", con, if_exists="replace", index=False)
        all_met.append(met)
        print(f"run {i + 1}/{len(seeds)} (seed {s}) done")
    con.commit()
    met = pd.concat(all_met, ignore_index=True)
    met.to_csv(RES / "per_run_metrics.csv", index=False)

    cols = ["precision", "recall", "f1", "false_alerts_per_100", "detection_rate", "mean_delay",
            "critical_detection_rate", "critical_mean_delay", "ndcg5", "p5", "premature_drop_rate", "alerts"]
    mean = met.groupby("method")[cols].mean().reindex(METHODS)
    std = met.groupby("method")[cols].std().reindex(METHODS)
    summary = mean.round(3).astype(str) + " ± " + std.round(3).astype(str)
    summary.insert(0, "label", [METHOD_LABELS[m] for m in METHODS])
    summary.to_csv(RES / "summary_table.csv")
    mean.to_csv(RES / "summary_means.csv")

    # paired significance tests (same seeds for every method)
    tests = []
    for base in ["B0_compliance_only", "B1_compliance_cvss"]:
        for col in ["precision", "f1", "false_alerts_per_100", "critical_detection_rate", "ndcg5", "p5",
                    "premature_drop_rate"]:
            a = met[met.method == "P_full"].set_index("seed")[col]
            b = met[met.method == base].set_index("seed")[col]
            pair = pd.concat([a, b], axis=1).dropna()
            if len(pair) >= 5 and not np.allclose(pair.iloc[:, 0], pair.iloc[:, 1]):
                stat, p = wilcoxon(pair.iloc[:, 0], pair.iloc[:, 1])
            else:
                stat, p = np.nan, np.nan
            tests.append(dict(comparison=f"P_full vs {base}", metric=col,
                              proposed_mean=a.mean(), baseline_mean=b.mean(),
                              difference=a.mean() - b.mean(), wilcoxon_p=p))
    tests = pd.DataFrame(tests)
    tests.to_csv(RES / "significance_tests.csv", index=False)

    # sensitivity of the drift threshold (first 10 seeds)
    sens = []
    for theta in [2.5, 5.0, 7.5, 10.0, 15.0]:
        c2 = copy.deepcopy(cfg)
        c2["drift_threshold"] = theta
        c2["cumulative_threshold"] = 1.5 * theta
        for s in seeds[:10]:
            _, _, _, m = one_run(s, c2)
            m = m[m.method == "P_full"].assign(theta=theta)
            sens.append(m)
    sens = pd.concat(sens).groupby("theta")[["precision", "recall", "f1", "critical_detection_rate",
                                             "false_alerts_per_100"]].mean().reset_index()
    sens.to_csv(RES / "sensitivity_theta.csv", index=False)

    make_charts(mean, std, sens, first, cfg)
    write_markdown(summary, tests, sens, len(seeds))
    print("\nDone. See results/ folder.")
    print(mean[["precision", "recall", "f1", "critical_detection_rate", "ndcg5"]].round(3))


def _bar(ax, mean, std, col, title, ylabel, pct=True):
    vals = mean[col] * (100 if pct else 1)
    errs = std[col] * (100 if pct else 1)
    ax.bar(range(len(vals)), vals, yerr=errs, color=[COLORS[m] for m in mean.index], capsize=3)
    ax.set_xticks(range(len(vals)))
    ax.set_xticklabels([SHORT[m] for m in mean.index], fontsize=8)
    ax.set_title(title, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=8)
    for i, v in enumerate(vals):
        ax.text(i, v + (errs.iloc[i] if not np.isnan(errs.iloc[i]) else 0) + 0.5, f"{v:.1f}",
                ha="center", fontsize=7)
    ax.spines[["top", "right"]].set_visible(False)


def make_charts(mean, std, sens, first, cfg):
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    _bar(axes[0], mean, std, "precision", "Alert precision", "%")
    _bar(axes[1], mean, std, "f1", "Alert F1-score", "%")
    _bar(axes[2], mean, std, "false_alerts_per_100", "False alerts per 100 asset-weeks", "count", pct=False)
    fig.tight_layout()
    fig.savefig(RES / "fig_alert_quality.png", dpi=200)
    plt.close(fig)

    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    _bar(axes[0], mean, std, "critical_detection_rate", "Critical events detected", "%")
    _bar(axes[1], mean, std, "ndcg5", "Prioritisation quality (NDCG@5)", "%")
    _bar(axes[2], mean, std, "premature_drop_rate", "Alerts dropped while still harmful", "%")
    fig.tight_layout()
    fig.savefig(RES / "fig_detection_priority.png", dpi=200)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6, 4))
    for col, lab in [("precision", "Precision"), ("recall", "Recall"), ("f1", "F1"),
                     ("critical_detection_rate", "Critical detection")]:
        ax.plot(sens.theta, sens[col] * 100, marker="o", label=lab)
    ax.axvline(cfg["drift_threshold"], ls="--", c="grey", lw=0.8)
    ax.set_xlabel("Drift threshold θ (risk points)")
    ax.set_ylabel("%")
    ax.set_title("Sensitivity of the proposed framework to θ")
    ax.legend(fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(RES / "fig_sensitivity_theta.png", dpi=200)
    plt.close(fig)

    # example asset timeline: pick the asset with the largest risk swing in run 1
    sim, scores, gt = first
    p = scores[scores.method == "P_full"]
    swing = p.groupby("asset_id").risk.agg(lambda r: r.max() - r.min()).sort_values(ascending=False)
    aid = swing.index[0]
    s = p[p.asset_id == aid].sort_values("period")
    b0 = scores[(scores.method == "B0_compliance_only") & (scores.asset_id == aid)].sort_values("period")
    ev = sim["events"][sim["events"].asset_id == aid]
    fig, (a1, a2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True, gridspec_kw={"height_ratios": [3, 2]})
    a1.plot(s.period, s.risk, marker="o", color=COLORS["P_full"], label="Risk(t) - proposed")
    a1.plot(b0.period, b0.risk, marker="s", color=COLORS["B0_compliance_only"], ls="--",
            label="100 - compliance score (base paper)")
    for _, r in s[s.alert == 1].iterrows():
        a1.axvspan(r.period - 0.5, r.period + 0.5, color="#f2c14e", alpha=0.25, lw=0)
    for i, e in enumerate(ev[ev.harmful == 1].itertuples()):
        a1.annotate(e.kind, xy=(e.start, s.set_index("period").risk.get(e.start, 0)),
                    xytext=(e.start, 92 - 10 * (i % 4)), fontsize=7,
                    arrowprops=dict(arrowstyle="-", lw=0.5, color="grey"))
    a1.set_ylim(0, 100)
    a1.set_ylabel("Score (0-100)")
    a1.set_title(f"Asset {aid}: risk and risk drift (shaded = proposed alert open)")
    a1.legend(fontsize=8, loc="upper left")
    a2.bar(s.period, s.drift, color=[("#c0392b" if d > 0 else "#2e8b57") for d in s.drift])
    a2.axhline(cfg["drift_threshold"], ls="--", c="grey", lw=0.8)
    a2.axhline(-cfg["drift_threshold"], ls="--", c="grey", lw=0.8)
    a2.set_ylabel("Risk Drift(t)")
    a2.set_xlabel("Week")
    for a in (a1, a2):
        a.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(RES / "fig_example_asset_timeline.png", dpi=200)
    plt.close(fig)


def write_markdown(summary, tests, sens, n):
    lines = [f"# Phase-II experiment results ({n} simulation runs, 20 assets, 16 weekly scans)\n",
             "Values are mean ± standard deviation across runs. Rates are fractions (0-1).\n",
             summary.to_markdown(), "\n\n## Paired Wilcoxon signed-rank tests\n",
             tests.round(4).to_markdown(index=False), "\n\n## Sensitivity to drift threshold θ\n",
             sens.round(3).to_markdown(index=False), "\n"]
    (RES / "summary.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
