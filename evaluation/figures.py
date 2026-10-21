"""Research-paper figures (PNG, 200 dpi) generated from stored results.

Every figure states its data origin in the subtitle:
  REAL     - data/real_lab.sqlite3 (controlled lab drift experiment, lab/drift_experiment.sh)
  SYNTHETIC- data/demo_synthetic.sqlite3, evaluation/results/*.csv|json (labelled fixtures)

Run:  python cli.py figures            (writes ./figures/*.png)
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

from core.catalog import CHECKS  # noqa: E402
from core.config import PROJECT_ROOT  # noqa: E402
from storage.database import Database  # noqa: E402

# ---- palette (validated reference palette, light mode) -------------------------------
SURFACE = "#fcfcfb"
INK, INK2, MUTED, GRID = "#0b0b0b", "#52514e", "#8a8984", "#e4e3df"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]          # categorical slots 1-4, fixed order
GOOD, WARN, SERIOUS, CRIT = "#0ca30c", "#fab219", "#ec835a", "#d03b3b"
UNKNOWN = "#b9b8b2"
BLUE_LIGHT, BLUE, BLUE_DARK = "#cde2fb", "#2a78d6", "#184f95"
STATUS_COLOR = {"COMPLIANT": GOOD, "NON_COMPLIANT": CRIT, "UNKNOWN": UNKNOWN, "ERROR": SERIOUS}
STATUS_LABEL = {"COMPLIANT": "C", "NON_COMPLIANT": "NC", "UNKNOWN": "?", "ERROR": "ERR"}
BAND_COLOR = {"Low": GOOD, "Medium": WARN, "High": SERIOUS, "Critical": CRIT}

SHORT = {"SSH-001": "SSH root login", "SSH-002": "SSH password auth", "FW-001": "UFW firewall",
         "SVC-001": "Prohibited services", "FILE-001": "Account file perms", "PWD-001": "Password policy",
         "LOCK-001": "Account lockout", "UPD-001": "Security updates"}
RESULTS = PROJECT_ROOT / "evaluation" / "results"
LAB_STEPS = ["R1\nbaseline", "R2\nno change", "R3\nroot login", "R4\nUFW off", "R5\nvsftpd",
             "R6\nshadow 644", "R7\nSSH pwd", "R8\nminlen 8", "R9\nno lockout", "R10\nupdates off",
             "R11\nremediate", "R12\nno change"]
N = len(LAB_STEPS)

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.titleweight": "bold", "axes.titlesize": 12, "axes.titlecolor": INK,
})


def _title(fig, ax, title: str, subtitle: str) -> None:
    ax.set_title(title, loc="left", pad=22)
    ax.text(0, 1.02, subtitle, transform=ax.transAxes, fontsize=8.5, color=INK2, va="bottom")


def _save(fig, out: Path, name: str) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    p = out / name
    fig.savefig(p, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return p


def _lab(db_path: Path, asset_id: str = "lab-ubuntu-container") -> dict[str, Any] | None:
    if not Path(db_path).exists():
        return None
    db = Database(db_path, read_only=True)
    runs = db.query("SELECT * FROM assessment_runs WHERE asset_id=? AND data_origin='HOST' ORDER BY run_id",
                    (asset_id,))[-N:]
    if len(runs) < N:
        db.close()
        return None
    scores = db.query("SELECT * FROM risk_scores WHERE asset_id=? ORDER BY score_id", (asset_id,))[-N:]
    rd = {r["score_id"]: r for r in db.query("SELECT * FROM risk_drift_events WHERE asset_id=?", (asset_id,))}
    data = {"runs": runs, "scores": scores,
            "results": [db.check_results(r["run_id"]) for r in runs],
            "drift": [db.drift_events_for_run(r["run_id"]) for r in runs],
            "rdrift": [rd.get(s["score_id"]) for s in scores]}
    db.close()
    return data


# ---------------------------------------------------------------- Fig 1 architecture
def fig_architecture(out: Path) -> Path:
    fig, ax = plt.subplots(figsize=(11, 6.2))
    ax.set_xlim(-2, 113)
    ax.set_ylim(0, 62)
    ax.axis("off")

    def box(x, y, w, h, title, sub, fill=BLUE_LIGHT, edge=BLUE):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2",
                                    fc=fill, ec=edge, lw=1.4))
        ax.text(x + w / 2, y + h - 2.6, title, ha="center", va="top", fontsize=9.5, weight="bold", color=INK)
        ax.text(x + w / 2, y + h - 6.2, sub, ha="center", va="top", fontsize=7.6, color=INK2, linespacing=1.35)

    def arrow(x1, y1, x2, y2, label=""):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12, lw=1.3,
                                     color=INK2))
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 1.0, label, ha="center", fontsize=7, color=MUTED)

    ax.text(0, 61, "Continuous Compliance Monitoring & Risk Drift Detection Framework", fontsize=13,
            weight="bold", color=INK, va="top")
    ax.text(0, 57.5, "Data flow of one assessment cycle (repeated by `cli.py monitor` / cron)", fontsize=8.5,
            color=INK2, va="top")
    # row 1 - compliance path
    box(0, 34, 18, 17, "Ubuntu asset", "SSH, UFW, services,\nfile perms, password,\nlockout, updates")
    box(23, 34, 19, 17, "Evidence collector", "8 read-only checks\nsafe subprocess\nJSON schema validated")
    box(47, 34, 19, 17, "Policy engine", "OPA / Rego\ncompliance.rego\n4 result statuses")
    box(71, 34, 17, 17, "SQLite storage", "runs, snapshots,\ncheck results,\nhistory", fill="#eeeeec", edge=INK2)
    box(92, 34, 18, 17, "Config drift", "baseline vs current\nNEW_NON_COMPLIANCE\nCORRECTED / CHANGE")
    # row 2 - risk path
    box(0, 6, 18, 17, "Greenbone /\nOpenVAS", "\nauthorised scan\nXML / CSV export", fill="#fde3d8", edge=SERIOUS)
    box(23, 6, 19, 17, "Vuln. import", "defusedxml parser\ndedup, CVSS, QoD\nhost filter")
    box(47, 6, 19, 17, "Risk scoring", "R = 0.45V + 0.25C\n+ 0.20D + 0.10A\n(0-100, bounds)")
    box(71, 6, 17, 17, "Risk drift", "ΔR = R_t − R_t−1\ncomponent\nexplanations")
    box(92, 6, 18, 17, "Dashboard & CLI", "Streamlit (9 pages)\nstatic web console\nevaluation reports",
        fill="#d6f2e6", edge=SERIES[2])
    arrow(18.8, 42.5, 22.4, 42.5, "")
    arrow(42.8, 42.5, 46.4, 42.5, "JSON")
    arrow(66.8, 42.5, 70.4, 42.5, "")
    arrow(88.8, 42.5, 91.4, 42.5, "")
    arrow(18.8, 14.5, 22.4, 14.5, "")
    arrow(42.8, 14.5, 46.4, 14.5, "V")
    arrow(66.8, 14.5, 70.4, 14.5, "")
    arrow(88.8, 14.5, 91.4, 14.5, "")
    arrow(56.5, 33.4, 56.5, 23.8, "")
    ax.text(57.5, 30.5, "C", fontsize=8, color=INK2, weight="bold")
    arrow(101, 33.4, 66.8, 22.0, "")
    ax.text(84, 29.5, "D", fontsize=8, color=INK2, weight="bold")
    ax.text(0, 1.0, "Inputs to R:  C = compliance (OPA)   D = configuration drift   V = vulnerabilities   A = asset criticality (asset_policy.json)", fontsize=7.6, color=INK2)
    return _save(fig, out, "fig01_architecture.png")


# ---------------------------------------------------------------- Fig 3 compliance heatmap
def fig_compliance(lab: dict[str, Any], out: Path) -> Path:
    checks = list(CHECKS)
    fig, ax = plt.subplots(figsize=(11.5, 4.6))
    for j, res in enumerate(lab["results"]):
        for i, cid in enumerate(checks):
            st = res.get(cid, {}).get("status", "UNKNOWN")
            ax.add_patch(plt.Rectangle((j + 0.04, i + 0.04), 0.92, 0.92, color=STATUS_COLOR[st], lw=0))
            ax.text(j + 0.5, i + 0.5, STATUS_LABEL[st], ha="center", va="center", fontsize=8.5,
                    color="white", weight="bold")
    ax.set_xlim(0, N)
    ax.set_ylim(len(checks), 0)
    ax.set_xticks([j + 0.5 for j in range(N)], LAB_STEPS, fontsize=7.8)
    ax.set_yticks([i + 0.5 for i in range(len(checks))],
                  [f"{c}  {SHORT[c]}" for c in checks], fontsize=8)
    ax.tick_params(length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=STATUS_COLOR[s]) for s in ("COMPLIANT", "NON_COMPLIANT")]
    ax.legend(handles, ["C = COMPLIANT", "NC = NON_COMPLIANT"], loc="upper left", bbox_to_anchor=(0, -0.2),
              ncol=2, frameon=False, fontsize=8)
    _title(fig, ax, "OPA compliance status of eight controls across twelve assessments",
           "REAL lab evidence (lab-ubuntu-container, Ubuntu 24.04) · each column = one `cli.py assess` run")
    return _save(fig, out, "fig03_compliance_status.png")


# ---------------------------------------------------------------- Fig 4 drift events
def fig_drift(lab: dict[str, Any], out: Path) -> Path:
    checks = list(CHECKS)
    fig, ax = plt.subplots(figsize=(11.5, 4.4))
    for j, evs in enumerate(lab["drift"]):
        for e in evs:
            if e["category"] not in ("NEW_NON_COMPLIANCE", "CORRECTED", "CONFIGURATION_CHANGE"):
                continue
            i = checks.index(e["check_id"])
            if e["category"] == "NEW_NON_COMPLIANCE":
                ax.scatter(j, i, s=140, marker="^", color=CRIT, edgecolor=SURFACE, lw=2, zorder=3)
                ax.text(j + 0.18, i, e["priority"], fontsize=7, color=INK2, va="center")
            elif e["category"] == "CORRECTED":
                ax.scatter(j, i, s=140, marker="v", color=GOOD, edgecolor=SURFACE, lw=2, zorder=3)
            else:
                ax.scatter(j, i, s=90, marker="o", color=WARN, edgecolor=SURFACE, lw=2, zorder=3)
    ax.set_xticks(range(N), LAB_STEPS, fontsize=7.8)
    ax.set_yticks(range(len(checks)), checks, fontsize=8.5)
    ax.set_ylim(len(checks) - 0.5, -0.5)
    ax.set_xlim(-0.5, N - 0.1)
    ax.grid(True, color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    h = [plt.Line2D([], [], marker="^", ls="", color=CRIT, ms=9),
         plt.Line2D([], [], marker="v", ls="", color=GOOD, ms=9)]
    ax.legend(h, ["NEW_NON_COMPLIANCE (drift detected)", "CORRECTED (remediation recognised)"],
              loc="upper left", bbox_to_anchor=(0, -0.2), ncol=2, frameon=False, fontsize=8)
    n_new = sum(1 for evs in lab["drift"] for e in evs if e["category"] == "NEW_NON_COMPLIANCE")
    n_cor = sum(1 for evs in lab["drift"] for e in evs if e["category"] == "CORRECTED")
    _title(fig, ax, "Configuration drift events detected between successive snapshots",
           f"REAL lab evidence · {n_new} drift events, {n_cor} corrections, 0 events in unchanged runs R2/R12")
    return _save(fig, out, "fig04_configuration_drift.png")


# ---------------------------------------------------------------- Fig 5 greenbone findings
def fig_greenbone(demo_db: Path, out: Path) -> Path | None:
    if not demo_db.exists():
        return None
    db = Database(demo_db, read_only=True)
    rows = db.query("SELECT severity_label, status, COUNT(*) n FROM vulnerability_findings GROUP BY 1, 2")
    scans = db.query("SELECT COUNT(*) n FROM vulnerability_scans")[0]["n"]
    db.close()
    order = ["High", "Medium", "Low", "Log"]
    counts = {k: 0 for k in order}
    fps = 0
    for r in rows:
        lab = (r["severity_label"] or "Log").capitalize()
        if (r["status"] or "").upper().startswith("FALSE"):
            fps += r["n"]
        counts[lab if lab in counts else "Log"] += r["n"]
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    cols = [CRIT, SERIOUS, BLUE, UNKNOWN]
    bars = ax.barh(order[::-1], [counts[k] for k in order[::-1]], color=cols[::-1], height=0.55)
    for b in bars:
        ax.text(b.get_width() + 0.15, b.get_y() + b.get_height() / 2, f"{int(b.get_width())}", va="center",
                fontsize=9, color=INK)
    ax.set_xlabel("Imported findings")
    ax.grid(axis="x", color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    _title(fig, ax, "Greenbone/OpenVAS findings imported by severity",
           f"SYNTHETIC report fixtures (demo DB) · {scans} scans imported · false positives marked: {fps}")
    return _save(fig, out, "fig05_greenbone_import.png")


# ---------------------------------------------------------------- Fig 6 decomposition
def fig_decomposition(lab: dict[str, Any], out: Path) -> Path:
    comps = [("v_score", "V vulnerability"), ("c_score", "C compliance"), ("d_score", "D drift"),
             ("a_score", "A criticality")]
    fig, ax = plt.subplots(figsize=(11.5, 4.6))
    bottoms = [0.0] * N
    for k, (col, label) in enumerate(comps):
        vals = []
        for s in lab["scores"]:
            w = json.loads(s["weights"]) if isinstance(s["weights"], str) else s["weights"]
            avail = s["available_components"]
            tot = sum(w[c] for c in avail) or 1
            key = col[0].upper()
            vals.append((w[key] / tot) * (s[col] or 0) if key in avail and s[col] is not None else 0.0)
        if not any(vals):
            continue
        ax.bar(range(N), vals, bottom=bottoms, color=SERIES[k], width=0.6, label=label,
               edgecolor=SURFACE, lw=2)
        bottoms = [b + v for b, v in zip(bottoms, vals)]
    for j, s in enumerate(lab["scores"]):
        ax.text(j, bottoms[j] + 1.5, f"{s['score']:.1f}", ha="center", fontsize=8.5, color=INK, weight="bold")
    ax.set_xticks(range(N), LAB_STEPS, fontsize=7.8)
    ax.set_ylabel("Weighted contribution to R (0-100)")
    ax.set_ylim(0, 100)
    ax.grid(axis="y", color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    ax.legend(loc="upper left", bbox_to_anchor=(0, -0.2), ncol=4, frameon=False, fontsize=8)
    _title(fig, ax, "Risk score decomposition  R = 0.45V + 0.25C + 0.20D + 0.10A",
           "REAL lab evidence · V unavailable (no Greenbone scan of lab host) → weights renormalised over C, D, A")
    return _save(fig, out, "fig06_risk_decomposition.png")


# ---------------------------------------------------------------- Fig 7 risk drift trend
def fig_trend(lab: dict[str, Any], out: Path) -> Path:
    sc = [s["score"] for s in lab["scores"]]
    lo = [s["score_lower"] for s in lab["scores"]]
    hi = [s["score_upper"] for s in lab["scores"]]
    fig, ax = plt.subplots(figsize=(11.5, 4.6))
    ax.fill_between(range(N), lo, hi, color=BLUE_LIGHT, alpha=0.6, lw=0, label="uncertainty bounds")
    ax.plot(range(N), sc, color=BLUE, lw=2, marker="o", ms=7, mec=SURFACE, mew=2, label="risk score R", zorder=3)
    for j, r in enumerate(lab["rdrift"]):
        if r and r["delta"] is not None and abs(r["delta"]) >= 0.01:
            ax.annotate(f"ΔR {r['delta']:+.1f}", (j, sc[j]), textcoords="offset points",
                        xytext=(0, 10 if r["delta"] > 0 else -16), ha="center", fontsize=8,
                        color=CRIT if r["delta"] > 0 else GOOD, weight="bold")
    ax.set_xticks(range(N), LAB_STEPS, fontsize=7.8)
    ax.set_ylabel("Risk score R (0-100)")
    ax.set_ylim(0, 100)
    ax.grid(axis="y", color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    ax.legend(loc="upper left", bbox_to_anchor=(0, -0.2), ncol=2, frameon=False, fontsize=8)
    _title(fig, ax, "Risk drift (ΔR) across the controlled drift experiment",
           "REAL lab evidence · ΔR = R_t − R_(t−1) between comparable scores; band thresholds per risk_model.json")
    return _save(fig, out, "fig07_risk_drift_trend.png")


def fig_trend_synthetic(demo_db: Path, out: Path) -> Path | None:
    if not demo_db.exists():
        return None
    db = Database(demo_db, read_only=True)
    s = db.query("SELECT score, score_lower, score_upper, calculated_at, available_components FROM risk_scores "
                 "WHERE asset_id='syn-timeline' ORDER BY score_id")
    rd = db.query("SELECT delta FROM risk_drift_events WHERE asset_id='syn-timeline' ORDER BY score_id")
    db.close()
    if not s:
        return None
    x = range(len(s))
    fig, ax = plt.subplots(figsize=(10, 4.2))
    ax.plot(x, [r["score"] for r in s], color=BLUE, lw=2, marker="o", ms=7, mec=SURFACE, mew=2, zorder=3)
    for j, r in enumerate(rd):
        if r["delta"] is not None and abs(r["delta"]) >= 0.01 and j < len(s):
            ax.annotate(f"{r['delta']:+.1f}", (j, s[j]["score"]), textcoords="offset points",
                        xytext=(0, 10 if r["delta"] > 0 else -16), ha="center", fontsize=8,
                        color=CRIT if r["delta"] > 0 else GOOD, weight="bold")
    ax.set_xticks(list(x), [f"{r['calculated_at'][5:10]}\n{r['available_components']}" for r in s], fontsize=7.8)
    ax.set_ylabel("Risk score R (0-100)")
    ax.set_ylim(0, 100)
    ax.grid(axis="y", color=GRID, lw=0.6)
    _title(fig, ax, "Risk drift with all four components (V, C, D, A)",
           "SYNTHETIC timeline asset `syn-timeline` (demo DB) · x-axis: date / available components")
    return _save(fig, out, "fig07b_risk_drift_synthetic_vcda.png")


# ---------------------------------------------------------------- Fig 8 scenarios
def fig_scenarios(out: Path) -> Path | None:
    p = RESULTS / "scenario_results.csv"
    if not p.exists():
        return None
    rows = list(csv.DictReader(p.open()))
    fig, ax = plt.subplots(figsize=(10, 0.29 * len(rows) + 0.9))
    ax.axis("off")
    hdr = ["#", "Scenario", "Expected ΔR", "Observed ΔR", "Result"]
    cells = [[str(i + 1), r["scenario"].replace("_", " "), r["expected_direction"], r["observed_direction"],
              "PASS" if r["passed"] == "True" else "FAIL"] for i, r in enumerate(rows)]
    t = ax.table(cellText=cells, colLabels=hdr, loc="upper left", cellLoc="left",
                 colWidths=[0.05, 0.47, 0.17, 0.17, 0.1])
    t.auto_set_font_size(False)
    t.set_fontsize(8.5)
    t.scale(1, 1.35)
    for (r, c), cell in t.get_celld().items():
        cell.set_edgecolor(GRID)
        if r == 0:
            cell.set_facecolor("#eeeeec")
            cell.set_text_props(weight="bold", color=INK)
        elif c == 4:
            cell.set_text_props(color=GOOD if cell.get_text().get_text() == "PASS" else CRIT, weight="bold")
    passed = sum(1 for r in rows if r["passed"] == "True")
    ax.set_title(f"Scenario evaluation: {passed}/{len(rows)} scenarios passed", loc="left", pad=18)
    ax.text(0, 1.0, "SYNTHETIC evidence through the real pipeline (real OPA, SQLite, drift, scoring)",
            transform=ax.transAxes, fontsize=8.5, color=INK2, va="bottom")
    return _save(fig, out, "fig08_scenario_evaluation.png")


# ---------------------------------------------------------------- Fig 9 baselines
def fig_baselines(out: Path) -> Path | None:
    p = RESULTS / "baseline_comparison.json"
    if not p.exists():
        return None
    data = json.loads(p.read_text())
    rows = sorted(data["table"], key=lambda r: r["rank_proposed"])
    methods = [("rank_cvss_only", "CVSS-only"), ("rank_compliance_only", "Compliance-only"),
               ("rank_proposed", "Proposed R")]
    fig, ax = plt.subplots(figsize=(9, 4.4))
    off = [-0.22, 0, 0.22]
    for k, (key, label) in enumerate(methods):
        ax.scatter([r[key] for r in rows], [i + off[k] for i in range(len(rows))], s=80, color=SERIES[k],
                   edgecolor=SURFACE, lw=2, label=label, zorder=3)
    ax.set_yticks(range(len(rows)), [f"{r['asset_id']} ({r['criticality']})" for r in rows], fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xticks(range(1, 7))
    ax.set_xlabel("Priority rank (1 = remediate first; ties share a rank)")
    ax.grid(axis="x", color=GRID, lw=0.6)
    ax.set_axisbelow(True)
    ax.legend(loc="upper left", bbox_to_anchor=(0, -0.16), ncol=3, frameon=False, fontsize=8)
    kt = data.get("kendall_tau", {})
    _title(fig, ax, "Prioritisation: CVSS-only vs compliance-only vs proposed risk score",
           f"SYNTHETIC portfolio · Kendall τ proposed–CVSS {kt.get('proposed_vs_cvss_only')}, "
           f"proposed–compliance {kt.get('proposed_vs_compliance_only')}")
    return _save(fig, out, "fig09_baseline_comparison.png")


def build_all(demo_db: str | Path, lab_db: str | Path, out: str | Path) -> list[Path]:
    out = Path(out)
    demo = Path(demo_db) if Path(demo_db).name.startswith("demo") else PROJECT_ROOT / "data" / "demo_synthetic.sqlite3"
    paths: list[Path | None] = [fig_architecture(out)]
    lab = _lab(Path(lab_db))
    if lab:
        paths += [fig_compliance(lab, out), fig_drift(lab, out), fig_decomposition(lab, out), fig_trend(lab, out)]
    else:
        print(f"  (no lab experiment in {lab_db}: run `sudo bash lab/drift_experiment.sh all` for Figs 3,4,6,7)")
    paths += [fig_greenbone(demo, out), fig_trend_synthetic(demo, out), fig_scenarios(out), fig_baselines(out)]
    return [p for p in paths if p]
