"""Streamlit dashboard — reads the SQLite database read-only and shows ONLY stored records.

Run:  streamlit run app.py               (database: $RDF_DB or data/rdf.sqlite3)
      RDF_DB=data/demo_synthetic.sqlite3 streamlit run app.py   (synthetic demo)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core.catalog import CHECKS
from core.config import DEFAULT_DB_PATH, load_risk_model
from core.timeutil import parse_iso, utc_now
from risk.prioritization import kendall_tau, prioritization_table, top_k_overlap
from storage.database import Database, DatabaseError

# Reference categorical palette (validated order) for the four score components.
COMP_COLORS = {"V": "#73A7FF", "C": "#3CCFC0", "D": "#F2A93B", "A": "#EE77BC"}
COMP_NAMES = {"V": "Vulnerability", "C": "Compliance", "D": "Config drift", "A": "Criticality"}
STATUS_ICON = {"COMPLIANT": "✅ COMPLIANT", "NON_COMPLIANT": "❌ NON_COMPLIANT", "UNKNOWN": "❔ UNKNOWN", "ERROR": "⚠️ ERROR"}
PRIORITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
PAGES = ["1. Overview", "2. Compliance checks", "3. Configuration drift", "4. Vulnerabilities",
         "5. Risk prioritisation", "6. Risk drift trend", "7. Risk explanations", "8. Assessment history & data quality",
         "9. Method comparison"]

st.set_page_config(page_title="Risk Drift Monitor", page_icon="🛡️", layout="wide")

# Console look shared with the static site: grid background, glowing cards, cyan accents.
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@100..125,500..900&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');
:root{--bg:#0A100F;--bg2:#0F1716;--panel:#121C1B;--panel2:#172322;--line:#22312E;--line2:#304440;--mu:#93A7A0;--amber:#F2A93B;--blue:#73A7FF;
 --mono:"IBM Plex Mono",ui-monospace,Consolas,monospace;--display:"Archivo","Arial Narrow",sans-serif}
html,body,.stApp,[data-testid="stMarkdownContainer"]{font-family:"IBM Plex Sans",system-ui,sans-serif}
.stApp{background:var(--bg)}
[data-testid="stHeader"]{background:rgba(10,16,15,.85);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
[data-testid="stSidebar"]{background-color:var(--bg2);border-right:1px solid var(--line);
 background-image:linear-gradient(rgba(115,167,255,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(115,167,255,.06) 1px,transparent 1px);background-size:16px 16px}
h1{font-family:var(--display)!important;font-weight:800!important;font-stretch:110%;letter-spacing:-.01em}
h2,h3{font-family:var(--display)!important;font-stretch:110%;color:#E9F0ED!important;text-transform:uppercase;letter-spacing:.03em;font-size:1rem!important}
[data-testid="stMetric"]{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;box-shadow:0 18px 50px -24px rgba(0,0,0,.7)}
[data-testid="stMetricLabel"]{font-family:var(--mono);text-transform:uppercase;letter-spacing:.12em;font-size:.72rem}
[data-testid="stMetricValue"]{font-family:var(--mono);color:var(--amber)}
[data-testid="stDataFrame"],[data-testid="stPlotlyChart"],[data-testid="stExpander"]{border:1px solid var(--line);border-radius:12px;background:var(--panel)}
[data-testid="stPlotlyChart"]{padding:8px}
.rdf-brand{display:flex;align-items:center;gap:10px;margin:-6px 0 14px}.rdf-brand b{font:800 17px var(--display);font-stretch:118%;color:#E9F0ED}
.rdf-brand small{display:block;color:var(--mu);font:500 10px var(--mono);letter-spacing:.18em;text-transform:uppercase}
.rdf-kw{font:600 11px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--amber);margin-bottom:-12px}
</style>""", unsafe_allow_html=True)
BRAND_SVG = ('<svg width="36" height="36" viewBox="0 0 38 38"><rect x="1" y="1" width="36" height="36" rx="9" fill="#121C1B" stroke="#304440"/>'
             '<path d="M6 22h6l3-10 5 16 3-9 2 3h7" fill="none" stroke="#F2A93B" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>')


def plot_layout(fig: go.Figure, height: int = 360) -> go.Figure:
    fig.update_layout(height=height, margin=dict(l=10, r=10, t=30, b=10), paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", legend=dict(orientation="h", y=-0.2), hovermode="x unified",
                      font=dict(color="#93A7A0", family="IBM Plex Sans, system-ui, sans-serif"), hoverlabel=dict(bgcolor="#172322", bordercolor="#304440"))
    fig.update_xaxes(showgrid=False, linecolor="#304440")
    fig.update_yaxes(gridcolor="#22312E", zerolinecolor="#304440")
    return fig


@st.cache_resource(show_spinner=False)
def open_db(path: str) -> Database:
    return Database(path, read_only=True)


def df(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def show(frame: pd.DataFrame) -> pd.DataFrame:
    """Display copy: empty cells as an em dash instead of 'None'."""
    return frame.astype(object).where(frame.notna(), "—")


def origin_badge(origin: str) -> str:
    return "🧪 SYNTHETIC" if origin == "SYNTHETIC" else "🖥️ HOST"


# ------------------------------------------------------------------ sidebar
st.sidebar.markdown(f'<div class="rdf-brand">{BRAND_SVG}<div><b>RDF</b><small>Risk Drift Monitor</small></div></div>',
                    unsafe_allow_html=True)
def db_choices() -> list[str]:
    """Databases the viewer may open: $RDF_DB (set by the operator) and *.sqlite3 files in data/.
    Free-text paths are not accepted, so a public deployment cannot be pointed at arbitrary files."""
    data_dir = Path(__file__).resolve().parent / "data"
    found = sorted(data_dir.glob("*.sqlite3"))
    preferred = [data_dir / "rdf.sqlite3", data_dir / "showcase.sqlite3"]
    ordered = [p for p in preferred if p in found] + [p for p in found if p not in preferred]
    out = [str(p) for p in ordered]
    env = os.environ.get("RDF_DB")
    if env:
        out = [env] + [p for p in out if Path(p).resolve() != Path(env).resolve()]
    return out or [str(DEFAULT_DB_PATH)]


db_path = st.sidebar.selectbox("SQLite database", db_choices(), format_func=lambda p: Path(p).name)
if not Path(db_path).exists():
    st.title("Continuous Compliance Monitoring & Risk Drift Detection")
    st.info(f"No database found at `{db_path}`.\n\nCreate one with `python cli.py init-db` and run "
            "`sudo -E python cli.py assess --asset-id <id>`, or build the clearly-labelled synthetic demo with "
            "`python cli.py demo` and open `data/demo_synthetic.sqlite3`.")
    st.stop()
try:
    db = open_db(db_path)
    assets = db.list_assets()
except DatabaseError as exc:
    st.error(f"Cannot read database: {exc}")
    st.stop()
if not assets:
    st.title("Continuous Compliance Monitoring & Risk Drift Detection")
    st.info("The database has no assets yet. Run `python cli.py init-db` then an assessment.")
    st.stop()

page = st.sidebar.radio("Page", PAGES)
origins = sorted({a["data_origin"] for a in assets})
origin_filter = st.sidebar.multiselect("Data origin", origins, default=origins)
visible = [a for a in assets if a["data_origin"] in origin_filter]
if not visible:
    st.warning("No assets match the selected data origin.")
    st.stop()
asset_ids = [a["asset_id"] for a in visible]
asset_id = st.sidebar.selectbox("Asset", asset_ids)
asset = next(a for a in visible if a["asset_id"] == asset_id)
st.sidebar.caption(f"{origin_badge(asset['data_origin'])} · criticality **{asset['criticality']}**")
if "SYNTHETIC" in origin_filter:
    st.warning("🧪 Records labelled SYNTHETIC are constructed demonstration/test data — they are **not** results "
               "of a real host assessment or a real Greenbone scan.")
try:
    model = load_risk_model()
except Exception as exc:  # noqa: BLE001
    model = None
    st.sidebar.error(f"risk_model.json: {exc}")


def latest_score(aid: str) -> dict | None:
    rows = db.query("SELECT score_id FROM risk_scores WHERE asset_id=? ORDER BY score_id DESC LIMIT 1", (aid,))
    return db.get_score(rows[0]["score_id"]) if rows else None


def scan_age_days(scan: dict) -> float | None:
    ts = parse_iso(scan.get("scan_ended_at") or scan.get("scan_started_at") or scan.get("imported_at"))
    return None if ts is None else (utc_now() - ts).total_seconds() / 86400


# =================================================================== pages
def page_title(text: str) -> None:
    st.markdown(f'<div class="rdf-kw">{page.split(". ", 1)[-1]}</div>', unsafe_allow_html=True)
    st.title(text)


if page == PAGES[0]:
    page_title("Overview")
    rows = []
    for a in visible:
        s = latest_score(a["asset_id"])
        run = db.latest_successful_run(a["asset_id"])
        res = db.check_results(run["run_id"]) if run else {}
        rows.append({"asset": a["asset_id"], "origin": origin_badge(a["data_origin"]), "criticality": a["criticality"],
                     "risk score": s["score"] if s else None, "band": s["band"] if s else None,
                     "score status": s["status"] if s else "no score",
                     "non-compliant": sum(r["status"] == "NON_COMPLIANT" for r in res.values()) if run else None,
                     "undetermined": sum(r["status"] in ("UNKNOWN", "ERROR") for r in res.values()) if run else None,
                     "last assessment": run["started_at"] if run else "none"})
    s = latest_score(asset_id)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Risk score", "—" if not s or s["score"] is None else f"{s['score']:.1f}",
              help="Prototype 0-100 priority indicator, not a probability of compromise.")
    c2.metric("Band", (s or {}).get("band") or "—")
    c3.metric("Score status", (s or {}).get("status") or "no score")
    rd = db.query("SELECT delta, direction FROM risk_drift_events WHERE asset_id=? ORDER BY event_id DESC LIMIT 1", (asset_id,))
    if rd and rd[0]["delta"] is not None:
        d = rd[0]["delta"]
        c4.metric("Last ΔR", rd[0]["direction"].replace("_", " ").title(), help="ΔR = R_t − R_t−1 (latest comparable scores)",
                  delta=None if abs(d) < 0.005 else f"{d:+.2f}", delta_color="inverse")
    else:
        c4.metric("Last ΔR", (rd[0]["direction"].replace("_", " ").title() if rd else "—"))
    if s and s["warnings"]:
        for w in s["warnings"]:
            st.warning(w)
    st.subheader("All assets")
    st.dataframe(df(rows), width="stretch", hide_index=True)

elif page == PAGES[1]:
    page_title("Compliance checks and evidence")
    runs = db.query("SELECT run_id, started_at, status FROM assessment_runs WHERE asset_id=? ORDER BY run_id DESC", (asset_id,))
    if not runs:
        st.info("No assessments for this asset yet.")
        st.stop()
    run_label = st.selectbox("Assessment run", [f"#{r['run_id']} · {r['started_at']} · {r['status']}" for r in runs])
    run_id = int(run_label.split("·")[0].strip("# "))
    results = db.check_results(run_id)
    run = db.get_run(run_id)
    if run["status"] == "FAILED":
        st.error(f"This run FAILED: {run['error_message']}. No compliance conclusion is drawn from it.")
    st.caption(f"Policy {run['policy_version']} · OPA {run['opa_version']} · collector {run['collector_version']} · "
               f"{origin_badge(run['data_origin'])}")
    if results:
        st.dataframe(df([{"check": cid, "title": r["title"], "status": STATUS_ICON[r["status"]],
                          "collector": r["collector_status"], "reason": r["reason"]} for cid, r in results.items()]),
                     width="stretch", hide_index=True)
    for cid in CHECKS:
        r = results.get(cid)
        if r is None:
            continue
        with st.expander(f"{cid} — {r['title']} — {STATUS_ICON[r['status']]}"):
            st.markdown(f"**Purpose:** {CHECKS[cid]['purpose']}")
            st.markdown(f"**Expected:** {r['expected']}")
            st.markdown(f"**Actual:** `{json.dumps(r['actual'])}`")
            st.markdown(f"**Reason:** {r['reason']}")
            if r["remediation"]:
                st.markdown(f"**Remediation:** {r['remediation']}")
            ev = r["evidence"] or {}
            if ev.get("limitations"):
                st.info("Limitations: " + " ".join(ev["limitations"]))
            if ev.get("errors"):
                st.warning("Collection errors: " + "; ".join(ev["errors"]))
            st.markdown("**Evidence sources:** " + ", ".join(ev.get("sources") or ["none"]))
            st.json(ev.get("evidence") or {}, expanded=False)
            st.caption(f"Record: check_results:{r['result_id']}")

elif page == PAGES[2]:
    page_title("Configuration drift history")
    events = db.drift_events(asset_id)
    if not events:
        st.info("No drift records yet — the first assessment creates a baseline.")
        st.stop()
    d = df(events)
    cats = st.multiselect("Category", sorted(d["category"].unique()),
                          default=[c for c in sorted(d["category"].unique()) if c != "BASELINE"] or None)
    pr = st.multiselect("Priority", PRIORITY_ORDER, default=PRIORITY_ORDER)
    view = d[d["category"].isin(cats or d["category"].unique()) & d["priority"].isin(pr)]
    if view.empty:
        st.info("No drift events match the filters.")
    else:
        # group per day; when all events fall on one day (e.g. a lab experiment) group per assessment run instead
        if view["detected_at"].str[:10].nunique() > 1:
            key, xtitle = view["detected_at"].str[:10], "Day"
        else:
            key, xtitle = "Run " + view["run_id"].astype(str), "Assessment run"
        counts = view.assign(bucket=key).groupby(["bucket", "priority"]).size().unstack(fill_value=0)
        if xtitle == "Assessment run":
            counts = counts.loc[sorted(counts.index, key=lambda x: int(x.split()[1]))]
        fig = go.Figure()
        prio_colors = {"CRITICAL": "#F2575A", "HIGH": "#F28A4B", "MEDIUM": "#E9B949", "LOW": "#73A7FF", "INFO": "#62766F"}
        for p in PRIORITY_ORDER:
            if p in counts:
                fig.add_bar(x=counts.index, y=counts[p], name=p, marker_color=prio_colors[p],
                            marker_line=dict(width=1, color="rgba(0,0,0,0)"))
        fig.update_layout(barmode="stack", yaxis_title="Drift events", xaxis_title=xtitle, xaxis_type="category")
        st.plotly_chart(plot_layout(fig, 300), width="stretch")
        st.dataframe(view[["drift_id", "detected_at", "run_id", "previous_run_id", "check_id", "category", "priority",
                           "previous_status", "current_status", "explanation", "previous_value", "current_value"]],
                     width="stretch", hide_index=True)

elif page == PAGES[3]:
    page_title("Vulnerability findings (Greenbone/OpenVAS imports)")
    scans = db.query("SELECT * FROM vulnerability_scans WHERE asset_id=? ORDER BY scan_id DESC", (asset_id,))
    if not scans:
        st.info("No Greenbone report imported for this asset. Vulnerability risk is treated as UNKNOWN, not zero. "
                "Import with `python cli.py import-greenbone --asset-id ... --file report.xml`.")
        st.stop()
    max_age = model["vulnerability"]["max_scan_age_days"] if model else 30
    for sc in scans:
        age = scan_age_days(sc)
        sc["age_days"] = None if age is None else round(age, 1)
        sc["stale"] = age is None or age > max_age
    st.dataframe(df(scans)[["scan_id", "source_file", "report_format", "source_report_id", "scan_ended_at", "imported_at",
                             "age_days", "stale", "finding_count", "duplicate_count", "skipped_count", "data_origin"]],
                 width="stretch", hide_index=True)
    sel = st.selectbox("Scan", [s["scan_id"] for s in scans])
    if next(s for s in scans if s["scan_id"] == sel)["stale"]:
        st.warning(f"This scan is older than {max_age} days (or undated): findings may not reflect the current host.")
    f = df(db.findings_for_scan(sel))
    if f.empty:
        st.success("This scan contains no findings for the asset.")
        st.stop()
    min_cvss = st.slider("Minimum CVSS", 0.0, 10.0, 0.0, 0.1)
    show_missing = st.checkbox("Include findings with missing CVSS", True)
    mask = (f["cvss_score"].fillna(-1) >= min_cvss) | (show_missing & f["cvss_score"].isna())
    view = f[mask].copy()
    view["cves"] = view["cves"].apply(lambda c: ", ".join(c) if c else "—")
    view["cvss_score"] = view["cvss_score"].apply(lambda x: "MISSING" if pd.isna(x) else x)
    c1, c2, c3 = st.columns(3)
    c1.metric("Findings shown", len(view))
    c2.metric("Max CVSS", f"{f['cvss_score'].max():.1f}" if f["cvss_score"].notna().any() else "—")
    c3.metric("Missing CVSS", int(f["cvss_score"].isna().sum()))
    hist = f["cvss_score"].dropna()
    if not hist.empty:
        fig = go.Figure(go.Histogram(x=hist, xbins=dict(start=0, end=10.01, size=1), marker_color="#F2A93B",
                                     marker_line=dict(width=2, color="rgba(0,0,0,0)"), name="findings"))
        fig.update_layout(xaxis_title="CVSS base score", yaxis_title="Findings", hovermode="closest")
        st.plotly_chart(plot_layout(fig, 260), width="stretch")
    st.dataframe(view[["finding_id", "name", "host", "port", "cvss_score", "severity_label", "qod", "cves", "nvt_oid",
                       "status", "solution"]], width="stretch", hide_index=True)

elif page == PAGES[4]:
    page_title("Risk prioritisation")
    st.caption("R = 0.45·V + 0.25·C + 0.20·D + 0.10·A (weights from config/risk_model.json). "
               "A prototype priority indicator — not a validated probability of exploitation or loss.")
    rows = []
    for a in visible:
        s = latest_score(a["asset_id"])
        if s:
            rows.append(s)
    if not rows:
        st.info("No risk scores yet. Run an assessment or `python cli.py score --asset-id ...`.")
        st.stop()
    rows.sort(key=lambda s: -(s["score"] if s["score"] is not None else -1))
    fig = go.Figure()
    names = [r["asset_id"] for r in rows]
    for k in "VCDA":
        w = rows[0]["weights"][k]
        fig.add_bar(y=names, x=[(r[f"{k.lower()}_score"] or 0) * w if r["status"] != "UNKNOWN" else 0 for r in rows],
                    name=f"{COMP_NAMES[k]} ({k})", orientation="h", marker_color=COMP_COLORS[k],
                    marker_line=dict(width=2, color="rgba(0,0,0,0)"),
                    hovertemplate="%{y}: %{x:.1f} pts<extra>" + COMP_NAMES[k] + "</extra>")
    fig.update_layout(barmode="stack", xaxis_title="Weighted contribution (points of 100)", hovermode="closest",
                      yaxis=dict(autorange="reversed"))
    st.plotly_chart(plot_layout(fig, 80 + 45 * len(rows)), width="stretch")
    st.caption("Bars show w·component using full weights; for PARTIAL scores with missing components the reported "
               "score is renormalised — see the table and bounds.")
    st.dataframe(df([{"asset": r["asset_id"], "origin": origin_badge(r["data_origin"]), "score": r["score"],
                      "lower": r["score_lower"], "upper": r["score_upper"], "band": r["band"], "status": r["status"],
                      "V": r["v_score"], "C": r["c_score"], "D": r["d_score"], "A": r["a_score"],
                      "components": r["available_components"], "calculated": r["calculated_at"],
                      "warnings": " | ".join(r["warnings"])} for r in rows]), width="stretch", hide_index=True)
    st.subheader("Weight sensitivity")
    sens = [{"asset": r["asset_id"], "default": r["score"] if r["status"] == "COMPLETE" else None,
             **(r["components"].get("sensitivity") or {})} for r in rows]
    st.dataframe(df(sens), width="stretch", hide_index=True)
    st.caption("Alternative weight sets are only computed when all four components are available.")

elif page == PAGES[5]:
    page_title("Historical risk drift (ΔR = Rₜ − Rₜ₋₁)")
    hist = db.query("SELECT s.score_id, s.calculated_at, s.score, s.score_lower, s.score_upper, s.status, "
                    "s.available_components, d.direction, d.delta, d.significant, d.previous_score_id "
                    "FROM risk_scores s LEFT JOIN risk_drift_events d ON d.score_id=s.score_id "
                    "WHERE s.asset_id=? ORDER BY s.score_id", (asset_id,))
    if not hist:
        st.info("No scores for this asset yet.")
        st.stop()
    h = df(hist)
    fig = go.Figure()
    fig.add_scatter(x=h["calculated_at"], y=h["score_upper"], mode="lines", line=dict(width=0), showlegend=False,
                    hoverinfo="skip")
    fig.add_scatter(x=h["calculated_at"], y=h["score_lower"], mode="lines", line=dict(width=0), fill="tonexty",
                    fillcolor="rgba(242,169,59,0.14)", name="uncertainty bounds", hoverinfo="skip")
    fig.add_scatter(x=h["calculated_at"], y=h["score"], mode="lines+markers", name="risk score",
                    line=dict(width=2.4, color="#F2A93B"), marker=dict(size=9, line=dict(width=2, color="#121C1B")),
                    customdata=h[["status", "direction", "delta"]].values,
                    hovertemplate="%{y:.1f} · %{customdata[0]} · %{customdata[1]} %{customdata[2]}<extra></extra>")
    sig = h[h["significant"] == 1]
    if not sig.empty:
        fig.add_scatter(x=sig["calculated_at"], y=sig["score"], mode="markers", name="significant change",
                        marker=dict(size=16, symbol="circle-open", line=dict(width=2, color="#F2575A")), hoverinfo="skip")
    fig.update_layout(yaxis=dict(range=[0, 100], title="Risk score"), xaxis_title="Calculated at")
    st.plotly_chart(plot_layout(fig, 400), width="stretch")
    st.caption("Points are only compared when both scores are valid and share model version and available components; "
               "otherwise the event is BASELINE or NOT_COMPARABLE.")
    st.dataframe(show(h), width="stretch", hide_index=True)

elif page == PAGES[6]:
    page_title("Evidence-supported risk explanations")
    scores = db.query("SELECT score_id, calculated_at, score, status FROM risk_scores WHERE asset_id=? ORDER BY score_id DESC",
                      (asset_id,))
    if not scores:
        st.info("No scores for this asset yet.")
        st.stop()
    label = st.selectbox("Score", [f"#{s['score_id']} · {s['calculated_at']} · {s['score']} ({s['status']})" for s in scores])
    sid = int(label.split("·")[0].strip("# "))
    ex = df(db.query("SELECT kind, component, factor, detail, evidence_ref FROM risk_explanations WHERE score_id=? "
                     "ORDER BY explanation_id", (sid,)))
    drift = db.query("SELECT * FROM risk_drift_events WHERE score_id=?", (sid,))
    if drift:
        d0 = drift[0]
        st.markdown(f"**Risk drift:** {d0['direction']}" + (f" by {d0['delta']:+.2f}" if d0["delta"] is not None else "")
                    + (" (significant)" if d0["significant"] else ""))
    for kind, title in (("DRIFT", "Why the score changed"), ("SCORE", "What the score consists of")):
        part = ex[ex["kind"] == kind] if not ex.empty else ex
        st.subheader(title)
        if part.empty:
            st.caption("No entries.")
        else:
            st.dataframe(show(part.drop(columns=["kind"])), width="stretch", hide_index=True)
    refs = sorted({r for r in (ex["evidence_ref"].dropna() if not ex.empty else []) if ":" in r})
    if refs:
        ref = st.selectbox("Open referenced evidence record", refs)
        table, rid = ref.split(":", 1)
        pk = {"vulnerability_findings": "finding_id", "check_results": "result_id", "config_drift_events": "drift_id",
              "vulnerability_scans": "scan_id", "risk_scores": "score_id", "asset_criticality_history": "history_id"}
        if table in pk and rid.isdigit():
            rec = db.query(f"SELECT * FROM {table} WHERE {pk[table]}=?", (int(rid),))  # table/pk from fixed allowlist
            st.json(rec[0] if rec else {"missing": ref}, expanded=True)

elif page == PAGES[7]:
    page_title("Assessment history, incomplete checks and data quality")
    runs = df(db.query("SELECT run_id, started_at, status, policy_version, opa_version, collector_version, data_origin, "
                       "error_message FROM assessment_runs WHERE asset_id=? ORDER BY run_id DESC", (asset_id,)))
    if runs.empty:
        st.info("No assessments yet.")
    else:
        st.dataframe(runs, width="stretch", hide_index=True)
        failed = runs[runs["status"] == "FAILED"]
        if not failed.empty:
            st.error(f"{len(failed)} failed assessment(s) — see error_message.")
    inc = df(db.query("SELECT r.run_id, a.started_at, r.check_id, r.status, r.collector_status, r.reason "
                      "FROM check_results r JOIN assessment_runs a ON a.run_id=r.run_id WHERE r.asset_id=? "
                      "AND r.status IN ('UNKNOWN','ERROR') ORDER BY r.run_id DESC", (asset_id,)))
    st.subheader("Incomplete / undetermined checks")
    if inc.empty:
        st.success("None recorded.")
    else:
        st.dataframe(inc, width="stretch", hide_index=True)
    st.subheader("Stale or missing data warnings")
    warnings = []
    scan = db.latest_scan(asset_id)
    max_age = model["vulnerability"]["max_scan_age_days"] if model else 30
    if scan is None:
        warnings.append("No vulnerability scan imported — vulnerability component is UNKNOWN.")
    else:
        age = scan_age_days(scan)
        if age is None or age > max_age:
            warnings.append(f"Latest scan #{scan['scan_id']} is {'undated' if age is None else f'{age:.0f} days old'} "
                            f"(threshold {max_age}).")
    run = db.latest_successful_run(asset_id)
    if run is None:
        warnings.append("No successful assessment — compliance component is UNKNOWN.")
    else:
        age = (utc_now() - parse_iso(run["started_at"])).total_seconds() / 86400
        if age > 7:
            warnings.append(f"Latest successful assessment is {age:.0f} days old.")
    for w in warnings:
        st.warning(w)
    if not warnings:
        st.success("No stale-data warnings for this asset.")

elif page == PAGES[8]:
    page_title("CVSS-only vs compliance-only vs proposed prioritisation")
    rows = prioritization_table(db)
    rows = [r for r in rows if r["data_origin"] in origin_filter]
    if len(rows) < 2:
        st.info("At least two assets with data are needed for a ranking comparison.")
    t = df(rows)
    st.dataframe(show(t[["asset_id", "data_origin", "criticality", "max_cvss", "high_findings", "non_compliant",
                    "undetermined", "risk_score", "risk_status", "rank_cvss_only", "rank_compliance_only",
                    "rank_proposed"]]) if not t.empty else t, width="stretch", hide_index=True)
    if len(rows) >= 2:
        c1, c2, c3 = st.columns(3)
        c1.metric("Kendall τ proposed vs CVSS-only", kendall_tau([r["rank_proposed"] for r in rows], [r["rank_cvss_only"] for r in rows]))
        c2.metric("Kendall τ proposed vs compliance-only",
                  kendall_tau([r["rank_proposed"] for r in rows], [r["rank_compliance_only"] for r in rows]))
        c3.metric("Top-2 overlap proposed vs CVSS-only", top_k_overlap(rows, "rank_proposed", "rank_cvss_only", 2))
    st.caption("Rank 1 = highest priority; ties share a rank; assets without data rank last. These statistics show "
               "how the methods differ on the stored data — they do not show which method is correct.")
