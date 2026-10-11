"""Streamlit dashboard:  streamlit run app.py"""
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from ccm import ROOT, db
from ccm.catalog import CERT_RULES, CONFIG_ITEMS
from ccm.risk import METHOD_LABELS, METHODS

NAVY, STEEL, AMBER, TEAL, RED = "#1f3a5f", "#6b7a8f", "#d99a1e", "#2e7d6f", "#b5452f"
TREND_COLOR = {"rising": RED, "stable": STEEL, "falling": TEAL, "improving-unresolved": AMBER}

st.set_page_config(page_title="Risk drift monitor", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&display=swap');
html, body, [class*="css"], .stMarkdown, .stDataFrame { font-family: 'IBM Plex Sans', system-ui, sans-serif; }
h1 { font-weight: 600; letter-spacing: -0.01em; color: #1f3a5f; }
h2, h3 { font-weight: 500; color: #1f3a5f; }
[data-testid="stMetricValue"] { font-weight: 500; }
.drift-note { border-left: 3px solid #d99a1e; padding: 0.4rem 0.8rem; background: #fbf6ea; }
</style>""", unsafe_allow_html=True)

RULE_MAP = {v["rule"]: (v["iso"], v["nist"]) for v in CONFIG_ITEMS.values() if v["rule"]}
RULE_MAP.update({k: (v["iso"], v["nist"]) for k, v in CERT_RULES.items()})


@st.cache_data(show_spinner=False)
def load(path, mtime):
    con = db.connect(path)
    out = {t: db.read(con, t) for t in ("assets", "scans", "compliance", "config", "vulns", "events", "scores")}
    con.close()
    return out


# ---------------- sidebar ----------------
st.sidebar.title("Risk drift monitor")
sources = {"Simulated enterprise (experiment)": ROOT / "data" / "simulation.db",
           "This machine (real scans)": ROOT / "data" / "real.db"}
available = {k: v for k, v in sources.items() if v.exists()}
if not available:
    st.title("No data yet")
    st.write("Run `python run_experiment.py` for the simulated enterprise, or "
             "`sudo -E python3 collect_real.py` on the Ubuntu VM for real scans. Then reload this page.")
    st.stop()
src = st.sidebar.selectbox("Data source", list(available))
data = load(str(available[src]), available[src].stat().st_mtime)
scores = data["scores"]
if scores.empty:
    st.warning("The database has evidence but no scores yet. Run the collector again.")
    st.stop()
runs = sorted(scores.run_id.unique())
run = st.sidebar.selectbox("Run", runs) if len(runs) > 1 else runs[0]
method = st.sidebar.selectbox("Scoring method", METHODS, index=METHODS.index("P_full"),
                              format_func=lambda m: METHOD_LABELS[m])
page = st.sidebar.radio("View", ["Overview", "Asset timeline", "Governance report", "Method comparison"])

s = scores[(scores.run_id == run) & (scores.method == method)].merge(
    data["assets"], on="asset_id", how="left")
periods = sorted(s.period.unique())
ev = data["events"][data["events"].run_id == run] if not data["events"].empty else data["events"]


def week_label(p):
    return f"Week {p}" if src.startswith("Simulated") else f"Scan {p}"


# ---------------- overview ----------------
if page == "Overview":
    st.title("Where is risk moving?")
    t = st.select_slider("Scan period", options=periods, value=periods[-1], format_func=week_label)
    now = s[s.period == t]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Assets monitored", len(now))
    c2.metric("Open alerts", int(now.alert.sum()))
    c3.metric("Risk rising this period", int((now.trend == "rising").sum()))
    c4.metric("Average risk", f"{now.risk.mean():.1f}",
              delta=f"{now.drift.mean():+.1f} vs previous", delta_color="inverse")

    st.subheader("Prioritised assets")
    st.caption("Ranked by current risk plus recent upward drift. Improving-unresolved means the risk "
               "has fallen but is still above where it was before the problem started.")
    table = now.sort_values("priority", ascending=False)[
        ["asset_id", "role", "criticality", "exposure", "risk", "drift", "trend", "alert", "alert_reason"]]
    table = table.rename(columns={"asset_id": "Asset", "role": "Role", "criticality": "Criticality",
                                  "exposure": "Exposure", "risk": "Risk", "drift": "Risk drift",
                                  "trend": "Trend", "alert": "Alert", "alert_reason": "Why"})
    table["Alert"] = table["Alert"].map({1: "Open", 0: ""})
    st.dataframe(table.style.format({"Risk": "{:.1f}", "Risk drift": "{:+.1f}"})
                 .map(lambda v: f"color: {TREND_COLOR.get(v, 'inherit')}", subset=["Trend"]),
                 width="stretch", hide_index=True)

    st.subheader("Risk across all assets and periods")
    heat = alt.Chart(s).mark_rect().encode(
        x=alt.X("period:O", title="Period"),
        y=alt.Y("asset_id:N", title=None, sort=alt.EncodingSortField("criticality", order="descending")),
        color=alt.Color("risk:Q", scale=alt.Scale(scheme="goldred", domain=[0, 80]), title="Risk"),
        tooltip=["asset_id", "period", alt.Tooltip("risk:Q", format=".1f"),
                 alt.Tooltip("drift:Q", format="+.1f"), "trend", "alert_reason"])
    st.altair_chart(heat.properties(height=max(200, 22 * s.asset_id.nunique())), width="stretch")

# ---------------- asset timeline ----------------
elif page == "Asset timeline":
    st.title("Asset timeline")
    order = s.groupby("asset_id").risk.max().sort_values(ascending=False).index.tolist()
    aid = st.selectbox("Asset", order)
    a = s[s.asset_id == aid].sort_values("period")
    meta = a.iloc[0]
    st.write(f"**{meta.role}**: criticality {meta.criticality}/5, {meta.exposure}"
             f"{', regulated' if meta.regulated else ''}. Context factor {meta.ctx:.2f}.")

    base = alt.Chart(a).encode(x=alt.X("period:O", title="Period"))
    band = base.mark_bar(color=AMBER, opacity=0.18).encode(y=alt.Y("alert_y:Q", title=None, axis=None)) \
        .transform_calculate(alert_y="datum.alert * 100")
    line = base.mark_line(point=True, color=NAVY).encode(
        y=alt.Y("risk:Q", title="Risk (0-100)", scale=alt.Scale(domain=[0, 100])),
        tooltip=["period", alt.Tooltip("risk:Q", format=".1f"), alt.Tooltip("C:Q", format=".2f"),
                 alt.Tooltip("D:Q", format=".2f"), alt.Tooltip("V:Q", format=".2f"), "alert_reason"])
    st.altair_chart(alt.layer(band, line).resolve_scale(y="independent").properties(height=280),
                    width="stretch")
    bars = base.mark_bar().encode(
        y=alt.Y("drift:Q", title="Risk drift"),
        color=alt.condition("datum.drift > 0", alt.value(RED), alt.value(TEAL)))
    st.altair_chart(bars.properties(height=160), width="stretch")
    st.markdown('<div class="drift-note">Shaded periods = alert open. Red bars = risk rose since the '
                'previous scan, green = it fell.</div>', unsafe_allow_html=True)

    if not ev.empty:
        e = ev[ev.asset_id == aid].sort_values("start")
        if len(e):
            st.subheader("What happened (simulation ground truth)")
            st.dataframe(e[["kind", "start", "end", "sev_class", "harmful", "description"]]
                         .rename(columns={"sev_class": "severity (1-3)"}), hide_index=True,
                         width="stretch")

    t = st.select_slider("Evidence at period", options=periods, value=periods[-1], format_func=week_label)
    col1, col2, col3 = st.columns(3)
    comp = data["compliance"]
    comp = comp[(comp.run_id == run) & (comp.asset_id == aid) & (comp.period == t) & (comp.result == "fail")]
    col1.write("**Failing compliance rules**")
    col1.dataframe(comp[["rule_id", "severity"]], hide_index=True, width="stretch")
    conf = data["config"]
    conf = conf[(conf.run_id == run) & (conf.asset_id == aid) & (conf.period == t) & (conf.deviates == 1)]
    col2.write("**Settings drifted from baseline**")
    col2.dataframe(conf[["item", "value", "baseline", "security"]], hide_index=True, width="stretch")
    vul = data["vulns"]
    vul = vul[(vul.run_id == run) & (vul.asset_id == aid) & (vul.period == t)]
    col3.write("**Open vulnerabilities**")
    col3.dataframe(vul[["vuln_id", "cvss", "epss"]], hide_index=True, width="stretch")

# ---------------- governance report ----------------
elif page == "Governance report":
    st.title("Governance report")
    st.caption("Failing controls mapped to ISO/IEC 27001:2022 Annex A and NIST CSF 2.0. The mapping "
               "is interpretive, as described in Table 3.1 of the Phase-I report.")
    t = st.select_slider("Scan period", options=periods, value=periods[-1], format_func=week_label)
    comp = data["compliance"]
    comp = comp[(comp.run_id == run) & (comp.period == t) & (comp.result == "fail")].copy()
    comp["ISO 27001"] = comp.rule_id.map(lambda r: RULE_MAP.get(r, ("other", "other"))[0])
    comp["NIST CSF"] = comp.rule_id.map(lambda r: RULE_MAP.get(r, ("other", "other"))[1])
    c1, c2 = st.columns(2)
    c1.write("**Failures by ISO/IEC 27001 control**")
    c1.dataframe(comp.groupby("ISO 27001").size().rename("failing checks").sort_values(ascending=False),
                 width="stretch")
    c2.write("**Failures by NIST CSF 2.0 category**")
    c2.dataframe(comp.groupby("NIST CSF").size().rename("failing checks").sort_values(ascending=False),
                 width="stretch")
    now = s[s.period == t]
    rep = now[["asset_id", "role", "risk", "drift", "trend", "alert", "alert_reason"]].sort_values(
        "risk", ascending=False)
    st.write("**Asset risk summary**")
    st.dataframe(rep, hide_index=True, width="stretch")
    st.download_button("Download report (CSV)", rep.to_csv(index=False).encode(),
                       file_name=f"risk_report_{run}_period{t}.csv", mime="text/csv")

# ---------------- method comparison ----------------
else:
    st.title("Base paper vs proposed framework")
    res = ROOT / "results"
    if not (res / "summary_means.csv").exists():
        st.info("Run `python run_experiment.py` to generate the comparison.")
        st.stop()
    m = pd.read_csv(res / "summary_means.csv", index_col=0)
    m.index = [METHOD_LABELS[i] for i in m.index]
    show = m[["precision", "recall", "f1", "critical_detection_rate", "ndcg5", "p5",
              "false_alerts_per_100", "premature_drop_rate"]]
    st.dataframe(show.style.format("{:.3f}").highlight_max(axis=0, color="#e3eef7",
                 subset=["precision", "f1", "critical_detection_rate", "ndcg5", "p5"]),
                 width="stretch")
    if (res / "significance_tests.csv").exists():
        st.write("**Paired Wilcoxon signed-rank tests (same simulated runs for every method)**")
        sig = pd.read_csv(res / "significance_tests.csv")
        st.dataframe(sig.style.format({"proposed_mean": "{:.4f}", "baseline_mean": "{:.4f}",
                                       "difference": "{:+.4f}", "wilcoxon_p": "{:.2e}"}),
                     hide_index=True, width="stretch")
    for img in ["fig_alert_quality.png", "fig_detection_priority.png", "fig_sensitivity_theta.png",
                "fig_example_asset_timeline.png"]:
        if (res / img).exists():
            st.image(str(res / img), width="stretch")
