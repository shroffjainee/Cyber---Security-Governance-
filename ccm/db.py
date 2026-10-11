"""SQLite evidence store. Every row is time-indexed by (run_id, period).

Privacy note (internal panel comment "Privacy issues & DLP"): the store keeps
only derived evidence (rule results, setting values, CVE ids and scores).
Hostnames are pseudonymised before they are written (see privacy.py), and no
raw log content, file content or credentials are ever stored.
"""
import os
import sqlite3
from pathlib import Path

import pandas as pd

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY, label TEXT, role TEXT,
    criticality INTEGER, exposure TEXT, regulated INTEGER);
CREATE TABLE IF NOT EXISTS scans (
    run_id TEXT, period INTEGER, ts TEXT, PRIMARY KEY (run_id, period));
CREATE TABLE IF NOT EXISTS compliance (
    run_id TEXT, period INTEGER, asset_id TEXT, rule_id TEXT, severity TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS config (
    run_id TEXT, period INTEGER, asset_id TEXT, item TEXT, value TEXT, baseline TEXT,
    deviates INTEGER, security INTEGER, severity TEXT);
CREATE TABLE IF NOT EXISTS vulns (
    run_id TEXT, period INTEGER, asset_id TEXT, vuln_id TEXT, cvss REAL, epss REAL, status TEXT);
CREATE TABLE IF NOT EXISTS events (
    run_id TEXT, event_id TEXT, asset_id TEXT, kind TEXT, start INTEGER, "end" INTEGER,
    sev_class INTEGER, harmful INTEGER, description TEXT);
CREATE TABLE IF NOT EXISTS scores (
    run_id TEXT, period INTEGER, asset_id TEXT, method TEXT, C REAL, D REAL, V REAL, ctx REAL,
    risk REAL, drift REAL, cum_drift REAL, trend TEXT, alert INTEGER, alert_reason TEXT,
    priority REAL);
CREATE INDEX IF NOT EXISTS ix_comp ON compliance(run_id, period, asset_id);
CREATE INDEX IF NOT EXISTS ix_conf ON config(run_id, period, asset_id);
CREATE INDEX IF NOT EXISTS ix_vuln ON vulns(run_id, period, asset_id);
CREATE INDEX IF NOT EXISTS ix_score ON scores(run_id, method, period);
"""


def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    try:  # owner-only file permissions on Linux (DLP hygiene)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return con


def write(con, table, df):
    if df is not None and len(df):
        df.to_sql(table, con, if_exists="append", index=False)


def read(con, table, run_id=None):
    if run_id is None:
        return pd.read_sql(f"SELECT * FROM {table}", con)
    return pd.read_sql(f"SELECT * FROM {table} WHERE run_id = ?", con, params=(str(run_id),))


def clear_run(con, run_id):
    for t in ("scans", "compliance", "config", "vulns", "events", "scores"):
        con.execute(f"DELETE FROM {t} WHERE run_id = ?", (str(run_id),))
    con.commit()


def clear_scores(con, run_id):
    con.execute("DELETE FROM scores WHERE run_id = ?", (str(run_id),))
    con.commit()
