"""OpenSCAP collector (same tool as the base paper, Moric et al., 2026).

Runs:
  oscap xccdf eval --profile <profile> --results <out.xml> <datastream>
and parses every <rule-result> into (rule_id, severity, result).
"""
import gzip
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from ..catalog import PREFIX


def run_oscap(datastream, profile, out_xml):
    if not shutil.which("oscap"):
        raise RuntimeError("oscap not found. Install with: sudo apt install openscap-scanner ssg-debderived")
    cmd = ["oscap", "xccdf", "eval", "--profile", profile, "--results", str(out_xml), str(datastream)]
    # oscap returns 2 when some rules fail; that is a normal result, not an error
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 2):
        raise RuntimeError(f"oscap failed: {proc.stderr[:500]}")
    return Path(out_xml)


def parse_results(xml_path):
    """Return list of dicts: rule_id (prefix stripped), severity, result (pass/fail)."""
    xml_path = str(xml_path)
    if xml_path.endswith(".gz"):
        with gzip.open(xml_path) as fh:
            tree = ET.parse(fh)
    else:
        tree = ET.parse(xml_path)
    rows = []
    for el in tree.iter():
        if not el.tag.endswith("rule-result"):
            continue
        rid = el.get("idref", "")
        sev = (el.get("severity") or "medium").lower()
        if sev not in ("high", "medium", "low"):
            sev = "low"
        res = ""
        for ch in el:
            if ch.tag.endswith("result"):
                res = (ch.text or "").strip()
        if res in ("notapplicable", "notchecked", "notselected", "informational", "error", "unknown", ""):
            continue
        rows.append(dict(rule_id=rid.replace(PREFIX, ""), severity=sev,
                         result="pass" if res in ("pass", "fixed") else "fail"))
    return rows
