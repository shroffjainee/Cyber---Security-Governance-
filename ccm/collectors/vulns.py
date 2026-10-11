"""Vulnerability evidence.

Supported sources
  * Trivy (recommended, lightweight):  trivy rootfs --format json -o trivy.json /
  * OpenVAS / Greenbone report exported as CSV (columns IP, CVSS, CVEs)
  * Generic CSV with columns: cve, cvss, epss(optional), status(optional)

EPSS (exploit probability, FIRST.org) is fetched from the public API when the
machine has internet access; otherwise the configured default is used.
"""
import csv
import json
import shutil
import subprocess
import urllib.request

SEV_TO_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.0, "UNKNOWN": 5.0}


def run_trivy(out_json):
    if not shutil.which("trivy"):
        raise RuntimeError("trivy not found. See README section 'Install Trivy'.")
    subprocess.run(["trivy", "rootfs", "--quiet", "--scanners", "vuln", "--format", "json",
                    "-o", str(out_json), "/"], check=True)
    return out_json


def parse_trivy(path):
    data = json.load(open(path, encoding="utf-8"))
    rows = {}
    for res in data.get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            vid = v.get("VulnerabilityID")
            score = None
            for src in (v.get("CVSS") or {}).values():
                score = src.get("V3Score") or src.get("V2Score") or score
            if score is None:
                score = SEV_TO_CVSS.get(v.get("Severity", "UNKNOWN"), 5.0)
            status = "open"  # Trivy lists vulnerabilities present in installed packages
            if vid not in rows or score > rows[vid]["cvss"]:
                rows[vid] = dict(vuln_id=vid, cvss=float(score), epss=None, status=status)
    return list(rows.values())


def parse_openvas_csv(path):
    rows = {}
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for r in csv.DictReader(f):
            cvss = float(r.get("CVSS") or 0)
            for cve in (r.get("CVEs") or "").replace(";", ",").split(","):
                cve = cve.strip()
                if cve:
                    rows[cve] = dict(vuln_id=cve, cvss=cvss, epss=None, status="open")
    return list(rows.values())


def parse_generic_csv(path):
    out = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            out.append(dict(vuln_id=r["cve"], cvss=float(r["cvss"]),
                            epss=float(r["epss"]) if r.get("epss") else None,
                            status=r.get("status") or "open"))
    return out


def enrich_epss(rows, timeout=15):
    cves = [r["vuln_id"] for r in rows if r["vuln_id"].startswith("CVE-") and r["epss"] is None]
    scores = {}
    for i in range(0, len(cves), 100):
        batch = ",".join(cves[i:i + 100])
        try:
            with urllib.request.urlopen(f"https://api.first.org/data/v1/epss?cve={batch}",
                                        timeout=timeout) as resp:
                for d in json.load(resp).get("data", []):
                    scores[d["cve"]] = float(d["epss"])
        except Exception:
            break  # offline: keep defaults
    for r in rows:
        if r["epss"] is None and r["vuln_id"] in scores:
            r["epss"] = scores[r["vuln_id"]]
    return rows
