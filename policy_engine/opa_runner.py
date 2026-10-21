"""Open Policy Agent integration via the documented ``opa eval`` CLI.

Command used (all flags are standard ``opa eval`` options):

    opa eval --data <policies_dir> --stdin-input --format json "data.compliance.results"

The evidence JSON is sent on stdin; OPA's JSON output has the shape
``{"result": [{"expressions": [{"value": {...}}]}]}``.  An empty ``result``
means the query was undefined, which is treated as an evaluation failure —
never as compliance.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from core.catalog import CHECKS, STATUSES
from core.config import POLICY_DIR, PROJECT_ROOT

QUERY_RESULTS = "data.compliance.results"
QUERY_VERSION = "data.compliance.policy_version"


class OPAError(RuntimeError):
    pass


def find_opa() -> str | None:
    """Locate the opa binary: $RDF_OPA_PATH, then PATH, then ./bin/opa."""
    env = os.environ.get("RDF_OPA_PATH")
    if env and os.access(env, os.X_OK):
        return env
    found = shutil.which("opa")
    if found:
        return found
    local = PROJECT_ROOT / "bin" / "opa"
    return str(local) if os.access(local, os.X_OK) else None


class OPARunner:
    def __init__(self, opa_path: str | None = None, policy_dir: str | Path = POLICY_DIR, timeout: float = 30.0):
        self.opa_path = opa_path or find_opa()
        if not self.opa_path:
            raise OPAError("OPA binary not found. Install it (see README) or set RDF_OPA_PATH.")
        self.policy_dir = str(policy_dir)
        self.timeout = timeout

    def _run(self, args: list[str], stdin: str | None = None) -> str:
        try:
            proc = subprocess.run([self.opa_path, *args], input=stdin, capture_output=True, text=True,
                                  timeout=self.timeout, check=False, shell=False)
        except FileNotFoundError as exc:
            raise OPAError(f"OPA binary not executable: {self.opa_path}") from exc
        except subprocess.TimeoutExpired as exc:
            raise OPAError(f"OPA timed out after {self.timeout}s") from exc
        if proc.returncode != 0:
            raise OPAError(f"opa {' '.join(args[:1])} failed (rc={proc.returncode}): {proc.stderr.strip()[:500]}")
        return proc.stdout

    def version(self) -> str:
        out = self._run(["version"])
        for line in out.splitlines():
            if line.lower().startswith("version:"):
                return line.split(":", 1)[1].strip()
        return out.strip().splitlines()[0] if out.strip() else "unknown"

    def eval_query(self, query: str, input_doc: Any) -> Any:
        out = self._run(["eval", "--data", self.policy_dir, "--stdin-input", "--format", "json", query],
                        stdin=json.dumps(input_doc))
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError as exc:
            raise OPAError(f"Unparseable OPA output: {exc}") from exc
        result = parsed.get("result") or []
        if not result or not result[0].get("expressions"):
            raise OPAError(f"Query {query} is undefined for this input")
        return result[0]["expressions"][0]["value"]

    def policy_version(self) -> str:
        return str(self.eval_query(QUERY_VERSION, {}))

    def evaluate(self, evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
        value = self.eval_query(QUERY_RESULTS, evidence)
        if not isinstance(value, dict):
            raise OPAError("data.compliance.results did not return an object")
        for cid in CHECKS:
            r = value.get(cid)
            if not isinstance(r, dict) or r.get("status") not in STATUSES:
                raise OPAError(f"Policy returned no valid status for {cid}")
        return value


def merge_results(evidence: dict[str, Any], opa_results: dict[str, dict[str, Any]],
                  evidence_hashes: dict[str, str]) -> list[dict[str, Any]]:
    """Combine OPA decisions with catalog metadata and the (normalized) evidence."""
    out = []
    for cid, info in CHECKS.items():
        decision = opa_results[cid]
        chk = evidence.get("checks", {}).get(cid)
        status = decision["status"]
        out.append({
            "check_id": cid,
            "title": info["title"],
            "status": status,
            "collector_status": chk.get("collector_status") if chk else None,
            "expected": decision.get("expected"),
            "actual": decision.get("actual"),
            "reason": decision.get("reason"),
            "remediation": None if status == "COMPLIANT" else info["remediation"],
            "evidence": {k: chk.get(k) for k in ("evidence", "sources", "errors", "limitations")} if chk else None,
            "evidence_hash": evidence_hashes.get(cid),
        })
    return out
