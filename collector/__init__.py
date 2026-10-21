"""Evidence collector: runs the eight read-only checks and builds one
normalized, timestamped JSON evidence document (see evidence_schema.json)."""
from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any, Callable

import jsonschema

from collector.account_lockout_checks import collect_account_lockout
from collector.common import COLLECTOR_VERSION, Context, error_check, parse_key_value_file
from collector.file_permission_checks import collect_file_permissions
from collector.firewall_checks import collect_firewall
from collector.password_policy_checks import collect_password_policy
from collector.service_checks import collect_services
from collector.ssh_checks import collect_ssh
from collector.update_checks import collect_updates
from core.catalog import CHECKS
from core.timeutil import utc_now_iso

EVIDENCE_SCHEMA_VERSION = "1.0"
SCHEMA_PATH = Path(__file__).with_name("evidence_schema.json")

SINGLE_COLLECTORS: list[tuple[str, Callable[[Context], dict[str, Any]]]] = [
    ("FW-001", collect_firewall),
    ("SVC-001", collect_services),
    ("FILE-001", collect_file_permissions),
    ("PWD-001", collect_password_policy),
    ("LOCK-001", collect_account_lockout),
    ("UPD-001", collect_updates),
]


class EvidenceValidationError(ValueError):
    pass


def _os_release(ctx: Context) -> dict[str, Any]:
    text, err = ctx.read_text("/etc/os-release")
    if err:
        return {"id": None, "version_id": None, "pretty_name": None}
    kv = parse_key_value_file(text)
    return {"id": kv.get("id"), "version_id": kv.get("version_id"), "pretty_name": kv.get("pretty_name")}


def _hostname(ctx: Context) -> str | None:
    if ctx.root in ("", "/"):
        return socket.gethostname()
    text, err = ctx.read_text("/etc/hostname")
    return text.strip() if text and not err else None


def collect_evidence(ctx: Context, asset_id: str, data_origin: str = "HOST") -> dict[str, Any]:
    """Run all eight checks. A crash in one collector becomes an ERROR entry, never a gap."""
    checks: dict[str, Any] = {}
    try:
        checks.update(collect_ssh(ctx))
    except Exception as exc:  # noqa: BLE001 - isolate collector failures
        for cid in ("SSH-001", "SSH-002"):
            checks[cid] = error_check(cid, CHECKS[cid]["title"], exc)
    for cid, fn in SINGLE_COLLECTORS:
        try:
            checks[cid] = fn(ctx)
        except Exception as exc:  # noqa: BLE001
            checks[cid] = error_check(cid, CHECKS[cid]["title"], exc)
    doc = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "data_origin": data_origin,
        "collector_version": COLLECTOR_VERSION,
        "collected_at": utc_now_iso(),
        "asset": {"asset_id": asset_id, "hostname": _hostname(ctx), "os_release": _os_release(ctx)},
        "policy_params": ctx.policy_params,
        "checks": {cid: checks[cid] for cid in CHECKS},
    }
    validate_evidence(doc)
    return doc


def validate_evidence(doc: Any) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(doc, schema)
    except jsonschema.ValidationError as exc:
        loc = "/".join(str(p) for p in exc.absolute_path)
        raise EvidenceValidationError(f"evidence invalid at '{loc}': {exc.message}") from exc


def load_evidence(path: str | Path) -> dict[str, Any]:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceValidationError(f"cannot read evidence {path}: {exc}") from exc
    validate_evidence(doc)
    return doc
