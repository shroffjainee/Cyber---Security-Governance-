"""FILE-001 — permissions/ownership of /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow.

Uses ``os.stat`` only (metadata), so it works without root and never reads
file contents.  Owner/group names are resolved from the numeric IDs via the
host's account databases (``pwd``/``grp``) when collecting from the live
root; for fixture trees, numeric ids 0 -> root and the gid of 'shadow' are
mapped through an optional ``etc/group`` in the fixture.
"""
from __future__ import annotations

import grp
import os
import pwd
import stat
from typing import Any

from collector.common import Context, make_check

FILES = ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow")


def _fixture_group_names(ctx: Context) -> dict[int, str]:
    text, err = ctx.read_text("/etc/group")
    names = {0: "root"}
    if not err and text:
        for line in text.splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2].isdigit():
                names[int(parts[2])] = parts[0]
    return names


def _name_uid(uid: int, live: bool) -> str | None:
    if not live:
        return "root" if uid == 0 else None
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def _name_gid(gid: int, live: bool, fixture_map: dict[int, str]) -> str | None:
    if not live:
        return fixture_map.get(gid)
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return None


def collect_file_permissions(ctx: Context) -> dict[str, Any]:
    title = "Account database file permissions and ownership"
    live = ctx.root in ("", "/")
    fixture_map = {} if live else _fixture_group_names(ctx)
    baseline = ctx.policy_params.get("file_baseline", {})
    files: dict[str, Any] = {}
    errors: list[str] = []
    sources: list[str] = []
    for path in sorted(set(FILES) | set(baseline)):
        try:
            st = os.stat(ctx.path(path), follow_symlinks=False)
        except FileNotFoundError:
            files[path] = {"exists": False, "mode": None, "mode_octal": None, "owner": None,
                           "group": None, "uid": None, "gid": None, "is_regular": None}
            if path in ("/etc/passwd", "/etc/shadow"):
                errors.append(f"{path}: missing")
            continue
        except OSError as exc:
            files[path] = {"exists": None, "mode": None, "mode_octal": None, "owner": None,
                           "group": None, "uid": None, "gid": None, "is_regular": None}
            errors.append(f"{path}: {exc.strerror}")
            continue
        mode = stat.S_IMODE(st.st_mode)
        files[path] = {
            "exists": True,
            "mode": mode,
            "mode_octal": format(mode, "04o"),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "owner": _name_uid(st.st_uid, live),
            "group": _name_gid(st.st_gid, live, fixture_map),
            "is_regular": stat.S_ISREG(st.st_mode),
        }
        sources.append(f"stat {path}")
    determined = [f for f in files.values() if f["exists"]]
    status = "ERROR" if not determined else ("PARTIAL" if errors else "OK")
    return make_check("FILE-001", title, status, {"files": files}, sources, errors)
