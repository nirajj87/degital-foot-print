"""Compare this scan with the previous report for the same target."""
from __future__ import annotations

import json
import os
import re


def _safe(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9\-_]", "_", str(target).replace("@", "_at_"))


def previous_report(out_dir: str, target: str, current_path: str | None = None) -> dict | None:
    needle = _safe(target)
    files = []
    if not os.path.isdir(out_dir):
        return None
    for name in os.listdir(out_dir):
        if not name.startswith("report_") or not name.endswith(".json"):
            continue
        if needle not in name:
            continue
        path = os.path.join(out_dir, name)
        if current_path and os.path.abspath(path) == os.path.abspath(current_path):
            continue
        files.append(path)
    if not files:
        return None
    files.sort(key=os.path.getmtime, reverse=True)
    try:
        with open(files[0], encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _breach_names(report: dict) -> set[str]:
    rows = ((report.get("results") or {}).get("breaches") or {}).get("breaches") or []
    raw = (report.get("results") or {}).get("hibp")
    names = {str(r.get("name")).lower() for r in rows if r.get("name")}
    if not names and isinstance(raw, dict):
        for group in raw.get("breaches") or []:
            if isinstance(group, list):
                names.update(str(x).lower() for x in group)
    return names


def _repo_names(report: dict) -> set[str]:
    names = set()
    accounts = ((report.get("view") or {}).get("github_accounts")) or []
    if not accounts:
        accounts = ((report.get("results") or {}).get("github_accounts") or {}).get("accounts") or []
    for acc in accounts:
        for repo in acc.get("repos") or []:
            if repo.get("name"):
                names.add(repo["name"].lower())
    return names


def diff_reports(previous: dict | None, current: dict) -> dict:
    if not previous:
        return {"has_previous": False, "new_breaches": [], "new_repos": [], "risk_delta": None}
    prev_b = _breach_names(previous)
    cur_b = _breach_names(current)
    prev_r = _repo_names(previous)
    cur_r = _repo_names(current)
    prev_score = ((previous.get("risk_analysis") or {}).get("score")) or 0
    cur_score = ((current.get("risk_analysis") or {}).get("score")) or 0
    return {
        "has_previous": True,
        "previous_timestamp": previous.get("timestamp"),
        "new_breaches": sorted(cur_b - prev_b),
        "new_repos": sorted(cur_r - prev_r),
        "risk_delta": cur_score - prev_score,
    }
