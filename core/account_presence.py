"""
Email → registered-account scan across built-in modules + project extras.

Only scan emails you own or have written permission to assess.
"""
from __future__ import annotations

import logging
from typing import Any

from core.extra_email_sites import EXTRA_EMAIL_CHECKERS

log = logging.getLogger(__name__)


def scan_email_accounts(email: str, timeout: float = 10.0) -> dict[str, Any]:
    """Check whether `email` appears registered on known websites."""
    email = (email or "").strip()
    empty = {
        "status": "skipped",
        "engine": "account_presence",
        "reason": "not_an_email",
        "checked": 0,
        "found_count": 0,
        "not_found_count": 0,
        "rate_limited_count": 0,
        "error_count": 0,
        "found": [],
        "rate_limited": [],
        "all": [],
        "builtin_modules": 0,
        "extra_modules": 0,
    }
    if not email or "@" not in email:
        return empty

    try:
        import httpx
        import trio
        from holehe.core import get_functions, import_submodules
    except ImportError as exc:
        return {
            **empty,
            "status": "unavailable",
            "reason": f"site-check modules not installed: {exc}",
            "hint": "pip install -r requirements.txt",
        }

    modules = import_submodules("holehe.modules")
    websites = list(get_functions(modules))
    extras = list(EXTRA_EMAIL_CHECKERS)
    all_checkers = websites + extras
    out: list[dict] = []

    async def _launch(module, client, bucket):
        try:
            await module(email, client, bucket)
        except Exception as exc:  # noqa: BLE001
            bucket.append(
                {
                    "name": getattr(module, "__name__", "unknown"),
                    "domain": None,
                    "rateLimit": False,
                    "exists": False,
                    "emailrecovery": None,
                    "phoneNumber": None,
                    "others": None,
                    "error": str(exc),
                }
            )

    async def _run():
        client = httpx.AsyncClient(timeout=timeout)
        try:
            async with trio.open_nursery() as nursery:
                for website in all_checkers:
                    nursery.start_soon(_launch, website, client, out)
        finally:
            await client.aclose()

    try:
        trio.run(_run)
    except Exception as exc:  # noqa: BLE001
        log.exception("account presence scan failed")
        return {
            **empty,
            "status": "error",
            "reason": str(exc),
            "error_count": 1,
        }

    # Deduplicate by name (extras may overlap built-ins)
    by_name: dict[str, dict] = {}
    for row in out:
        key = str(row.get("name") or "")
        prev = by_name.get(key)
        if prev is None:
            by_name[key] = row
            continue
        # Prefer a definitive exists=True over rate-limit / false
        if row.get("exists") and not prev.get("exists"):
            by_name[key] = row
        elif row.get("exists") == prev.get("exists") and not row.get("rateLimit") and prev.get("rateLimit"):
            by_name[key] = row

    found, not_found, rate_limited, errors = [], [], [], []
    for row in sorted(by_name.values(), key=lambda r: str(r.get("name") or "")):
        item = {
            "name": row.get("name"),
            "domain": row.get("domain"),
            "exists": bool(row.get("exists")),
            "rate_limited": bool(row.get("rateLimit")),
            "email_recovery": row.get("emailrecovery") or None,
            "phone_recovery": row.get("phoneNumber") or None,
            "others": row.get("others"),
            "error": row.get("error"),
        }
        if item["error"]:
            errors.append(item)
        elif item["rate_limited"]:
            rate_limited.append(item)
        elif item["exists"]:
            found.append(item)
        else:
            not_found.append(item)

    return {
        "status": "ok",
        "engine": "account_presence",
        "checked": len(by_name),
        "module_count": len(all_checkers),
        "builtin_modules": len(websites),
        "extra_modules": len(extras),
        "found_count": len(found),
        "not_found_count": len(not_found),
        "rate_limited_count": len(rate_limited),
        "error_count": len(errors),
        "found": found,
        "rate_limited": rate_limited,
        "errors": errors,
        "all": found + rate_limited + not_found + errors,
    }
