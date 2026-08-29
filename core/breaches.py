"""Normalize breach APIs into a short, actionable list."""
from __future__ import annotations

from .utils import safe_get

# Extra context when a provider only returns a name.
CATALOG = {
    "canva": {
        "year": "2019",
        "data": "Email, name, password (hashed)",
        "action": "Reset Canva password if you still use that account. Do not reuse it on Gmail.",
    },
    "000webhost": {
        "year": "2015",
        "data": "Email, IP, plaintext password",
        "action": "If you ever hosted there, that old password is public. Never reuse it.",
    },
    "boat": {
        "year": "2020s",
        "data": "Email and account fields from a consumer-brand list",
        "action": "Reset boAt / related shop login if it still exists.",
    },
    "collection-1": {
        "year": "2019",
        "data": "Email + password combos from many older leaks",
        "action": "Treat any reused password as burned. Unique password + 2FA on email.",
    },
    "1.4billionrecords": {
        "year": "compiled list",
        "data": "Email (often with passwords from other leaks)",
        "action": "Same as other combo lists: unique passwords everywhere.",
    },
    "exploitin": {
        "year": "compiled list",
        "data": "Aggregated emails/passwords",
        "action": "Assume this address is on combo lists used for password spraying.",
    },
    "pemiblanc": {
        "year": "compiled list",
        "data": "Aggregated leak set",
        "action": "Rotate reused passwords; enable 2FA.",
    },
}


def _names_from_xon(payload) -> list[str]:
    names = []
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, list):
                names.extend(x for x in item if isinstance(x, str))
    elif isinstance(payload, dict):
        for key in ("breaches", "Breaches"):
            names.extend(_names_from_xon(payload.get(key)))
    return names


def _catalog_row(name: str) -> dict:
    meta = CATALOG.get(name.lower().replace(" ", "")) or CATALOG.get(name.lower())
    row = {"name": name, "year": None, "domain": None, "data": None, "action": None}
    if meta:
        row.update(meta)
        row["name"] = name
    return row


def fetch_xon_analytics(email: str) -> dict:
    r = safe_get(
        "https://api.xposedornot.com/v1/breach-analytics",
        params={"email": email},
        headers={"User-Agent": "DFAnalyzer/1.2"},
        timeout=20,
    )
    if not r or r.status_code != 200:
        return {}
    try:
        return r.json() or {}
    except Exception:
        return {}


def normalize_breaches(email: str, hibp_raw, key=None) -> dict:
    """
    Always return:
      source, count, breaches[{name, year, domain, data, action}]
    """
    rows = []
    source = "none"

    analytics = fetch_xon_analytics(email)
    details = (
        ((analytics.get("ExposedBreaches") or {}).get("breaches_details"))
        or ((analytics.get("exposedBreaches") or {}).get("breaches_details"))
        or []
    )
    if isinstance(details, list) and details:
        source = "xposedornot_analytics"
        for item in details:
            if not isinstance(item, dict):
                continue
            name = item.get("breach") or item.get("name") or item.get("Name")
            if not name:
                continue
            base = _catalog_row(name)
            base.update(
                {
                    "name": name,
                    "year": item.get("xposed_date") or item.get("breachedDate") or base.get("year"),
                    "domain": item.get("domain"),
                    "data": item.get("xposed_data") or item.get("xposed_records") or base.get("data"),
                    "verified": item.get("verified"),
                    "password_risk": item.get("password_risk"),
                }
            )
            if not base.get("action"):
                base["action"] = f"If you used {name}, change that password and do not reuse it on email."
            rows.append(base)

    if not rows:
        if isinstance(hibp_raw, list) and hibp_raw and isinstance(hibp_raw[0], dict):
            source = "hibp"
            for item in hibp_raw:
                name = item.get("Name") or item.get("Title") or "Unknown"
                base = _catalog_row(name)
                base.update(
                    {
                        "name": name,
                        "year": (item.get("BreachDate") or "")[:4] or base.get("year"),
                        "domain": item.get("Domain"),
                        "data": ", ".join(item.get("DataClasses") or []) or base.get("data"),
                    }
                )
                rows.append(base)
        else:
            names = _names_from_xon(hibp_raw)
            if names:
                source = "xposedornot"
                rows = [_catalog_row(n) for n in names]
                for row in rows:
                    if not row.get("action"):
                        row["action"] = f"If you used {row['name']}, change that password."

    seen = set()
    unique = []
    for row in rows:
        keyn = (row.get("name") or "").lower()
        if keyn in seen:
            continue
        seen.add(keyn)
        unique.append(row)

    return {
        "source": source,
        "email": email,
        "count": len(unique),
        "breaches": unique,
        "raw_status": None if unique else (hibp_raw if isinstance(hibp_raw, dict) else None),
    }
