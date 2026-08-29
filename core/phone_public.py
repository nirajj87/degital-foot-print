"""Find public pages that mention a phone number. No people-search or leak DBs."""
from __future__ import annotations

import os
import re
from urllib.parse import quote_plus

import requests

from .github_public import search_github

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "osint_output",
    "__pycache__",
    "dist",
    "build",
    ".next",
}

APP_UA = "DFAnalyzer/1.3"


def variants_from_phone(phone: dict) -> list[str]:
    e164 = phone.get("e164") or ""
    digits = re.sub(r"\D", "", e164 or phone.get("input") or "")
    last10 = digits[-10:] if len(digits) >= 10 else digits
    intl = phone.get("international") or ""
    out = []
    for item in (
        e164,
        digits,
        last10,
        intl,
        f"+91{last10}" if len(last10) == 10 else None,
        f"+91 {last10}" if len(last10) == 10 else None,
        f"+91 {last10[:5]} {last10[5:]}" if len(last10) == 10 else None,
        f"0{last10}" if len(last10) == 10 else None,
        f"{last10[:5]} {last10[5:]}" if len(last10) == 10 else None,
        f"{last10[:5]}-{last10[5:]}" if len(last10) == 10 else None,
        f"91-{last10}" if len(last10) == 10 else None,
    ):
        if item and item not in out:
            out.append(item)
    return out


def _needles(variants: list[str]) -> list[str]:
    needles = []
    for v in variants:
        compact = re.sub(r"\D", "", v)
        if compact and compact not in needles:
            needles.append(compact)
        if v not in needles:
            needles.append(v)
    return needles


def _page_contains(url: str, needles: list[str]) -> bool:
    try:
        r = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": APP_UA},
            allow_redirects=True,
        )
        if r.status_code >= 400:
            return False
        text = r.text or ""
        compact = re.sub(r"\D", "", text)
        for n in needles:
            if n.isdigit() and len(n) >= 10 and n in compact:
                return True
            if n in text:
                return True
    except Exception:
        return False
    return False


def find_local_mentions(needles: list[str], roots: list[str]) -> list[dict]:
    hits = []
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(path) > 1_500_000:
                        continue
                    with open(path, encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                except Exception:
                    continue
                compact = re.sub(r"\D", "", text)
                if not any((n.isdigit() and len(n) >= 10 and n in compact) or (n in text) for n in needles):
                    continue
                rel = os.path.relpath(path, root)
                hits.append(
                    {
                        "source": "local_workspace",
                        "title": rel,
                        "url": path,
                        "repo": os.path.basename(root),
                        "confirmed": True,
                    }
                )
    return hits


def find_public_mentions(phone: dict, token=None, workspace_roots=None) -> dict:
    variants = variants_from_phone(phone)
    needles = _needles(variants)
    last10 = next((v for v in variants if v.isdigit() and len(v) == 10), "")
    hits = []
    seen = set()
    errors = []

    queries = []
    if last10:
        queries.append(("code", f'"{last10}"'))
        queries.append(("repositories", f'"{last10}"'))
        queries.append(("issues", f'"{last10}"'))
    e164 = phone.get("e164")
    if e164:
        queries.append(("code", f'"{e164}"'))
        queries.append(("issues", f'"{e164}"'))

    for hit in find_local_mentions(needles, workspace_roots or []):
        if hit["url"] not in seen:
            seen.add(hit["url"])
            hits.append(hit)

    for kind, q in queries:
        result = search_github(kind, q, token, per_page=8)
        if not result.get("ok"):
            errors.append({kind: result.get("error")})
            continue
        for item in result.get("items") or []:
            url = item.get("html_url")
            title = item.get("full_name") or item.get("path") or item.get("title") or item.get("login")
            if not url or url in seen:
                continue
            seen.add(url)
            repo = (item.get("repository") or {}).get("full_name") or item.get("full_name")
            hits.append(
                {
                    "source": f"github_{kind}",
                    "title": title,
                    "url": url,
                    "repo": repo,
                    "confirmed": None,
                }
            )

    for hit in hits:
        hit["confirmed"] = _page_contains(hit["url"], needles)

    search_links = []
    for label, url in (
        ("DuckDuckGo quoted", f"https://duckduckgo.com/?q={quote_plus('\"' + (e164 or last10) + '\"')}"),
        ("Google quoted", f"https://www.google.com/search?q={quote_plus('\"' + (e164 or last10) + '\"')}"),
        ("GitHub code", f"https://github.com/search?q={quote_plus(last10 or e164 or '')}&type=code"),
        ("GitHub issues", f"https://github.com/search?q={quote_plus(last10 or '')}&type=issues"),
    ):
        if last10 or e164:
            search_links.append({"label": label, "url": url})

    confirmed = [h for h in hits if h.get("confirmed")]
    return {
        "variants": variants,
        "hits": hits,
        "confirmed_count": len(confirmed),
        "search_links": search_links,
        "errors": errors,
        "note": "Public GitHub/web mentions only. Hidden WhatsApp/Truecaller data is not queried.",
    }
