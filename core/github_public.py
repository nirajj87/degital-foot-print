"""Public GitHub profile + light email correlation. No private repo access."""
from __future__ import annotations

import re

import requests

APP_UA = "DFAnalyzer/1.2"


def _headers(token=None):
    h = {"Accept": "application/vnd.github+json", "User-Agent": APP_UA}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(url, token=None, params=None, timeout=20):
    try:
        return requests.get(url, headers=_headers(token), params=params, timeout=timeout)
    except Exception:
        return None


def profile_card(user: dict) -> dict:
    keep = (
        "login",
        "name",
        "bio",
        "company",
        "location",
        "blog",
        "email",
        "twitter_username",
        "html_url",
        "avatar_url",
        "public_repos",
        "public_gists",
        "followers",
        "following",
        "created_at",
        "updated_at",
        "hireable",
        "type",
    )
    return {k: user.get(k) for k in keep if user.get(k) not in (None, "")}


def get_user(username: str, token=None) -> dict | None:
    r = _get(f"https://api.github.com/users/{username}", token)
    if not r or r.status_code != 200:
        return None
    data = r.json()
    if not data.get("login"):
        return None
    return profile_card(data)


def list_repos(username: str, token=None, limit: int = 12) -> list[dict]:
    r = _get(
        f"https://api.github.com/users/{username}/repos",
        token,
        params={"per_page": limit, "sort": "updated"},
    )
    if not r or r.status_code != 200:
        return []
    out = []
    for repo in r.json() or []:
        if not isinstance(repo, dict):
            continue
        out.append(
            {
                "name": repo.get("name"),
                "full_name": repo.get("full_name"),
                "url": repo.get("html_url"),
                "description": (repo.get("description") or "")[:180] or None,
                "language": repo.get("language"),
                "updated_at": repo.get("updated_at"),
                "homepage": repo.get("homepage") or None,
            }
        )
    return out


def _collect_logins(payload) -> list[str]:
    logins = []
    items = (payload or {}).get("items") if isinstance(payload, dict) else []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if item.get("login"):
            logins.append(item["login"])
        owner = item.get("owner") or item.get("user") or {}
        if isinstance(owner, dict) and owner.get("login"):
            logins.append(owner["login"])
        repo = item.get("repository") or {}
        if isinstance(repo, dict):
            o = repo.get("owner") or {}
            if o.get("login"):
                logins.append(o["login"])
    seen = set()
    unique = []
    for login in logins:
        low = login.lower()
        if low in seen:
            continue
        seen.add(low)
        unique.append(login)
    return unique


def search_github(kind: str, query: str, token=None, per_page: int = 8) -> dict:
    r = _get(f"https://api.github.com/search/{kind}", token, params={"q": query, "per_page": per_page})
    if not r:
        return {"ok": False, "error": "no_response", "items": []}
    if r.status_code in (401, 403):
        return {"ok": False, "error": f"http_{r.status_code}_need_token_or_rate_limit", "items": []}
    if r.status_code != 200:
        return {"ok": False, "error": f"http_{r.status_code}", "items": []}
    body = r.json() or {}
    return {"ok": True, "items": body.get("items") or [], "total": body.get("total_count")}


def find_accounts_for_email(email: str, token=None) -> dict:
    """
    Find public GitHub accounts that mention this email or matching login.
    Works better with a token; still tries public search without one.
    """
    local = email.split("@", 1)[0]
    queries = [
        ("repositories", f'"{email}"'),
        ("repositories", f"{local} in:readme"),
        ("users", local),
        ("issues", f'"{email}"'),
    ]
    hits = []
    errors = []
    logins = []

    for kind, q in queries:
        r = _get(f"https://api.github.com/search/{kind}", token, params={"q": q, "per_page": 5})
        if not r:
            errors.append({kind: "no_response"})
            continue
        if r.status_code in (401, 403):
            errors.append({kind: f"http_{r.status_code}_need_token_or_rate_limit"})
            continue
        if r.status_code != 200:
            errors.append({kind: f"http_{r.status_code}"})
            continue
        body = r.json()
        found = _collect_logins(body)
        logins.extend(found)
        for item in (body.get("items") or [])[:5]:
            hits.append(
                {
                    "kind": kind,
                    "title": item.get("full_name") or item.get("login") or item.get("title"),
                    "url": item.get("html_url"),
                }
            )

    # Always try the email local-part as a username.
    if get_user(local, token):
        logins.insert(0, local)

    seen = set()
    unique_logins = []
    for login in logins:
        if login.lower() in seen:
            continue
        seen.add(login.lower())
        unique_logins.append(login)

    accounts = []
    for login in unique_logins[:5]:
        card = get_user(login, token)
        if not card:
            continue
        repos = list_repos(login, token)
        accounts.append({"profile": card, "repos": repos, "matched_via": "public_github_search"})

    return {
        "query": email,
        "accounts": accounts,
        "search_hits": hits[:12],
        "errors": errors,
        "note": None
        if accounts
        else "No public GitHub account tied to this email via search. A GITHUB_TOKEN improves code/email search.",
    }


def enrich_username(username: str, token=None) -> dict:
    card = get_user(username, token)
    if not card:
        return {"status": "not_found", "username": username}
    return {
        "status": "found",
        "username": username,
        "profile": card,
        "repos": list_repos(username, token),
    }


def websites_from_accounts(accounts: list) -> list[dict]:
    links = []
    seen = set()
    for acc in accounts:
        profile = acc.get("profile") or {}
        blog = (profile.get("blog") or "").strip()
        if blog:
            url = blog if re.match(r"^https?://", blog, re.I) else f"https://{blog}"
            if url not in seen:
                seen.add(url)
                links.append({"label": f"Website from {profile.get('login')}", "url": url, "status": "found"})
        if profile.get("twitter_username"):
            url = f"https://x.com/{profile['twitter_username']}"
            if url not in seen:
                seen.add(url)
                links.append({"label": "X from GitHub", "url": url, "status": "found"})
        for repo in acc.get("repos") or []:
            home = (repo.get("homepage") or "").strip()
            if home and home not in seen and "github.com" not in home:
                seen.add(home)
                links.append({"label": f"Homepage · {repo.get('name')}", "url": home, "status": "found"})
    return links
