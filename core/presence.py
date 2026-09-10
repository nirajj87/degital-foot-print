"""
Public-only presence checks.

Looks up profile URLs and official public APIs. Does not log into
Instagram/Facebook, does not read private accounts, and does not query
people-search or leak databases.
"""
from __future__ import annotations

import hashlib
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote_plus

import requests

from core.username_sites import SITES  # edit username_sites.py to grow the catalog

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
APP_UA = "DFAnalyzer/1.1 (public-profile-check)"


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    return s


def _hit(status: str, site: dict, url: str, **extra) -> dict:
    row = {
        "site": site["id"],
        "name": site["name"],
        "url": url,
        "status": status,
        "confidence": extra.pop("confidence", "low"),
        "details": extra.pop("details", {}),
    }
    row.update(extra)
    return row


def _github(site, username, session, token=None):
    url = site["url"].format(u=username)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": APP_UA}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = session.get(f"https://api.github.com/users/{username}", headers=headers, timeout=10)
    if r.status_code == 404:
        return _hit("not_found", site, url, confidence="high")
    if r.status_code != 200:
        return _hit("unknown", site, url, confidence="low", error=f"http_{r.status_code}")
    j = r.json()
    if j.get("type") == "Organization" or j.get("message") == "Not Found":
        if not j.get("login"):
            return _hit("not_found", site, url, confidence="high")
    details = {
        k: j.get(k)
        for k in (
            "login",
            "name",
            "bio",
            "company",
            "location",
            "blog",
            "email",
            "twitter_username",
            "followers",
            "following",
            "public_repos",
            "public_gists",
            "created_at",
            "updated_at",
            "avatar_url",
            "html_url",
            "type",
        )
        if j.get(k) not in (None, "")
    }
    return _hit("found", site, j.get("html_url") or url, confidence="high", details=details)


def _gitlab(site, username, session, **_):
    url = site["url"].format(u=username)
    r = session.get(
        "https://gitlab.com/api/v4/users",
        params={"username": username},
        headers={"User-Agent": APP_UA},
        timeout=10,
    )
    if r.status_code != 200:
        return _hit("unknown", site, url, error=f"http_{r.status_code}")
    payload = r.json()
    items = payload if isinstance(payload, list) else []
    if not items:
        return _hit("not_found", site, url, confidence="high")
    u = items[0]
    details = {
        k: u.get(k)
        for k in ("username", "name", "web_url", "bio", "location", "public_email", "website_url", "avatar_url")
        if u.get(k)
    }
    return _hit("found", site, u.get("web_url") or url, confidence="high", details=details)


def _reddit(site, username, session, **_):
    url = site["url"].format(u=username)
    r = session.get(
        f"https://www.reddit.com/user/{username}/about.json",
        headers={"User-Agent": APP_UA},
        timeout=10,
    )
    if r.status_code == 404:
        return _hit("not_found", site, url, confidence="high")
    if r.status_code != 200:
        return _hit("unknown", site, url, error=f"http_{r.status_code}")
    data = (r.json() or {}).get("data") or {}
    if data.get("is_suspended") and not data.get("name"):
        return _hit("not_found", site, url, confidence="medium")
    sub = data.get("subreddit") or {}
    details = {
        "name": data.get("name"),
        "title": sub.get("title"),
        "public_description": sub.get("public_description"),
        "total_karma": data.get("total_karma"),
        "created_utc": data.get("created_utc"),
        "icon_img": data.get("icon_img"),
    }
    details = {k: v for k, v in details.items() if v not in (None, "")}
    return _hit("found", site, url, confidence="high", details=details)


def _devto(site, username, session, **_):
    url = site["url"].format(u=username)
    r = session.get(f"https://dev.to/api/users/by_username", params={"url": username}, headers={"User-Agent": APP_UA}, timeout=10)
    if r.status_code == 404:
        return _hit("not_found", site, url, confidence="high")
    if r.status_code != 200:
        return _hit("unknown", site, url, error=f"http_{r.status_code}")
    j = r.json()
    details = {k: j.get(k) for k in ("username", "name", "summary", "location", "website_url", "twitter_username", "github_username", "profile_image") if j.get(k)}
    return _hit("found", site, url, confidence="high", details=details)


def _hackernews(site, username, session, **_):
    url = site["url"].format(u=username)
    r = session.get(f"https://hacker-news.firebaseio.com/v0/user/{username}.json", timeout=10)
    if r.status_code != 200 or r.text in ("null", "null\n"):
        return _hit("not_found", site, url, confidence="high")
    j = r.json()
    if not j:
        return _hit("not_found", site, url, confidence="high")
    details = {k: j.get(k) for k in ("id", "karma", "created", "about") if j.get(k) not in (None, "")}
    return _hit("found", site, url, confidence="high", details=details)


def _keybase(site, username, session, **_):
    url = site["url"].format(u=username)
    r = session.get(
        "https://keybase.io/_/api/1.0/user/lookup.json",
        params={"username": username},
        timeout=10,
    )
    if r.status_code != 200:
        return _hit("unknown", site, url, error=f"http_{r.status_code}")
    j = r.json()
    if j.get("status", {}).get("code") != 0 or not j.get("them"):
        return _hit("not_found", site, url, confidence="high")
    them = j["them"][0] if isinstance(j["them"], list) else j["them"]
    profile = (them.get("profile") or {})
    proofs = []
    for p in ((them.get("proofs_summary") or {}).get("all") or []):
        proofs.append({"kind": p.get("proof_type"), "name": p.get("nametag"), "url": p.get("service_url")})
    details = {
        "username": (them.get("basics") or {}).get("username"),
        "full_name": profile.get("full_name"),
        "bio": profile.get("bio"),
        "location": profile.get("location"),
        "proofs": proofs,
    }
    details = {k: v for k, v in details.items() if v}
    return _hit("found", site, url, confidence="high", details=details)


def _html(site, username, session, **_):
    url = site["url"].format(u=username)
    try:
        r = session.get(url, timeout=10, allow_redirects=True)
    except Exception as e:
        return _hit("unknown", site, url, error=str(e))
    body = (r.text or "")[:20000].lower()
    if r.status_code in (404, 410):
        return _hit("not_found", site, url, confidence="high")
    for marker in site.get("not_found") or ():
        if marker.lower() in body:
            return _hit("not_found", site, url, confidence="medium")
    final = str(r.url)
    if username.lower() not in final.lower() and site["id"] not in ("hackernews",):
        return _hit("not_found", site, url, confidence="medium", message="Redirected away from this username.")
    for marker in site.get("found") or ():
        if marker.lower() in body:
            title = _og_title(r.text or "")
            return _hit("found", site, final, confidence="medium", details={"title": title} if title else {})
    if r.status_code == 200:
        title = _og_title(r.text or "") or ""
        if title and username.lower() in title.lower():
            return _hit("possible", site, final, confidence="medium", details={"title": title})
        return _hit(
            "possible",
            site,
            final,
            confidence="low",
            message="Page returned 200 but profile is not confirmed.",
        )
    return _hit("unknown", site, url, error=f"http_{r.status_code}")


def _og_title(html: str) -> str | None:
    m = re.search(r'property=["\']og:title["\']\s+content=["\']([^"\']+)', html, re.I)
    if not m:
        m = re.search(r'content=["\']([^"\']+)["\']\s+property=["\']og:title["\']', html, re.I)
    return m.group(1).strip() if m else None


_GENERIC_TITLES = {
    "twitch",
    "instagram",
    "facebook",
    "tiktok",
    "pinterest",
    "youtube",
    "x",
    "twitter",
    "linkedin",
    "medium",
    "threads",
    "telegram",
}


def _downgrade_generic(profile: dict, username: str) -> dict:
    """Drop 'found' when the page title is just the site name."""
    title = ((profile.get("details") or {}).get("title") or "").strip().lower()
    handle = username.lower()
    if profile.get("status") == "found" and title:
        core = title.split("–")[0].split("-")[0].split("|")[0].strip()
        if handle not in title and (core in _GENERIC_TITLES or core == (profile.get("name") or "").lower()):
            profile["status"] = "possible"
            profile["confidence"] = "low"
            profile["message"] = "Generic site title only; not treated as a confirmed profile."
    url = (profile.get("url") or "").lower()
    if profile.get("status") in ("found", "possible") and handle not in url and profile.get("site") != "hackernews":
        profile["status"] = "not_found"
        profile["confidence"] = "medium"
        profile["message"] = "Final URL does not contain this username."
    return profile


_HANDLERS = {
    "github": _github,
    "gitlab": _gitlab,
    "reddit": _reddit,
    "devto": _devto,
    "hackernews": _hackernews,
    "keybase": _keybase,
    "html": _html,
}


def check_username(username: str, github_token: str | None = None, max_workers: int = 10) -> dict:
    username = (username or "").strip().lstrip("@")
    if not username:
        return {"query": username, "profiles": [], "error": "empty_username"}

    session = _session()

    def run(site):
        handler = _HANDLERS.get(site["kind"], _html)
        try:
            return handler(site, username, session, token=github_token)
        except Exception as e:
            logging.debug("presence %s: %s", site["id"], e)
            return _hit("unknown", site, site["url"].format(u=username), error=str(e))

    profiles = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(run, site) for site in SITES]
        for fut in as_completed(futs):
            profiles.append(fut.result())

    for p in profiles:
        _downgrade_generic(p, username)

    order = {s["id"]: i for i, s in enumerate(SITES)}
    profiles.sort(key=lambda p: (p["status"] != "found", p["status"] != "possible", order.get(p["site"], 99)))

    found = [p for p in profiles if p["status"] == "found"]
    possible = [p for p in profiles if p["status"] == "possible"]
    extra_links = []
    for p in found:
        d = p.get("details") or {}
        if d.get("blog"):
            extra_links.append({"label": "GitHub blog/website", "url": d["blog"]})
        if d.get("twitter_username"):
            extra_links.append({"label": "Twitter from GitHub", "url": f"https://x.com/{d['twitter_username']}"})
        if d.get("website_url"):
            extra_links.append({"label": "Website", "url": d["website_url"]})
        for proof in d.get("proofs") or []:
            if proof.get("url"):
                extra_links.append({"label": f"Keybase {proof.get('kind')}", "url": proof["url"]})

    return {
        "query": username,
        "checked": len(profiles),
        "found_count": len(found),
        "possible_count": len(possible),
        "profiles": profiles,
        "linked_from_profiles": extra_links,
    }


def gravatar_lookup(email: str) -> dict:
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    avatar = f"https://www.gravatar.com/avatar/{digest}?d=404"
    profile_json = f"https://www.gravatar.com/{digest}.json"
    profile_page = f"https://gravatar.com/{digest}"
    session = _session()
    out = {"hash": digest, "avatar_url": None, "profile_url": profile_page, "status": "not_found", "details": {}, "accounts": []}
    try:
        img = session.get(avatar, timeout=8)
        if img.status_code == 200:
            out["avatar_url"] = avatar.replace("?d=404", "")
            out["status"] = "found"
    except Exception as e:
        out["error"] = str(e)
        return out
    try:
        r = session.get(profile_json, headers={"User-Agent": APP_UA}, timeout=8)
        if r.status_code == 200:
            entry = ((r.json() or {}).get("entry") or [None])[0] or {}
            out["status"] = "found"
            out["details"] = {
                "displayName": entry.get("displayName"),
                "aboutMe": entry.get("aboutMe"),
                "currentLocation": entry.get("currentLocation"),
                "preferredUsername": entry.get("preferredUsername"),
                "profileUrl": entry.get("profileUrl") or profile_page,
            }
            out["details"] = {k: v for k, v in out["details"].items() if v}
            for acc in entry.get("accounts") or []:
                out["accounts"].append(
                    {
                        "shortname": acc.get("shortname"),
                        "username": acc.get("username"),
                        "url": acc.get("url"),
                    }
                )
            if entry.get("profileUrl"):
                out["profile_url"] = entry["profileUrl"]
    except Exception:
        pass
    return out


def keybase_email_lookup(email: str) -> dict:
    try:
        r = requests.get(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"email": email},
            timeout=10,
            headers={"User-Agent": APP_UA},
        )
        if r.status_code != 200:
            return {"status": "unknown", "error": f"http_{r.status_code}"}
        j = r.json()
        if j.get("status", {}).get("code") != 0 or not j.get("them"):
            return {"status": "not_found"}
        them = j["them"][0] if isinstance(j["them"], list) else j["them"]
        username = (them.get("basics") or {}).get("username")
        proofs = []
        for p in ((them.get("proofs_summary") or {}).get("all") or []):
            proofs.append({"kind": p.get("proof_type"), "name": p.get("nametag"), "url": p.get("service_url")})
        return {
            "status": "found",
            "username": username,
            "profile_url": f"https://keybase.io/{username}" if username else None,
            "proofs": proofs,
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def parse_phone(number: str) -> dict:
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, number_type
    except ImportError:
        return {
            "status": "parsed_basic",
            "input": number,
            "digits": re.sub(r"\D", "", number),
            "message": "Install phonenumbers for country/carrier parsing.",
        }

    raw = number.strip()
    parsed = None
    for region in (None, "IN", "US"):
        try:
            parsed = phonenumbers.parse(raw, region)
            if phonenumbers.is_possible_number(parsed):
                break
        except Exception:
            parsed = None
    if not parsed:
        return {"status": "invalid", "input": number}

    ntype = number_type(parsed)
    type_name = {
        0: "fixed_line",
        1: "mobile",
        2: "fixed_or_mobile",
        3: "toll_free",
        4: "premium_rate",
        5: "shared_cost",
        6: "voip",
        7: "personal",
        10: "uan",
    }.get(int(ntype), str(ntype))
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    return {
        "status": "ok",
        "input": number,
        "e164": e164,
        "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "country": geocoder.country_name_for_number(parsed, "en") or None,
        "region_code": phonenumbers.region_code_for_number(parsed),
        "carrier": carrier.name_for_number(parsed, "en") or None,
        "number_type": type_name,
        "valid": phonenumbers.is_valid_number(parsed),
        "note": "Country/carrier come from the number itself, not a people-search database.",
    }


def public_search_links(query: str) -> list[dict]:
    q = quote_plus(query)
    return [
        {"label": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={q}"},
        {"label": "Google", "url": f"https://www.google.com/search?q={q}"},
        {"label": "GitHub search", "url": f"https://github.com/search?q={q}&type=users"},
    ]


def flatten_public_links(presence: dict, extras: list | None = None) -> list[dict]:
    links = []
    seen = set()

    def add(label, url, status="found"):
        if not url or url in seen:
            return
        seen.add(url)
        links.append({"label": label, "url": url, "status": status})

    for p in presence.get("profiles") or []:
        if p.get("status") not in ("found", "possible"):
            continue
        if p.get("status") == "possible" and p.get("confidence") == "low":
            continue
        add(p.get("name") or p.get("site"), p.get("url"), p.get("status"))
    for extra in presence.get("linked_from_profiles") or []:
        add(extra.get("label"), extra.get("url"), "found")
    for extra in extras or []:
        add(extra.get("label"), extra.get("url"), extra.get("status", "found"))
    return links
