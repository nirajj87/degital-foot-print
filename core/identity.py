from __future__ import annotations

import re
from urllib.parse import urlparse

PLATFORM_ALIASES = {
    "github": "github",
    "gh": "github",
    "gitlab": "gitlab",
    "instagram": "instagram",
    "insta": "instagram",
    "ig": "instagram",
    "facebook": "facebook",
    "fb": "facebook",
    "twitter": "twitter",
    "x": "twitter",
    "reddit": "reddit",
    "telegram": "telegram",
    "tg": "telegram",
    "youtube": "youtube",
    "yt": "youtube",
    "tiktok": "tiktok",
    "linkedin": "linkedin",
    "medium": "medium",
    "pinterest": "pinterest",
    "twitch": "twitch",
    "threads": "threads",
}

HOST_TO_PLATFORM = {
    "github.com": "github",
    "www.github.com": "github",
    "gitlab.com": "gitlab",
    "www.gitlab.com": "gitlab",
    "instagram.com": "instagram",
    "www.instagram.com": "instagram",
    "facebook.com": "facebook",
    "www.facebook.com": "facebook",
    "fb.com": "facebook",
    "twitter.com": "twitter",
    "www.twitter.com": "twitter",
    "x.com": "twitter",
    "www.x.com": "twitter",
    "reddit.com": "reddit",
    "www.reddit.com": "reddit",
    "t.me": "telegram",
    "telegram.me": "telegram",
    "youtube.com": "youtube",
    "www.youtube.com": "youtube",
    "tiktok.com": "tiktok",
    "www.tiktok.com": "tiktok",
    "linkedin.com": "linkedin",
    "www.linkedin.com": "linkedin",
    "medium.com": "medium",
    "pinterest.com": "pinterest",
    "www.pinterest.com": "pinterest",
    "twitch.tv": "twitch",
    "www.twitch.tv": "twitch",
    "threads.net": "threads",
    "www.threads.net": "threads",
}

_PHONE_RE = re.compile(r"^\+?[\d\s\-().]{8,20}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USER_RE = re.compile(r"^[A-Za-z0-9._-]{2,64}$")


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _username_from_path(platform: str, path: str) -> str:
    parts = [p for p in path.split("/") if p]
    if not parts:
        return ""
    if platform == "youtube" and parts[0].startswith("@"):
        return parts[0].lstrip("@")
    if platform == "reddit" and parts[0] in ("user", "u"):
        return parts[1] if len(parts) > 1 else ""
    if platform == "linkedin" and parts[0] in ("in", "company"):
        return parts[1] if len(parts) > 1 else ""
    if platform == "medium" and parts[0].startswith("@"):
        return parts[0].lstrip("@")
    if platform == "tiktok" and parts[0].startswith("@"):
        return parts[0].lstrip("@")
    return parts[0].lstrip("@")


def classify_target(raw: str, forced_type: str | None = None) -> dict:
    """
    Normalize an email, phone, username, domain, or profile URL.
    """
    original = (raw or "").strip()
    text = original
    hint = None

    if "://" not in text and text.lower().startswith(("www.", "github.com/", "instagram.com/", "facebook.com/", "fb.com/", "x.com/", "twitter.com/")):
        text = "https://" + text

    if "://" in text:
        parsed = urlparse(text)
        platform = HOST_TO_PLATFORM.get((parsed.netloc or "").lower())
        handle = _username_from_path(platform or "", parsed.path or "")
        return {
            "type": "username",
            "original": original,
            "value": handle or original,
            "username": handle or None,
            "platform_hint": platform,
            "url": text,
        }

    if ":" in text and "@" not in text:
        prefix, rest = text.split(":", 1)
        alias = PLATFORM_ALIASES.get(prefix.lower().strip())
        rest = rest.strip().lstrip("@/")
        if alias and rest:
            return {
                "type": "username",
                "original": original,
                "value": rest,
                "username": rest,
                "platform_hint": alias,
                "url": None,
            }

    if "/" in text and "@" not in text:
        prefix, rest = text.split("/", 1)
        alias = PLATFORM_ALIASES.get(prefix.lower().strip())
        rest = rest.strip().lstrip("@/")
        if alias and rest:
            return {
                "type": "username",
                "original": original,
                "value": rest,
                "username": rest,
                "platform_hint": alias,
                "url": None,
            }

    if text.startswith("@") and _USER_RE.match(text[1:]):
        return {
            "type": "username",
            "original": original,
            "value": text[1:],
            "username": text[1:],
            "platform_hint": hint,
            "url": None,
        }

    forced = (forced_type or "").lower().strip() or None
    if forced in ("user", "handle"):
        forced = "username"
    if forced == "mobile":
        forced = "phone"

    if forced == "email" or (not forced and _EMAIL_RE.match(text)):
        local = text.split("@", 1)[0]
        return {
            "type": "email",
            "original": original,
            "value": text.lower(),
            "username": local,
            "domain": text.split("@", 1)[1].lower() if "@" in text else None,
            "platform_hint": None,
            "url": None,
        }

    if forced == "phone" or (not forced and _PHONE_RE.match(text) and len(_digits(text)) >= 8):
        return {
            "type": "phone",
            "original": original,
            "value": text,
            "username": None,
            "platform_hint": None,
            "url": None,
        }

    _TLDS = {
        "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "name",
        "in", "io", "ai", "co", "uk", "us", "ca", "au", "de", "fr", "jp", "cn",
        "ru", "br", "pk", "bd", "np", "lk", "ae", "sa", "app", "dev", "me",
        "xyz", "online", "site", "tech", "store", "blog", "cloud", "id",
    }
    looks_domain = bool(re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,24}$", text))
    tld = text.rsplit(".", 1)[-1].lower() if "." in text else ""
    if forced == "domain" or (
        not forced
        and looks_domain
        and (tld in _TLDS or text.count(".") >= 2)
    ):
        return {
            "type": "domain",
            "original": original,
            "value": text.lower(),
            "username": None,
            "platform_hint": None,
            "url": None,
        }

    handle = text.lstrip("@")
    return {
        "type": "username",
        "original": original,
        "value": handle,
        "username": handle,
        "platform_hint": hint,
        "url": None,
    }
