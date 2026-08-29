"""Flag public GitHub files that look like secrets or published emails."""
from __future__ import annotations

import base64
import re

import requests

APP_UA = "DFAnalyzer/1.3"

SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
    "serviceAccount.json",
    "secrets.json",
    "secret.json",
    "wp-config.php",
    "dump.sql",
    "backup.sql",
}

SENSITIVE_SUFFIX = (".pem", ".p12", ".pfx")


def _headers(token=None):
    h = {"Accept": "application/vnd.github+json", "User-Agent": APP_UA}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _get(url, token=None, timeout=12):
    try:
        return requests.get(url, headers=_headers(token), timeout=timeout)
    except Exception:
        return None


def _looks_sensitive(name: str) -> str | None:
    low = (name or "").lower()
    if low in {n.lower() for n in SENSITIVE_NAMES}:
        return f"Sensitive filename: {name}"
    if low.endswith(SENSITIVE_SUFFIX):
        return f"Key/cert file published: {name}"
    if low in ("config.py", "settings.py") and False:
        return None
    return None


def _repo_root(full_name: str, token=None) -> list[dict]:
    r = _get(f"https://api.github.com/repos/{full_name}/contents/", token)
    if not r or r.status_code != 200:
        return []
    data = r.json()
    return data if isinstance(data, list) else []


def _readme_text(full_name: str, token=None) -> str:
    r = _get(f"https://api.github.com/repos/{full_name}/readme", token)
    if not r or r.status_code != 200:
        return ""
    body = r.json() or {}
    encoded = body.get("content") or ""
    try:
        return base64.b64decode(encoded.replace("\n", "")).decode("utf-8", errors="replace")
    except Exception:
        return ""


def scan_accounts(accounts: list, email: str | None = None, token=None, repo_limit: int = 8) -> dict:
    flags = []
    email_l = (email or "").lower()
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    for acc in accounts or []:
        profile = acc.get("profile") or {}
        login = profile.get("login")
        repos = (acc.get("repos") or [])[:repo_limit]
        for repo in repos:
            name = repo.get("name")
            url = repo.get("url") or ""
            full = repo.get("full_name")
            if not full and login and name:
                full = f"{login}/{name}"
            if not full:
                continue
            for item in _repo_root(full, token):
                reason = _looks_sensitive(item.get("name") or "")
                if reason:
                    flags.append(
                        {
                            "severity": "high",
                            "kind": "sensitive_file",
                            "repo": full,
                            "file": item.get("name"),
                            "url": item.get("html_url") or url,
                            "detail": reason,
                        }
                    )
            readme = _readme_text(full, token)
            if not readme:
                continue
            found_emails = sorted(set(email_re.findall(readme)))
            if email_l and email_l in readme.lower():
                flags.append(
                    {
                        "severity": "medium",
                        "kind": "email_in_readme",
                        "repo": full,
                        "file": "README",
                        "url": f"https://github.com/{full}",
                        "detail": f"Public README contains {email}",
                    }
                )
            elif found_emails:
                flags.append(
                    {
                        "severity": "low",
                        "kind": "email_in_readme",
                        "repo": full,
                        "file": "README",
                        "url": f"https://github.com/{full}",
                        "detail": "README publishes email(s): " + ", ".join(found_emails[:3]),
                    }
                )

    return {"count": len(flags), "flags": flags}
