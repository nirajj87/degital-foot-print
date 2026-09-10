"""
Extra email → account checks beyond the built-in 120+ module set.

Each checker follows the same async contract:
  await fn(email, httpx_client, out_list)

out_list items use keys: name, domain, rateLimit, exists, emailrecovery, phoneNumber, others
"""
from __future__ import annotations

import random
import string
from typing import Any, Awaitable, Callable

Checker = Callable[[str, Any, list], Awaitable[None]]

_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
]


def _row(name: str, domain: str, *, exists=False, rate_limit=False, emailrecovery=None, phone=None, others=None):
    return {
        "name": name,
        "domain": domain,
        "rateLimit": rate_limit,
        "exists": exists,
        "emailrecovery": emailrecovery,
        "phoneNumber": phone,
        "others": others,
    }


def _rand(n: int = 12) -> str:
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


async def microsoft(email, client, out):
    name, domain = "microsoft", "microsoft.com"
    try:
        r = await client.post(
            "https://login.microsoftonline.com/common/GetCredentialType",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/json"},
            json={"username": email, "isOtherIdpSupported": True, "checkPhones": False, "isRemoteNGCSupported": True},
        )
        if r.status_code != 200:
            out.append(_row(name, domain, rate_limit=True))
            return
        data = r.json()
        # IfExistsResult: 0 = exists, 1 = not, 5/6 = exists federated/consumer variants commonly used in OSINT
        code = data.get("IfExistsResult")
        if code in (0, 5, 6):
            out.append(_row(name, domain, exists=True))
        elif code == 1:
            out.append(_row(name, domain, exists=False))
        else:
            out.append(_row(name, domain, rate_limit=True, others={"IfExistsResult": code}))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def linkedin(email, client, out):
    name, domain = "linkedin", "linkedin.com"
    try:
        r = await client.get(
            "https://www.linkedin.com/uas/request-password-reset",
            headers={"User-Agent": random.choice(_UA)},
        )
        if r.status_code >= 400:
            out.append(_row(name, domain, rate_limit=True))
            return
        # Soft signal: many LinkedIn flows do not expose a clean boolean; mark unknown as rate-limit
        # rather than inventing a hit. Keep probe for future endpoint updates.
        out.append(_row(name, domain, rate_limit=True, others={"note": "endpoint guarded"}))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def paypal(email, client, out):
    name, domain = "paypal", "paypal.com"
    try:
        r = await client.post(
            "https://www.paypal.com/authflow/password-recovery/",
            headers={
                "User-Agent": random.choice(_UA),
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={"email": email},
        )
        text = (r.text or "").lower()
        if r.status_code in (429, 403):
            out.append(_row(name, domain, rate_limit=True))
        elif "not found" in text or "doesn't match" in text or "does not match" in text:
            out.append(_row(name, domain, exists=False))
        elif r.status_code == 200 and ("success" in text or "sent" in text or "code" in text):
            out.append(_row(name, domain, exists=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def dropbox(email, client, out):
    name, domain = "dropbox", "dropbox.com"
    try:
        r = await client.post(
            "https://www.dropbox.com/sso_login_check",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/x-www-form-urlencoded"},
            data={"email": email},
        )
        if r.status_code in (429, 403):
            out.append(_row(name, domain, rate_limit=True))
            return
        j = {}
        try:
            j = r.json()
        except Exception:
            pass
        status = str(j.get("status") or j.get("result") or "").lower()
        if "does_not_exist" in status or status in ("not_found", "no"):
            out.append(_row(name, domain, exists=False))
        elif "exists" in status or j.get("sso") is not None:
            out.append(_row(name, domain, exists=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def slack(email, client, out):
    name, domain = "slack", "slack.com"
    try:
        r = await client.post(
            "https://slack.com/api/signup.checkEmail",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/x-www-form-urlencoded"},
            data={"email": email},
        )
        j = r.json() if r.status_code == 200 else {}
        if j.get("ok") and j.get("email_valid") is False:
            out.append(_row(name, domain, exists=False))
        elif j.get("ok") and (j.get("email_taken") or j.get("auth_url")):
            out.append(_row(name, domain, exists=True))
        elif r.status_code in (429, 403) or not j.get("ok"):
            out.append(_row(name, domain, rate_limit=True))
        else:
            out.append(_row(name, domain, exists=False))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def steam(email, client, out):
    name, domain = "steam", "steampowered.com"
    try:
        r = await client.post(
            "https://store.steampowered.com/join/checkavail/",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/x-www-form-urlencoded"},
            data={"email": email, "count": "1"},
        )
        j = r.json() if r.status_code == 200 else {}
        if j.get("bAvailable") is True:
            out.append(_row(name, domain, exists=False))
        elif j.get("bAvailable") is False:
            out.append(_row(name, domain, exists=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def duolingo(email, client, out):
    name, domain = "duolingo", "duolingo.com"
    try:
        r = await client.get(
            "https://www.duolingo.com/2017-06-30/users",
            params={"email": email},
            headers={"User-Agent": random.choice(_UA)},
        )
        if r.status_code == 404:
            out.append(_row(name, domain, exists=False))
        elif r.status_code == 200:
            j = r.json()
            users = j.get("users") if isinstance(j, dict) else None
            out.append(_row(name, domain, exists=bool(users)))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def wordpress_com(email, client, out):
    name, domain = "wordpress_com", "wordpress.com"
    try:
        r = await client.get(
            "https://public-api.wordpress.com/rest/v1.1/users/",
            params={"email": email},
            headers={"User-Agent": random.choice(_UA)},
        )
        if r.status_code == 200:
            j = r.json()
            found = bool(j.get("found") or j.get("ID") or j.get("username"))
            out.append(_row(name, domain, exists=found))
        elif r.status_code == 404:
            out.append(_row(name, domain, exists=False))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def bitbucket(email, client, out):
    name, domain = "bitbucket", "bitbucket.org"
    try:
        r = await client.post(
            "https://bitbucket.org/!api/internal/email-availability",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/json"},
            json={"email": email},
        )
        if r.status_code == 200:
            j = r.json()
            # available true => not registered
            if "available" in j:
                out.append(_row(name, domain, exists=not bool(j.get("available"))))
            else:
                out.append(_row(name, domain, rate_limit=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def npm(email, client, out):
    name, domain = "npm", "npmjs.com"
    try:
        # npm does not expose a clean public email-exists API; probe forgot-password page soft-fail
        r = await client.post(
            "https://www.npmjs.com/forgot",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/x-www-form-urlencoded"},
            data={"email": email},
        )
        text = (r.text or "").lower()
        if r.status_code in (429, 403):
            out.append(_row(name, domain, rate_limit=True))
        elif "no user" in text or "not found" in text:
            out.append(_row(name, domain, exists=False))
        elif r.status_code in (200, 302):
            out.append(_row(name, domain, rate_limit=True, others={"note": "ambiguous"}))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def huggingface(email, client, out):
    name, domain = "huggingface", "huggingface.co"
    try:
        r = await client.post(
            "https://huggingface.co/api/users/check-email",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/json"},
            json={"email": email},
        )
        if r.status_code == 200:
            j = r.json()
            if "exists" in j:
                out.append(_row(name, domain, exists=bool(j.get("exists"))))
            elif "available" in j:
                out.append(_row(name, domain, exists=not bool(j.get("available"))))
            else:
                out.append(_row(name, domain, rate_limit=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def canva(email, client, out):
    name, domain = "canva", "canva.com"
    try:
        r = await client.post(
            "https://www.canva.com/_ajax/email/exists",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/json"},
            json={"email": email},
        )
        if r.status_code == 200:
            j = r.json()
            if "exists" in j:
                out.append(_row(name, domain, exists=bool(j.get("exists"))))
            else:
                out.append(_row(name, domain, rate_limit=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def notion(email, client, out):
    name, domain = "notion", "notion.so"
    try:
        r = await client.post(
            "https://www.notion.so/api/v3/getLoginOptions",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/json"},
            json={"email": email},
        )
        if r.status_code == 200:
            j = r.json()
            # hasAccount / found patterns vary
            if j.get("hasAccount") is True or j.get("found") is True:
                out.append(_row(name, domain, exists=True))
            elif j.get("hasAccount") is False or j.get("found") is False:
                out.append(_row(name, domain, exists=False))
            else:
                out.append(_row(name, domain, rate_limit=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def zoom(email, client, out):
    name, domain = "zoom", "zoom.us"
    try:
        r = await client.post(
            "https://zoom.us/signin",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/x-www-form-urlencoded"},
            data={"email": email, "type": "1"},
        )
        text = (r.text or "").lower()
        if "does not exist" in text or "not exist" in text:
            out.append(_row(name, domain, exists=False))
        elif "password" in text or "captcha" in text:
            out.append(_row(name, domain, exists=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def airbnb(email, client, out):
    name, domain = "airbnb", "airbnb.com"
    try:
        r = await client.post(
            "https://www.airbnb.com/api/v2/auth_flows",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/json"},
            json={"email": email},
        )
        if r.status_code in (429, 403):
            out.append(_row(name, domain, rate_limit=True))
        elif r.status_code == 200:
            text = (r.text or "").lower()
            if "not_found" in text or "no_account" in text:
                out.append(_row(name, domain, exists=False))
            elif "account" in text or "password" in text:
                out.append(_row(name, domain, exists=True))
            else:
                out.append(_row(name, domain, rate_limit=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def chess(email, client, out):
    name, domain = "chess", "chess.com"
    try:
        r = await client.post(
            "https://www.chess.com/callback/email/available",
            headers={"User-Agent": random.choice(_UA), "Content-Type": "application/json"},
            json={"email": email},
        )
        if r.status_code == 200:
            j = r.json()
            if "isAvailable" in j:
                out.append(_row(name, domain, exists=not bool(j.get("isAvailable"))))
            elif "available" in j:
                out.append(_row(name, domain, exists=not bool(j.get("available"))))
            else:
                out.append(_row(name, domain, rate_limit=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def roblox(email, client, out):
    name, domain = "roblox", "roblox.com"
    try:
        r = await client.get(
            "https://auth.roblox.com/v2/passwords/reset",
            params={"request": email, "type": "Email"},
            headers={"User-Agent": random.choice(_UA)},
        )
        if r.status_code in (429, 403):
            out.append(_row(name, domain, rate_limit=True))
        elif r.status_code == 200:
            out.append(_row(name, domain, exists=True))
        elif r.status_code == 404:
            out.append(_row(name, domain, exists=False))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


async def twitter_x(email, client, out):
    """X/Twitter email availability (often rate-limited / captcha)."""
    name, domain = "twitter_x", "x.com"
    try:
        r = await client.get(
            "https://api.x.com/i/users/email_available.json",
            params={"email": email},
            headers={"User-Agent": random.choice(_UA)},
        )
        if r.status_code == 200:
            j = r.json()
            if "taken" in j:
                out.append(_row(name, domain, exists=bool(j.get("taken"))))
            elif "valid" in j and j.get("taken") is False:
                out.append(_row(name, domain, exists=False))
            else:
                out.append(_row(name, domain, rate_limit=True))
        else:
            out.append(_row(name, domain, rate_limit=True))
    except Exception:
        out.append(_row(name, domain, rate_limit=True))


EXTRA_EMAIL_CHECKERS: list[Checker] = [
    microsoft,
    linkedin,
    paypal,
    dropbox,
    slack,
    steam,
    duolingo,
    wordpress_com,
    bitbucket,
    npm,
    huggingface,
    canva,
    notion,
    zoom,
    airbnb,
    chess,
    roblox,
    twitter_x,
]

EXTRA_EMAIL_SITE_META = [
    {"name": fn.__name__, "domain": {
        "microsoft": "microsoft.com",
        "linkedin": "linkedin.com",
        "paypal": "paypal.com",
        "dropbox": "dropbox.com",
        "slack": "slack.com",
        "steam": "steampowered.com",
        "duolingo": "duolingo.com",
        "wordpress_com": "wordpress.com",
        "bitbucket": "bitbucket.org",
        "npm": "npmjs.com",
        "huggingface": "huggingface.co",
        "canva": "canva.com",
        "notion": "notion.so",
        "zoom": "zoom.us",
        "airbnb": "airbnb.com",
        "chess": "chess.com",
        "roblox": "roblox.com",
        "twitter_x": "x.com",
    }.get(fn.__name__, fn.__name__)}
    for fn in EXTRA_EMAIL_CHECKERS
]
