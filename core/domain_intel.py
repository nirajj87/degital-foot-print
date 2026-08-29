"""Domain hygiene: email auth, SSL age, WHOIS summary, public CT names."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from .network_tools import dns_lookup, fetch_ssl, whois_lookup

APP_UA = "DFAnalyzer/1.3"


def host_from_url(value: str | None) -> str | None:
    if not value:
        return None
    text = value.strip()
    if "://" not in text:
        text = "https://" + text
    host = (urlparse(text).hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host:
        return None
    return host


def _parse_spf(txt_records: list) -> dict:
    records = [t.strip().strip('"') for t in txt_records if "v=spf1" in t.lower()]
    if not records:
        return {"present": False, "record": None, "issue": "No SPF TXT record"}
    rec = records[0]
    issue = None
    if "+all" in rec.lower():
        issue = "SPF ends with +all (too open)"
    elif "?all" in rec.lower():
        issue = "SPF is neutral (?all) — weak"
    return {"present": True, "record": rec[:220], "issue": issue}


def _parse_dmarc(txt_records: list) -> dict:
    records = [t.strip().strip('"') for t in txt_records if "v=dmarc1" in t.lower()]
    if not records:
        return {"present": False, "policy": None, "record": None, "issue": "No DMARC record on _dmarc"}
    rec = records[0]
    policy = None
    m = re.search(r"p=([a-z]+)", rec, re.I)
    if m:
        policy = m.group(1).lower()
    issue = None
    if policy in (None, "none"):
        issue = "DMARC policy is none (monitor only)"
    return {"present": True, "policy": policy, "record": rec[:220], "issue": issue}


def _whois_summary(raw: dict) -> dict:
    if not raw or raw.get("error"):
        return {"error": (raw or {}).get("error") or "whois_failed"}

    def first(val):
        if isinstance(val, list) and val:
            return str(val[0])
        return str(val) if val not in (None, "", []) else None

    return {
        "registrar": first(raw.get("registrar")),
        "org": first(raw.get("org")),
        "created": first(raw.get("creation_date")),
        "expires": first(raw.get("expiration_date")),
        "country": first(raw.get("country")),
        "dnssec": first(raw.get("dnssec")),
    }


def _ssl_summary(raw: dict) -> dict:
    parsed = (raw or {}).get("parsed") or {}
    if raw.get("error") and not parsed:
        return {"error": raw.get("error")}
    not_after = parsed.get("not_after")
    days_left = None
    try:
        dt = datetime.fromisoformat(str(not_after).replace("Z", ""))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        days_left = (dt - datetime.now(timezone.utc)).days
    except Exception:
        days_left = None
    issue = None
    if days_left is not None and days_left < 0:
        issue = "Certificate expired"
    elif days_left is not None and days_left < 21:
        issue = f"Certificate expires in {days_left} days"
    return {
        "issuer": parsed.get("issuer"),
        "subject": parsed.get("subject"),
        "not_after": not_after,
        "days_left": days_left,
        "issue": issue,
    }


def _web_probe(domain: str) -> dict:
    out = {"status": None, "title": None, "server": None, "final_url": None}
    try:
        r = requests.get(
            f"https://{domain}",
            timeout=10,
            headers={"User-Agent": APP_UA},
            allow_redirects=True,
        )
        out["status"] = r.status_code
        out["server"] = r.headers.get("Server")
        out["final_url"] = str(r.url)
        m = re.search(r"<title[^>]*>([^<]+)</title>", r.text or "", re.I)
        if m:
            out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:160]
    except Exception as e:
        out["error"] = str(e)
    return out


def _ct_names(domain: str, limit: int = 12) -> list[str]:
    try:
        r = requests.get(
            "https://crt.sh/",
            params={"q": domain, "output": "json"},
            timeout=12,
            headers={"User-Agent": APP_UA},
        )
        if r.status_code != 200:
            return []
        names = []
        for row in r.json() or []:
            raw = row.get("name_value") or ""
            for part in str(raw).split("\n"):
                name = part.strip().lower().lstrip("*.")
                if name and domain in name:
                    names.append(name)
        seen = set()
        unique = []
        for n in names:
            if n in seen:
                continue
            seen.add(n)
            unique.append(n)
            if len(unique) >= limit:
                break
        return unique
    except Exception:
        return []


def inspect_domain(domain: str) -> dict:
    domain = (domain or "").lower().strip().lstrip(".")
    dns = dns_lookup(domain)
    txt = dns.get("TXT") if isinstance(dns.get("TXT"), list) else []
    dmarc_dns = dns_lookup(f"_dmarc.{domain}")
    dmarc_txt = dmarc_dns.get("TXT") if isinstance(dmarc_dns.get("TXT"), list) else []

    whois = _whois_summary(whois_lookup(domain))
    ssl = _ssl_summary(fetch_ssl(domain))
    spf = _parse_spf(txt)
    dmarc = _parse_dmarc(dmarc_txt)
    web = _web_probe(domain)
    ct = _ct_names(domain)

    issues = []
    for item in (spf, dmarc, ssl):
        if item.get("issue"):
            issues.append(item["issue"])
    mx = dns.get("MX") if isinstance(dns.get("MX"), list) else []
    if not mx:
        issues.append("No MX records (no mail on this domain)")

    return {
        "domain": domain,
        "whois": whois,
        "ssl": ssl,
        "spf": spf,
        "dmarc": dmarc,
        "mx": mx[:6],
        "ns": dns.get("NS") if isinstance(dns.get("NS"), list) else [],
        "web": web,
        "ct_names": ct,
        "issues": issues,
    }


def inspect_hosts(hosts: list[str], limit: int = 3) -> list[dict]:
    seen = set()
    out = []
    for host in hosts:
        h = host_from_url(host) or (host if host and "." in host else None)
        if not h or h in seen:
            continue
        seen.add(h)
        try:
            out.append(inspect_domain(h))
        except Exception as e:
            out.append({"domain": h, "error": str(e)})
        if len(out) >= limit:
            break
    return out
