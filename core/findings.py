"""Turn raw module output into a short list a person can act on."""
from __future__ import annotations

CONSUMER_MAIL = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.co.in",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "aol.com",
    "rediffmail.com",
}


def is_consumer_mail(domain: str | None) -> bool:
    return (domain or "").lower() in CONSUMER_MAIL


def build_findings(report: dict) -> dict:
    results = report.get("results") or {}
    identity = report.get("identity") or {}
    findings = []
    actions = []
    people = []

    breaches = results.get("breaches") or {}
    for b in breaches.get("breaches") or []:
        findings.append(
            {
                "severity": "high",
                "title": f"Email seen in public breach: {b.get('name')}",
                "detail": " · ".join(
                    x
                    for x in (
                        f"Year: {b['year']}" if b.get("year") else None,
                        f"Data: {b['data']}" if b.get("data") else None,
                        f"Site: {b['domain']}" if b.get("domain") else None,
                    )
                    if x
                )
                or "Name only — treat as a known leak list.",
                "action": b.get("action"),
            }
        )
        if b.get("action"):
            actions.append(b["action"])

    if breaches.get("count"):
        actions.insert(
            0,
            "Put a unique password on this mailbox and turn on 2-step verification.",
        )

    accounts = []
    gh = results.get("github_accounts") or {}
    accounts.extend(gh.get("accounts") or [])
    one = results.get("github_profile")
    if one and one.get("status") == "found" and one.get("profile"):
        login = (one["profile"].get("login") or "").lower()
        if login not in {(a.get("profile") or {}).get("login", "").lower() for a in accounts}:
            accounts.append(one)

    for acc in accounts:
        p = acc.get("profile") or {}
        if not p:
            continue
        people.append(p)
        bits = [p.get("name"), p.get("company"), p.get("location"), p.get("blog")]
        findings.append(
            {
                "severity": "medium",
                "title": f"Public GitHub profile: {p.get('login')}",
                "detail": " · ".join(str(x) for x in bits if x)
                + (f" · {p.get('public_repos')} public repos" if p.get("public_repos") is not None else ""),
                "url": p.get("html_url"),
                "action": "Review public repos and README files for email, phone, or keys.",
            }
        )
        if p.get("blog"):
            findings.append(
                {
                    "severity": "info",
                    "title": f"Website linked from GitHub: {p.get('blog')}",
                    "url": p.get("blog") if str(p.get("blog")).startswith("http") else f"https://{p.get('blog')}",
                }
            )

    if identity.get("type") == "email" and identity.get("username"):
        local = identity["username"]
        gh_logins = {((a.get("profile") or {}).get("login") or "").lower() for a in accounts}
        if local.lower() not in gh_logins and accounts:
            findings.append(
                {
                    "severity": "info",
                    "title": "Email handle and GitHub login are different",
                    "detail": f"{local} is not a GitHub user. Public search tied this mailbox to: "
                    + ", ".join(sorted(gh_logins)),
                    "action": "Remove the raw email from public READMEs if you do not want mailbox harvesting.",
                }
            )
            actions.append("Remove or mask your email in public GitHub README / contact pages.")

    presence = results.get("presence") or {}
    for p in presence.get("profiles") or []:
        if p.get("status") != "found" or p.get("confidence") == "low":
            continue
        details = p.get("details") or {}
        useful = {k: v for k, v in details.items() if v and k not in ("proofs",)}
        findings.append(
            {
                "severity": "low",
                "title": f"Public profile: {p.get('name')}",
                "detail": ", ".join(f"{k}={v}" for k, v in list(useful.items())[:4]) or "Profile URL confirmed.",
                "url": p.get("url"),
            }
        )

    sites = results.get("account_presence") or {}
    sites_found = sites.get("found") or []
    if sites.get("status") == "ok" and sites_found:
        names = [f.get("domain") or f.get("name") for f in sites_found[:12]]
        more = len(sites_found) - len(names)
        detail = ", ".join(str(n) for n in names if n)
        if more > 0:
            detail += f" (+{more} more)"
        extras = []
        for f in sites_found:
            if f.get("email_recovery"):
                extras.append(f"{f.get('name')}: recovery {f['email_recovery']}")
            if f.get("phone_recovery"):
                extras.append(f"{f.get('name')}: phone {f['phone_recovery']}")
        if extras:
            detail += " · " + "; ".join(extras[:4])
        findings.append(
            {
                "severity": "medium",
                "title": f"Email registered on {len(sites_found)} site(s)",
                "detail": detail,
                "action": "Review accounts you no longer use; enable 2FA on important ones.",
            }
        )
        actions.append(
            f"Review {len(sites_found)} detected account(s); close unused services and turn on 2FA."
        )
        for f in sites_found[:8]:
            findings.append(
                {
                    "severity": "low",
                    "title": f"Account exists: {f.get('name')}",
                    "detail": " · ".join(
                        x
                        for x in (
                            f.get("domain"),
                            f"recovery {f['email_recovery']}" if f.get("email_recovery") else None,
                            f"phone {f['phone_recovery']}" if f.get("phone_recovery") else None,
                        )
                        if x
                    ),
                    "url": f"https://{f['domain']}" if f.get("domain") else None,
                }
            )
    elif sites.get("status") == "ok" and sites.get("rate_limited_count"):
        findings.append(
            {
                "severity": "info",
                "title": f"Site checks rate-limited on {sites.get('rate_limited_count')} site(s)",
                "detail": "Retry later or change IP/VPN. Other modules still ran.",
            }
        )
    elif sites.get("status") == "unavailable":
        findings.append(
            {
                "severity": "info",
                "title": "Site presence scan not available",
                "detail": sites.get("reason") or "Install dependencies with: pip install -r requirements.txt",
            }
        )

    gravatar = results.get("gravatar") or {}
    if gravatar.get("status") == "found":
        findings.append(
            {
                "severity": "medium",
                "title": "Gravatar profile is public for this email",
                "url": gravatar.get("profile_url"),
                "detail": ", ".join(
                    f"{a.get('shortname')}: {a.get('url') or a.get('username')}"
                    for a in gravatar.get("accounts") or []
                )
                or (gravatar.get("details") or {}).get("displayName"),
            }
        )

    phone = results.get("phone") or {}
    if phone.get("status") == "ok":
        findings.append(
            {
                "severity": "info",
                "title": f"Phone parses as {phone.get('international')}",
                "detail": " · ".join(
                    x
                    for x in (
                        phone.get("country"),
                        phone.get("carrier"),
                        phone.get("number_type"),
                    )
                    if x
                ),
            }
        )
    mentions = results.get("phone_mentions") or {}
    for hit in mentions.get("hits") or []:
        findings.append(
            {
                "severity": "medium" if hit.get("confirmed") else "low",
                "title": f"Number found on {hit.get('source')}: {hit.get('title')}",
                "detail": "Page confirmed to contain this number."
                if hit.get("confirmed")
                else "Search hit — open to confirm.",
                "url": hit.get("url"),
                "action": "Remove the number from this public page if you do not want it indexed.",
            }
        )
        if hit.get("confirmed"):
            actions.append(f"Remove public phone listing: {hit.get('url')}")

    for domain in results.get("domains") or []:
        host = domain.get("domain")
        for issue in domain.get("issues") or []:
            findings.append(
                {
                    "severity": "medium",
                    "title": f"Domain issue on {host}: {issue}",
                    "detail": " · ".join(
                        x
                        for x in (
                            f"SSL days left: {(domain.get('ssl') or {}).get('days_left')}",
                            f"DMARC: {(domain.get('dmarc') or {}).get('policy') or 'missing'}",
                            f"Title: {(domain.get('web') or {}).get('title')}",
                        )
                        if x
                    ),
                    "url": f"https://{host}",
                    "action": "Fix SPF/DMARC or renew the certificate on this domain.",
                }
            )
            actions.append(f"Review domain hygiene for {host}: {issue}")
        ct = domain.get("ct_names") or []
        if len(ct) > 1:
            findings.append(
                {
                    "severity": "info",
                    "title": f"{host}: {len(ct)} names in public certificate logs",
                    "detail": ", ".join(ct[:8]),
                }
            )

    for flag in (results.get("github_hygiene") or {}).get("flags") or []:
        findings.append(
            {
                "severity": flag.get("severity") or "medium",
                "title": f"GitHub public file: {flag.get('file')} in {flag.get('repo')}",
                "detail": flag.get("detail"),
                "url": flag.get("url"),
                "action": "Remove the file from git history or make the repo private if it should not be public.",
            }
        )
        if flag.get("kind") == "sensitive_file":
            actions.append(f"Remove public secret-like file {flag.get('file')} from {flag.get('repo')}.")

    delta = results.get("history") or {}
    if delta.get("has_previous"):
        if delta.get("new_breaches"):
            findings.append(
                {
                    "severity": "high",
                    "title": "New breach names since last scan",
                    "detail": ", ".join(delta["new_breaches"]),
                }
            )
        if delta.get("new_repos"):
            findings.append(
                {
                    "severity": "info",
                    "title": "New public repos since last scan",
                    "detail": ", ".join(delta["new_repos"]),
                }
            )

    seen_a = set()
    uniq_actions = []
    for a in actions:
        if a and a not in seen_a:
            seen_a.add(a)
            uniq_actions.append(a)

    if not findings:
        findings.append(
            {
                "severity": "info",
                "title": "No high-value public hits",
                "detail": "No breaches, GitHub profile, or confirmed social account from public APIs.",
            }
        )

    return {
        "findings": findings,
        "actions": uniq_actions,
        "people": people,
        "github_accounts": accounts,
        "breach_count": breaches.get("count") or 0,
        "sites_found_count": len((results.get("account_presence") or {}).get("found") or []),
        "sites_checked": (results.get("account_presence") or {}).get("checked") or 0,
        "graph": report.get("graph") or {},
        "history": delta,
    }
