def risk_score(results, view=None):
    score = 0
    reasons = []
    view = view or {}

    n = (results.get("breaches") or {}).get("count") or 0
    if n:
        score += min(45, 15 + n * 5)
        reasons.append(f"{n} public breach record(s) for this email")

    accounts = view.get("github_accounts") or (results.get("github_accounts") or {}).get("accounts") or []
    if accounts:
        score += 10
        logins = [((a.get("profile") or {}).get("login")) for a in accounts if (a.get("profile") or {}).get("login")]
        reasons.append("Public GitHub account correlated: " + ", ".join(logins))

    if (results.get("gravatar") or {}).get("status") == "found":
        score += 5
        reasons.append("Public Gravatar profile")

    dark = results.get("darkweb") or {}
    if isinstance(dark, dict) and dark.get("status") == "ok" and dark.get("count"):
        score += 20
        reasons.append(f"Dark-web mentions: {dark.get('count')}")

    confirmed = 0
    for p in (results.get("presence") or {}).get("profiles") or []:
        if p.get("status") == "found" and p.get("confidence") != "low":
            confirmed += 1
    if confirmed:
        score += min(10, confirmed * 2)
        reasons.append(f"{confirmed} confirmed public profile(s)")

    sites = results.get("account_presence") or {}
    hf = sites.get("found_count") or len(sites.get("found") or [])
    if sites.get("status") == "ok" and hf:
        score += min(18, 4 + hf)
        reasons.append(f"Email registered on {hf} site(s) (of {sites.get('checked', '?')} checked)")
    elif sites.get("status") == "ok" and (sites.get("rate_limited_count") or 0) > 10:
        reasons.append(f"{sites.get('rate_limited_count')} site checks rate-limited (retry later)")

    hygiene = (results.get("github_hygiene") or {}).get("flags") or []
    secrets = [f for f in hygiene if f.get("kind") == "sensitive_file"]
    emails = [f for f in hygiene if f.get("kind") == "email_in_readme"]
    if secrets:
        score += min(20, 8 * len(secrets))
        reasons.append(f"{len(secrets)} public file(s) look like secrets")
    if emails:
        score += 6
        reasons.append("Email published in a public README")

    for domain in results.get("domains") or []:
        for issue in domain.get("issues") or []:
            if "expired" in issue.lower():
                score += 8
            elif "dmarc" in issue.lower() or "spf" in issue.lower():
                score += 4
            else:
                score += 2
            reasons.append(f"{domain.get('domain')}: {issue}")

    if (results.get("history") or {}).get("new_breaches"):
        score += 8
        reasons.append("New breach names since last scan")

    level = "Low"
    if score >= 55:
        level = "High"
    elif score >= 25:
        level = "Medium"
    return {"score": min(score, 100), "level": level, "reasons": reasons, "notes": reasons}
