from colorama import Fore, Style


def short_summary(data):
    lines = []
    view = data.get("view") or {}
    risk = data.get("risk_analysis") or {}

    lines.append(f"{Style.BRIGHT}{Fore.CYAN}Target:{Style.RESET_ALL} {data.get('target')} ({data.get('type')})")
    lines.append(
        f"{Fore.MAGENTA}Risk:{Style.RESET_ALL} {risk.get('level', '-')} ({risk.get('score', 0)})"
    )
    for reason in risk.get("reasons") or []:
        lines.append(f"  - {reason}")

    findings = view.get("findings") or []
    if findings:
        lines.append("")
        lines.append(f"{Style.BRIGHT}Useful findings{Style.RESET_ALL}")
        for item in findings:
            sev = (item.get("severity") or "info").upper()
            color = {
                "HIGH": Fore.RED,
                "MEDIUM": Fore.YELLOW,
                "LOW": Fore.CYAN,
                "INFO": Fore.WHITE,
            }.get(sev, Fore.WHITE)
            lines.append(f"  {color}[{sev}]{Style.RESET_ALL} {item.get('title')}")
            if item.get("detail"):
                lines.append(f"      {item['detail']}")
            if item.get("url"):
                lines.append(f"      {item['url']}")

    actions = view.get("actions") or []
    if actions:
        lines.append("")
        lines.append(f"{Style.BRIGHT}{Fore.YELLOW}What to do{Style.RESET_ALL}")
        for i, action in enumerate(actions, 1):
            lines.append(f"  {i}. {action}")

    accounts = view.get("github_accounts") or []
    for acc in accounts:
        p = acc.get("profile") or {}
        repos = acc.get("repos") or []
        lines.append("")
        lines.append(f"{Style.BRIGHT}GitHub @{p.get('login')}{Style.RESET_ALL} {p.get('html_url') or ''}")
        if p.get("name"):
            lines.append(f"  name:     {p['name']}")
        if p.get("bio"):
            lines.append(f"  bio:      {p['bio']}")
        if p.get("company"):
            lines.append(f"  company:  {p['company']}")
        if p.get("location"):
            lines.append(f"  location: {p['location']}")
        if p.get("blog"):
            lines.append(f"  website:  {p['blog']}")
        lines.append(
            f"  stats:    {p.get('public_repos', 0)} repos, {p.get('followers', 0)} followers, since {(p.get('created_at') or '')[:10]}"
        )
        if repos:
            lines.append("  recent repos:")
            for repo in repos[:8]:
                lang = repo.get("language") or "-"
                desc = (repo.get("description") or "")[:70]
                extra = f" - {desc}" if desc else ""
                lines.append(f"    - {repo.get('name')} ({lang}){extra}")
                lines.append(f"      {repo.get('url')}")

    breaches = ((data.get("results") or {}).get("breaches") or {}).get("breaches") or []
    if breaches:
        lines.append("")
        lines.append(f"{Style.BRIGHT}{Fore.RED}Breach names and data types{Style.RESET_ALL}")
        for b in breaches:
            year = f" ({b['year']})" if b.get("year") else ""
            data_types = f" — {b['data']}" if b.get("data") else ""
            lines.append(f"  - {b.get('name')}{year}{data_types}")

    for domain in (data.get("results") or {}).get("domains") or []:
        lines.append("")
        lines.append(f"{Style.BRIGHT}Domain {domain.get('domain')}{Style.RESET_ALL}")
        ssl = domain.get("ssl") or {}
        dmarc = domain.get("dmarc") or {}
        web = domain.get("web") or {}
        if web.get("title"):
            lines.append(f"  title:  {web['title']}")
        if ssl.get("days_left") is not None:
            lines.append(f"  ssl:    {ssl['days_left']} days left · {ssl.get('issuer') or ''}")
        lines.append(f"  dmarc:  {dmarc.get('policy') or 'missing'}")
        lines.append(f"  spf:    {'yes' if (domain.get('spf') or {}).get('present') else 'no'}")
        if domain.get("issues"):
            for issue in domain["issues"]:
                lines.append(f"  issue:  {issue}")
        if domain.get("ct_names"):
            lines.append(f"  certs:  {', '.join(domain['ct_names'][:6])}")

    mentions = ((data.get("results") or {}).get("phone_mentions") or {}).get("hits") or []
    if mentions:
        lines.append("")
        lines.append(f"{Style.BRIGHT}Public pages using this number{Style.RESET_ALL}")
        for hit in mentions:
            mark = "confirmed" if hit.get("confirmed") else "search hit"
            lines.append(f"  - [{mark}] {hit.get('title')}")
            lines.append(f"    {hit.get('url')}")

    flags = ((data.get("results") or {}).get("github_hygiene") or {}).get("flags") or []
    if flags:
        lines.append("")
        lines.append(f"{Style.BRIGHT}{Fore.YELLOW}GitHub public hygiene{Style.RESET_ALL}")
        for flag in flags:
            lines.append(f"  - {flag.get('detail')} ({flag.get('repo')})")
            if flag.get("url"):
                lines.append(f"    {flag['url']}")

    graph = (data.get("view") or {}).get("graph") or data.get("graph") or {}
    if graph.get("edges"):
        lines.append("")
        lines.append(f"{Style.BRIGHT}How identities link{Style.RESET_ALL}")
        labels = {n["id"]: n["label"] for n in graph.get("nodes") or []}
        for e in graph.get("edges") or []:
            lines.append(f"  {labels.get(e['from'], e['from'])} -> {labels.get(e['to'], e['to'])} ({e.get('why')})")

    hist = ((data.get("results") or {}).get("history") or {})
    if hist.get("has_previous"):
        lines.append("")
        lines.append("Compared with previous scan")
        lines.append(f"  risk change: {hist.get('risk_delta')}")
        if hist.get("new_breaches"):
            lines.append(f"  new breaches: {', '.join(hist['new_breaches'])}")
        if hist.get("new_repos"):
            lines.append(f"  new repos: {', '.join(hist['new_repos'])}")

    lines.append("")
    lines.append("Public sources only. Use on your own accounts or with permission.")
    return "\n".join(lines)
