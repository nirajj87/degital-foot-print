from __future__ import annotations

import html
from datetime import datetime


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _sev_color(sev: str) -> str:
    return {
        "high": "#b42318",
        "medium": "#b54708",
        "low": "#175cd3",
        "info": "#475467",
    }.get(sev, "#475467")


def write_html_report(report: dict, path: str) -> str:
    view = report.get("view") or {}
    findings = view.get("findings") or []
    actions = view.get("actions") or []
    accounts = view.get("github_accounts") or []
    risk = report.get("risk_analysis") or {}
    identity = report.get("identity") or {}
    target = _esc(report.get("target"))
    now = _esc(report.get("timestamp") or datetime.utcnow().isoformat())

    finding_html = []
    for f in findings:
        sev = f.get("severity") or "info"
        url = f.get("url")
        link = f' <a href="{_esc(url)}">{_esc(url)}</a>' if url else ""
        action = f'<div class="muted">Next: {_esc(f.get("action"))}</div>' if f.get("action") else ""
        finding_html.append(
            f"""<div class="card">
  <div class="sev" style="color:{_sev_color(sev)}">{_esc(sev.upper())}</div>
  <h3>{_esc(f.get("title"))}</h3>
  <p>{_esc(f.get("detail") or "")}{link}</p>
  {action}
</div>"""
        )

    action_html = "".join(f"<li>{_esc(a)}</li>" for a in actions) or "<li>No urgent actions.</li>"

    people_html = []
    for acc in accounts:
        p = acc.get("profile") or {}
        repos = acc.get("repos") or []
        repo_rows = "".join(
            f"<tr><td><a href='{_esc(r.get('url'))}'>{_esc(r.get('name'))}</a></td>"
            f"<td>{_esc(r.get('language') or '-')}</td>"
            f"<td>{_esc(r.get('description') or '')}</td></tr>"
            for r in repos
        )
        people_html.append(
            f"""<div class="card">
  <h3><a href="{_esc(p.get('html_url'))}">{_esc(p.get('login'))}</a> — {_esc(p.get('name') or '')}</h3>
  <p>{_esc(p.get('bio') or '')}</p>
  <p class="muted">{_esc(p.get('company') or '')} · {_esc(p.get('location') or '')} · {_esc(p.get('blog') or '')}</p>
  <p class="muted">Repos { _esc(p.get('public_repos')) } · Followers { _esc(p.get('followers')) } · Since { _esc((p.get('created_at') or '')[:10]) }</p>
  <table><thead><tr><th>Repo</th><th>Lang</th><th>About</th></tr></thead><tbody>{repo_rows}</tbody></table>
</div>"""
        )

    domain_html = []
    for domain in (report.get("results") or {}).get("domains") or []:
        issues = "".join(f"<li>{_esc(i)}</li>" for i in (domain.get("issues") or [])) or "<li>No email-auth / SSL issues</li>"
        ct = ", ".join(domain.get("ct_names") or []) or "-"
        ssl = domain.get("ssl") or {}
        web = domain.get("web") or {}
        domain_html.append(
            f"""<div class="card">
  <h3>{_esc(domain.get("domain"))}</h3>
  <p>{_esc(web.get("title") or "")} · SSL { _esc(ssl.get("days_left")) } days left</p>
  <p class="muted">DMARC { _esc((domain.get("dmarc") or {}).get("policy") or "missing") } · SPF { "yes" if (domain.get("spf") or {}).get("present") else "no" }</p>
  <p class="muted">CT names: {_esc(ct)}</p>
  <ul>{issues}</ul>
</div>"""
        )
    domain_html = "".join(domain_html)

    flags = ((report.get("results") or {}).get("github_hygiene") or {}).get("flags") or []
    hygiene_html = "".join(
        f"<tr><td>{_esc(f.get('kind'))}</td><td>{_esc(f.get('repo'))}</td>"
        f"<td>{_esc(f.get('file'))}</td><td>{_esc(f.get('detail'))} "
        f"<a href='{_esc(f.get('url'))}'>open</a></td></tr>"
        for f in flags
    )
    if hygiene_html:
        hygiene_html = (
            "<table><thead><tr><th>Kind</th><th>Repo</th><th>File</th><th>Detail</th></tr></thead>"
            f"<tbody>{hygiene_html}</tbody></table>"
        )

    graph = view.get("graph") or report.get("graph") or {}
    labels = {n["id"]: n["label"] for n in graph.get("nodes") or []}
    graph_html = "".join(
        f"<li>{_esc(labels.get(e.get('from'), e.get('from')))} → "
        f"{_esc(labels.get(e.get('to'), e.get('to')))} "
        f"<span class='muted'>({_esc(e.get('why'))})</span></li>"
        for e in graph.get("edges") or []
    )
    if graph_html:
        graph_html = f"<ul>{graph_html}</ul>"

    breaches = ((report.get("results") or {}).get("breaches") or {}).get("breaches") or []
    breach_rows = "".join(
        f"<tr><td>{_esc(b.get('name'))}</td><td>{_esc(b.get('year'))}</td>"
        f"<td>{_esc(b.get('data'))}</td><td>{_esc(b.get('action'))}</td></tr>"
        for b in breaches
    ) or "<tr><td colspan='4'>No public breach names returned.</td></tr>"

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>Digital footprint — {target}</title>
  <style>
    body {{ font-family: Segoe UI, sans-serif; background:#f8fafc; color:#101828; margin:0; }}
    main {{ max-width: 920px; margin: 32px auto; padding: 0 20px 48px; }}
    h1 {{ font-size: 24px; margin: 0 0 6px; }}
    h2 {{ font-size: 18px; margin: 28px 0 12px; }}
    h3 {{ font-size: 16px; margin: 0 0 8px; }}
    .muted {{ color:#667085; font-size: 14px; }}
    .hero {{ background:#fff; border:1px solid #e4e7ec; border-radius:10px; padding:20px; }}
    .stats {{ display:flex; gap:16px; flex-wrap:wrap; margin-top:12px; }}
    .stat {{ background:#f2f4f7; border-radius:8px; padding:10px 14px; min-width:120px; }}
    .stat b {{ display:block; font-size:20px; }}
    .card {{ background:#fff; border:1px solid #e4e7ec; border-radius:10px; padding:16px; margin:10px 0; }}
    .sev {{ font-size:12px; font-weight:600; letter-spacing:.04em; }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }}
    th, td {{ text-align:left; padding:8px 6px; border-bottom:1px solid #e4e7ec; vertical-align:top; }}
    a {{ color:#175cd3; }}
  </style>
</head>
<body>
<main>
  <h1>Digital footprint report</h1>
  <p class="muted">{target} · {_esc(identity.get('type'))} · {now}</p>
  <div class="hero">
    <div class="stats">
      <div class="stat"><b>{_esc(risk.get('level') or '-')}</b>Risk</div>
      <div class="stat"><b>{_esc(risk.get('score') if risk.get('score') is not None else 0)}</b>Score</div>
      <div class="stat"><b>{_esc(view.get('breach_count') or 0)}</b>Breaches</div>
      <div class="stat"><b>{_esc(len(accounts))}</b>GitHub accounts</div>
    </div>
    <p class="muted" style="margin-top:12px">Public sources only. No Instagram/Facebook private data.</p>
  </div>

  <h2>What to do</h2>
  <ol>{action_html}</ol>

  <h2>Useful findings</h2>
  {''.join(finding_html)}

  <h2>Breach details</h2>
  <table>
    <thead><tr><th>Name</th><th>When</th><th>Data types</th><th>What you should do</th></tr></thead>
    <tbody>{breach_rows}</tbody>
  </table>

  <h2>GitHub</h2>
  {''.join(people_html) or '<p class="muted">No public GitHub profile correlated.</p>'}

  <h2>Domains</h2>
  {domain_html or '<p class="muted">No related domain inspected.</p>'}

  <h2>GitHub hygiene</h2>
  {hygiene_html or '<p class="muted">No public secret-like files or README emails flagged.</p>'}

  <h2>Identity links</h2>
  {graph_html or '<p class="muted">No graph.</p>'}

  <p class="muted">Generated by Digital Footprint Analyzer for authorized / self-assessment use.</p>
</main>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    return path
