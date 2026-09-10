from __future__ import annotations

import html
from datetime import datetime
from collections import defaultdict


def _esc(v) -> str:
    return html.escape("" if v is None else str(v))


def _risk_tone(level: str) -> tuple[str, str, str]:
    """bg, accent, label color"""
    lv = (level or "").lower()
    if lv == "high":
        return "#fef3f2", "#b42318", "#912018"
    if lv == "medium":
        return "#fffaeb", "#b54708", "#93370d"
    return "#ecfdf3", "#027a48", "#054f31"


def write_html_report(report: dict, path: str) -> str:
    view = report.get("view") or {}
    findings = view.get("findings") or []
    actions = view.get("actions") or []
    accounts = view.get("github_accounts") or []
    risk = report.get("risk_analysis") or {}
    identity = report.get("identity") or {}
    results = report.get("results") or {}
    target = _esc(report.get("target"))
    now = _esc(report.get("timestamp") or datetime.utcnow().isoformat())
    level = risk.get("level") or "Low"
    score = int(risk.get("score") or 0)
    tone_bg, tone_accent, tone_text = _risk_tone(level)
    score_pct = max(0, min(100, score))

    # --- Actions ---
    action_html = "".join(
        f'<li><span class="step">{i}</span><span>{_esc(a)}</span></li>'
        for i, a in enumerate(actions, 1)
    ) or "<li><span class='step'>✓</span><span>No urgent actions right now.</span></li>"

    # --- Findings grouped by severity ---
    by_sev: dict[str, list] = defaultdict(list)
    for f in findings:
        by_sev[(f.get("severity") or "info").lower()].append(f)

    sev_order = ["high", "medium", "low", "info"]
    finding_blocks = []
    for sev in sev_order:
        items = by_sev.get(sev) or []
        if not items:
            continue
        cards = []
        for f in items:
            url = f.get("url")
            link = (
                f'<a class="chip-link" href="{_esc(url)}" target="_blank" rel="noopener">{_esc(url)}</a>'
                if url
                else ""
            )
            nxt = (
                f'<p class="next">Next: {_esc(f.get("action"))}</p>'
                if f.get("action")
                else ""
            )
            cards.append(
                f"""<article class="finding sev-{_esc(sev)}">
  <header><span class="badge">{_esc(sev.upper())}</span><h3>{_esc(f.get("title"))}</h3></header>
  <p>{_esc(f.get("detail") or "")}</p>
  {link}{nxt}
</article>"""
            )
        finding_blocks.append(
            f'<div class="sev-group"><h3 class="sev-label">{_esc(sev.upper())} · {len(items)}</h3>'
            f'<div class="finding-grid">{"".join(cards)}</div></div>'
        )
    findings_html = "".join(finding_blocks) or '<p class="empty">No findings.</p>'

    # --- Breaches ---
    breaches = (results.get("breaches") or {}).get("breaches") or []
    breach_cards = []
    for b in breaches:
        breach_cards.append(
            f"""<div class="breach-card">
  <div class="breach-year">{_esc(b.get("year") or "—")}</div>
  <div>
    <strong>{_esc(b.get("name"))}</strong>
    <p class="muted">{_esc(b.get("data") or "Details limited")}</p>
    <p class="next">{_esc(b.get("action") or "")}</p>
  </div>
</div>"""
        )
    breaches_html = "".join(breach_cards) or '<p class="empty">No public breach names returned.</p>'

    # --- Sites ---
    sites = results.get("account_presence") or {}
    site_chips = "".join(
        f'<a class="site-chip" href="https://{_esc(r.get("domain") or "")}" target="_blank" rel="noopener">'
        f'<b>{_esc(r.get("name"))}</b><span>{_esc(r.get("domain"))}</span></a>'
        for r in (sites.get("found") or [])
        if r.get("domain") or r.get("name")
    )
    if sites.get("status") == "ok":
        sites_section = f"""
<section id="sites" class="panel">
  <div class="panel-head">
    <h2>Registered accounts</h2>
    <p class="muted">Email registration probes · soft signal (rate-limits common)</p>
  </div>
  <div class="mini-stats">
    <div><b>{_esc(sites.get("found_count") or 0)}</b><span>Found</span></div>
    <div><b>{_esc(sites.get("checked") or 0)}</b><span>Checked</span></div>
    <div><b>{_esc(sites.get("rate_limited_count") or 0)}</b><span>Rate-limited</span></div>
  </div>
  <div class="chip-row">{site_chips or '<p class="empty">No accounts confirmed.</p>'}</div>
</section>"""
    elif sites.get("status") == "unavailable":
        sites_section = f"""
<section id="sites" class="panel">
  <div class="panel-head"><h2>Registered accounts</h2></div>
  <p class="empty">Not available: {_esc(sites.get("reason"))}</p>
</section>"""
    else:
        sites_section = ""

    # --- GitHub ---
    people_html = []
    for acc in accounts:
        p = acc.get("profile") or {}
        repos = acc.get("repos") or []
        repo_rows = "".join(
            f"<tr><td><a href='{_esc(r.get('url'))}' target='_blank' rel='noopener'>{_esc(r.get('name'))}</a></td>"
            f"<td>{_esc(r.get('language') or '—')}</td>"
            f"<td>{_esc((r.get('description') or '')[:120])}</td></tr>"
            for r in repos[:12]
        )
        avatar = p.get("avatar_url") or ""
        av = f'<img class="avatar" src="{_esc(avatar)}" alt="" />' if avatar else ""
        people_html.append(
            f"""<div class="gh-card">
  <div class="gh-top">{av}
    <div>
      <h3><a href="{_esc(p.get('html_url'))}" target="_blank" rel="noopener">@{_esc(p.get('login'))}</a>
        <span class="muted">{_esc(p.get('name') or '')}</span></h3>
      <p>{_esc(p.get('bio') or '')}</p>
      <p class="muted">{_esc(p.get('company') or '—')} · {_esc(p.get('location') or '—')} ·
        <a href="{_esc(p.get('blog') or '#')}">{_esc(p.get('blog') or '')}</a></p>
      <div class="mini-stats tight">
        <div><b>{_esc(p.get('public_repos') or 0)}</b><span>Repos</span></div>
        <div><b>{_esc(p.get('followers') or 0)}</b><span>Followers</span></div>
        <div><b>{_esc((p.get('created_at') or '')[:10] or '—')}</b><span>Since</span></div>
      </div>
    </div>
  </div>
  <table><thead><tr><th>Repo</th><th>Lang</th><th>About</th></tr></thead><tbody>{repo_rows or '<tr><td colspan=3>No repos listed.</td></tr>'}</tbody></table>
</div>"""
        )
    github_html = "".join(people_html) or '<p class="empty">No public GitHub profile correlated.</p>'

    # --- Domains ---
    domain_blocks = []
    for domain in results.get("domains") or []:
        issues = "".join(f"<li>{_esc(i)}</li>" for i in (domain.get("issues") or [])) or "<li>No email-auth / SSL issues</li>"
        ssl = domain.get("ssl") or {}
        web = domain.get("web") or {}
        dmarc = (domain.get("dmarc") or {}).get("policy") or "missing"
        spf = "yes" if (domain.get("spf") or {}).get("present") else "no"
        domain_blocks.append(
            f"""<div class="domain-card">
  <h3>{_esc(domain.get("domain"))}</h3>
  <p>{_esc(web.get("title") or "")}</p>
  <div class="tag-row">
    <span class="tag">SSL {_esc(ssl.get("days_left"))}d</span>
    <span class="tag {'bad' if dmarc == 'missing' else ''}">DMARC {_esc(dmarc)}</span>
    <span class="tag">SPF {_esc(spf)}</span>
  </div>
  <ul>{issues}</ul>
</div>"""
        )
    domains_html = "".join(domain_blocks) or '<p class="empty">No related domain inspected.</p>'

    # --- Hygiene ---
    flags = (results.get("github_hygiene") or {}).get("flags") or []
    hygiene_rows = "".join(
        f"<tr><td><span class='tag'>{_esc(f.get('kind'))}</span></td><td>{_esc(f.get('repo'))}</td>"
        f"<td>{_esc(f.get('file'))}</td><td>{_esc(f.get('detail'))} "
        f"<a href='{_esc(f.get('url'))}' target='_blank' rel='noopener'>open</a></td></tr>"
        for f in flags
    )
    hygiene_html = (
        f"<table><thead><tr><th>Kind</th><th>Repo</th><th>File</th><th>Detail</th></tr></thead>"
        f"<tbody>{hygiene_rows}</tbody></table>"
        if hygiene_rows
        else '<p class="empty">No public secret-like files or README emails flagged.</p>'
    )

    # --- Graph ---
    graph = view.get("graph") or report.get("graph") or {}
    labels = {n["id"]: n["label"] for n in graph.get("nodes") or []}
    graph_items = "".join(
        f"""<div class="edge">
  <span class="from">{_esc(labels.get(e.get('from'), e.get('from')))}</span>
  <span class="arrow">→</span>
  <span class="to">{_esc(labels.get(e.get('to'), e.get('to')))}</span>
  <span class="why">{_esc(e.get('why'))}</span>
</div>"""
        for e in graph.get("edges") or []
    )
    graph_html = graph_items or '<p class="empty">No identity links.</p>'

    # --- History ---
    hist = results.get("history") or {}
    if hist.get("has_previous"):
        hist_html = f"""
<section id="history" class="panel">
  <div class="panel-head"><h2>Since last scan</h2></div>
  <div class="mini-stats">
    <div><b>{_esc(hist.get('risk_delta'))}</b><span>Risk change</span></div>
  </div>
  <p class="muted">New repos: {_esc(', '.join(hist.get('new_repos') or []) or '—')}</p>
  <p class="muted">New breaches: {_esc(', '.join(hist.get('new_breaches') or []) or '—')}</p>
</section>"""
    else:
        hist_html = ""

    reasons = risk.get("reasons") or []
    reasons_html = "".join(f"<li>{_esc(r)}</li>" for r in reasons) or "<li>No risk drivers listed.</li>"

    high_n = len(by_sev.get("high") or [])
    med_n = len(by_sev.get("medium") or [])
    breach_n = view.get("breach_count") or len(breaches)
    sites_n = view.get("sites_found_count") or sites.get("found_count") or 0

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Footprint report — {target}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com"/>
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
  <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600;9..144,700&family=Source+Sans+3:wght@400;500;600;700&display=swap" rel="stylesheet"/>
  <style>
    :root {{
      --ink: #0f172a;
      --muted: #64748b;
      --line: #e2e8f0;
      --paper: #f1f5f9;
      --card: #ffffff;
      --accent: #0f766e;
      --accent-soft: #ccfbf1;
      --shadow: 0 10px 30px rgba(15, 23, 42, .06);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--ink);
      background:
        radial-gradient(1200px 500px at 10% -10%, #ccfbf1 0%, transparent 55%),
        radial-gradient(900px 400px at 100% 0%, #e0f2fe 0%, transparent 50%),
        var(--paper);
      font-family: "Source Sans 3", Segoe UI, sans-serif;
      line-height: 1.5;
    }}
    .wrap {{ max-width: 1080px; margin: 0 auto; padding: 28px 20px 64px; }}
    .brand {{
      display: flex; justify-content: space-between; gap: 16px; align-items: end;
      margin-bottom: 20px; flex-wrap: wrap;
    }}
    .brand h1 {{
      font-family: Fraunces, Georgia, serif;
      font-size: clamp(1.6rem, 3vw, 2.2rem);
      margin: 0 0 4px;
      letter-spacing: -.02em;
    }}
    .muted {{ color: var(--muted); font-size: .95rem; }}
    .nav {{
      display: flex; flex-wrap: wrap; gap: 8px; margin: 0 0 22px;
      position: sticky; top: 0; z-index: 5;
      background: rgba(241,245,249,.92); backdrop-filter: blur(8px);
      padding: 10px 0; border-bottom: 1px solid var(--line);
    }}
    .nav a {{
      text-decoration: none; color: var(--ink); font-size: .86rem; font-weight: 600;
      padding: 6px 10px; border-radius: 999px; background: #fff; border: 1px solid var(--line);
    }}
    .nav a:hover {{ border-color: var(--accent); color: var(--accent); }}
    .hero {{
      display: grid; grid-template-columns: 1.2fr .8fr; gap: 18px; margin-bottom: 22px;
    }}
    @media (max-width: 800px) {{ .hero {{ grid-template-columns: 1fr; }} }}
    .panel, .hero-card {{
      background: var(--card); border: 1px solid var(--line); border-radius: 16px;
      box-shadow: var(--shadow); padding: 20px 22px; margin-bottom: 18px;
    }}
    .hero-card.risk {{ background: {tone_bg}; border-color: {tone_accent}33; }}
    .risk-level {{
      font-family: Fraunces, Georgia, serif; font-size: 2.4rem; margin: 0;
      color: {tone_text};
    }}
    .meter {{
      height: 10px; background: #fff8; border-radius: 999px; overflow: hidden;
      border: 1px solid {tone_accent}44; margin: 14px 0 8px;
    }}
    .meter > i {{
      display: block; height: 100%; width: {score_pct}%;
      background: {tone_accent}; border-radius: inherit;
    }}
    .stat-grid {{
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 14px;
    }}
    @media (max-width: 700px) {{ .stat-grid {{ grid-template-columns: repeat(2, 1fr); }} }}
    .stat {{
      background: #f8fafc; border: 1px solid var(--line); border-radius: 12px; padding: 12px 14px;
    }}
    .stat b {{ display: block; font-size: 1.35rem; font-weight: 700; }}
    .stat span {{ color: var(--muted); font-size: .82rem; }}
    .panel-head {{ margin-bottom: 14px; }}
    .panel-head h2 {{
      font-family: Fraunces, Georgia, serif; font-size: 1.35rem; margin: 0 0 4px;
    }}
    .mini-stats {{ display: flex; gap: 18px; flex-wrap: wrap; margin: 8px 0 14px; }}
    .mini-stats.tight {{ gap: 14px; }}
    .mini-stats b {{ display: block; font-size: 1.15rem; }}
    .mini-stats span {{ color: var(--muted); font-size: .8rem; }}
    ol.actions {{ list-style: none; padding: 0; margin: 0; display: grid; gap: 10px; }}
    ol.actions li {{
      display: flex; gap: 12px; align-items: flex-start;
      padding: 12px 14px; border-radius: 12px; background: #f8fafc; border: 1px solid var(--line);
    }}
    .step {{
      flex: 0 0 28px; height: 28px; border-radius: 50%;
      background: var(--accent); color: #fff; font-weight: 700; font-size: .85rem;
      display: grid; place-items: center;
    }}
    .sev-group {{ margin-bottom: 18px; }}
    .sev-label {{ font-size: .8rem; letter-spacing: .08em; color: var(--muted); margin: 0 0 8px; }}
    .finding-grid {{ display: grid; gap: 10px; }}
    .finding {{
      border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px;
      border-left: 4px solid #94a3b8; background: #fff;
    }}
    .finding.sev-high {{ border-left-color: #b42318; background: #fffbfa; }}
    .finding.sev-medium {{ border-left-color: #b54708; background: #fffcf5; }}
    .finding.sev-low {{ border-left-color: #175cd3; }}
    .finding header {{ display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }}
    .finding h3 {{ margin: 0; font-size: 1.02rem; }}
    .finding p {{ margin: 8px 0 0; }}
    .badge {{
      font-size: .68rem; font-weight: 700; letter-spacing: .06em;
      padding: 3px 8px; border-radius: 999px; background: #e2e8f0; color: #334155;
    }}
    .sev-high .badge {{ background: #fee4e2; color: #b42318; }}
    .sev-medium .badge {{ background: #fef0c7; color: #b54708; }}
    .sev-low .badge {{ background: #d1e9ff; color: #175cd3; }}
    .next {{ color: var(--accent); font-size: .9rem; font-weight: 600; margin-top: 8px !important; }}
    .chip-link, a {{ color: #0f766e; }}
    .chip-row {{ display: flex; flex-wrap: wrap; gap: 8px; }}
    .site-chip {{
      display: inline-flex; flex-direction: column; gap: 2px;
      text-decoration: none; color: inherit;
      border: 1px solid var(--line); border-radius: 12px; padding: 10px 12px; background: #f8fafc;
      min-width: 120px;
    }}
    .site-chip:hover {{ border-color: var(--accent); background: var(--accent-soft); }}
    .site-chip span {{ color: var(--muted); font-size: .78rem; }}
    .breach-card {{
      display: grid; grid-template-columns: 72px 1fr; gap: 12px;
      padding: 12px 0; border-bottom: 1px solid var(--line);
    }}
    .breach-card:last-child {{ border-bottom: 0; }}
    .breach-year {{
      font-family: Fraunces, Georgia, serif; font-size: 1.2rem; color: #b42318;
      background: #fef3f2; border-radius: 10px; display: grid; place-items: center;
    }}
    .gh-card, .domain-card {{ margin-top: 8px; }}
    .gh-top {{ display: flex; gap: 14px; margin-bottom: 12px; }}
    .avatar {{ width: 64px; height: 64px; border-radius: 14px; object-fit: cover; border: 1px solid var(--line); }}
    table {{ width: 100%; border-collapse: collapse; font-size: .92rem; }}
    th, td {{ text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; font-size: .8rem; letter-spacing: .04em; text-transform: uppercase; }}
    .tag-row {{ display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }}
    .tag {{
      font-size: .75rem; font-weight: 600; padding: 4px 8px; border-radius: 999px;
      background: #f1f5f9; border: 1px solid var(--line);
    }}
    .tag.bad {{ background: #fef3f2; color: #b42318; border-color: #fecdca; }}
    .edge {{
      display: grid; grid-template-columns: 1fr auto 1fr; gap: 8px; align-items: center;
      padding: 10px 12px; border: 1px solid var(--line); border-radius: 12px; margin-bottom: 8px;
      background: #f8fafc;
    }}
    .edge .arrow {{ color: var(--accent); font-weight: 700; }}
    .edge .why {{ grid-column: 1 / -1; color: var(--muted); font-size: .82rem; }}
    .trust {{
      background: linear-gradient(135deg, #ecfeff, #f0fdf4);
      border: 1px solid #99f6e4;
    }}
    .trust ul {{ margin: 8px 0 0; padding-left: 18px; color: #334155; }}
    .empty {{ color: var(--muted); font-style: italic; }}
    footer.note {{
      margin-top: 28px; color: var(--muted); font-size: .85rem; text-align: center;
    }}
    @media print {{
      body {{ background: #fff; }}
      .nav {{ display: none; }}
      .panel, .hero-card {{ box-shadow: none; break-inside: avoid; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <header class="brand">
      <div>
        <h1>Digital Footprint Report</h1>
        <p class="muted">{target} · {_esc(identity.get('type') or report.get('type'))} · {now}</p>
      </div>
      <p class="muted">Self-assessment · public sources only</p>
    </header>

    <nav class="nav">
      <a href="#summary">Summary</a>
      <a href="#actions">Actions</a>
      <a href="#findings">Findings</a>
      <a href="#breaches">Breaches</a>
      <a href="#sites">Accounts</a>
      <a href="#github">GitHub</a>
      <a href="#domains">Domains</a>
      <a href="#hygiene">Hygiene</a>
      <a href="#graph">Links</a>
    </nav>

    <section id="summary" class="hero">
      <div class="hero-card risk">
        <p class="muted" style="margin:0 0 4px; font-weight:600; letter-spacing:.06em; text-transform:uppercase; font-size:.75rem;">Overall risk</p>
        <p class="risk-level">{_esc(level)}</p>
        <div class="meter" aria-label="Risk score {score}"><i></i></div>
        <p style="margin:0; font-weight:700; color:{tone_text};">Score {score} / 100</p>
        <ul style="margin:12px 0 0; padding-left:18px; color:{tone_text};">{reasons_html}</ul>
      </div>
      <div class="hero-card">
        <p class="muted" style="margin:0 0 8px; font-weight:600; letter-spacing:.06em; text-transform:uppercase; font-size:.75rem;">At a glance</p>
        <div class="stat-grid">
          <div class="stat"><b>{_esc(breach_n)}</b><span>Breaches</span></div>
          <div class="stat"><b>{_esc(high_n)}</b><span>High findings</span></div>
          <div class="stat"><b>{_esc(med_n)}</b><span>Medium</span></div>
          <div class="stat"><b>{_esc(sites_n)}</b><span>Site hits</span></div>
        </div>
        <p class="muted" style="margin-top:14px;">GitHub accounts correlated: <b>{_esc(len(accounts))}</b></p>
      </div>
    </section>

    <section class="panel trust">
      <div class="panel-head">
        <h2>How to read this report</h2>
        <p class="muted">Not every signal is equal — treat sources by trust level.</p>
      </div>
      <ul>
        <li><b>High trust:</b> breach lists, GitHub API, DNS/SSL (DMARC/SPF).</li>
        <li><b>Medium:</b> README email mentions, domain discovery from profile.</li>
        <li><b>Soft / incomplete:</b> email “registered on site” probes (rate-limits are common; not a full social scrape).</li>
        <li>This tool does <b>not</b> log into Facebook, Instagram, LinkedIn, or YouTube private data.</li>
      </ul>
    </section>

    <section id="actions" class="panel">
      <div class="panel-head">
        <h2>What to do first</h2>
        <p class="muted">Prioritized actions from this scan</p>
      </div>
      <ol class="actions">{action_html}</ol>
    </section>

    <section id="findings" class="panel">
      <div class="panel-head">
        <h2>Findings</h2>
        <p class="muted">Grouped by severity</p>
      </div>
      {findings_html}
    </section>

    <section id="breaches" class="panel">
      <div class="panel-head">
        <h2>Breach details</h2>
        <p class="muted">Public leak lists mentioning this email</p>
      </div>
      {breaches_html}
    </section>

    {sites_section}

    <section id="github" class="panel">
      <div class="panel-head">
        <h2>GitHub</h2>
        <p class="muted">Public profiles correlated to this target</p>
      </div>
      {github_html}
    </section>

    <section id="domains" class="panel">
      <div class="panel-head">
        <h2>Domains</h2>
        <p class="muted">Email auth &amp; certificate hygiene</p>
      </div>
      {domains_html}
    </section>

    <section id="hygiene" class="panel">
      <div class="panel-head">
        <h2>GitHub hygiene</h2>
        <p class="muted">Public files that look sensitive or publish emails</p>
      </div>
      {hygiene_html}
    </section>

    <section id="graph" class="panel">
      <div class="panel-head">
        <h2>Identity links</h2>
        <p class="muted">How pieces of this footprint connect</p>
      </div>
      {graph_html}
    </section>

    {hist_html}

    <p class="note footer">Generated by Digital Footprint Analyzer for authorized / self-assessment use. Print this page to PDF from your browser if needed.</p>
  </div>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)
    return path
