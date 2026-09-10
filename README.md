# Digital Footprint Analyzer

Self-assessment tool for **your own** email, phone, username, or domain.

It maps where your identity shows up in **public** data: breach lists, email→account checks on **~139 sites**, username profiles on **67 sites**, GitHub hygiene, and domain email-auth (SPF/DMARC/SSL).

Use only on accounts you own, or with written permission.

---

## What it does

| Input | What happens |
|---|---|
| **Email** | ~121 built-in site modules + **18 project extras** (Microsoft, PayPal, Slack, Steam, Notion, Canva, …) → registered-account list; breaches; Gravatar/Keybase; GitHub correlation |
| **Username / `github:name`** | Public profile probe across **67** sites (`core/username_sites.py`) |
| **Phone** | Parse country/carrier; public GitHub / page mentions; search links |
| **Domain** | WHOIS, SPF/DMARC, SSL days left, site title |

Then you get a **risk score**, actionable findings, and **HTML + JSON + CSV** under `osint_output/`.

Optional dashboard: `python main.py --web` → http://127.0.0.1:8765

---

## Where are all the sites listed?

| Collection | File |
|---|---|
| **Full inventory (counts + names)** | [`docs/SITES_CATALOG.md`](./docs/SITES_CATALOG.md) |
| **Username URLs (edit to grow)** | [`core/username_sites.py`](./core/username_sites.py) |
| **Extra email checkers (edit to grow)** | [`core/extra_email_sites.py`](./core/extra_email_sites.py) |
| **Built-in email pack (~121)** | Installed package modules (listed in the catalog) |

Regenerate the catalog anytime:

```powershell
.\venv\Scripts\python.exe scripts\generate_sites_catalog.py
```

---

## Setup (Windows PowerShell)

```powershell
git clone https://github.com/nirajj87/degital-foot-print.git
cd degital-foot-print
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

**Important:** use `.\venv\Scripts\Activate.ps1` (with `.\`).  
Plain `venv\Scripts\activate` fails on PowerShell.

If activation is blocked:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Put a GitHub token in `.env` for better public search:

```env
GITHUB_TOKEN=ghp_your_token_here
```

Optional: `HIBP_API_KEY`, `DARKWEB_KEY`, `ACCOUNT_PRESENCE_ENABLED=true`

---

## How to search

### Email (full site registration scan)

```powershell
.\venv\Scripts\Activate.ps1
python main.py you@example.com
```

Faster (skip 120+ site registration checks):

```powershell
python main.py you@example.com --no-sites
```

### Username / GitHub

```powershell
python main.py myhandle
python main.py github:myhandle
python main.py https://github.com/myhandle
```

### Phone / domain

```powershell
python main.py +9198XXXXXXXX
python main.py example.com
```

### Force type

```powershell
python main.py something --type email
python main.py something --type username
python main.py something --type phone
python main.py something --type domain
```

### Web dashboard

```powershell
python main.py --web
```

Open http://127.0.0.1:8765 — paste a target and run.

### Read the report

Terminal prints a short summary and paths like:

```text
HTML: osint_output\report_....html
JSON: osint_output\report_....json
```

Open the HTML file in a browser.

---

## Current site counts

| Kind | Count |
|---|---:|
| Email registration (built-in) | ~121 |
| Email registration (extras in this repo) | 18 |
| Email total (unique names) | **~139** |
| Username / handle profiles | **67** |

Add more:

- Username URLs → edit `core/username_sites.py`
- Email checkers → add async functions in `core/extra_email_sites.py` and append to `EXTRA_EMAIL_CHECKERS`
- Then run `scripts/generate_sites_catalog.py`

---

## Live server

See **[USER_MANUAL.md](./USER_MANUAL.md)** for nginx, systemd, and `WEB_TOKEN`.

Do not bind `0.0.0.0` without `WEB_TOKEN`. Put HTTPS in front.

---

## Safety

- Default is self-assessment / authorized use only  
- No Instagram/Facebook private dumps, WhatsApp chats, or purchased leak DBs  
- Some sites rate-limit; report marks those clearly  

---

## License

MIT · [nirajj87](https://github.com/nirajj87)
