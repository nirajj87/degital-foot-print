# Digital Footprint Analyzer

Self-assessment tool for **your own** email, phone, username, or domain.

It collects **public** data only: breach lists, GitHub profiles, domain email-auth (SPF/DMARC/SSL), and public pages that mention a handle or number. It does **not** log into Instagram/Facebook, read WhatsApp, or query people-search / leak marketplaces.

Use it on accounts you own, or with written permission.

## What you get

- Risk score with reasons you can act on
- Breach names, years, and data types (XposedOrNot or Have I Been Pwned)
- GitHub profile, repos, and public files that look like secrets or published emails
- Domain hygiene for websites discovered from GitHub
- HTML + JSON + CSV report under `osint_output/`
- Optional local / live dashboard (`python main.py --web`)

## Quick start (Windows)

```bat
git clone https://github.com/nirajj87/degital-foot-print.git
cd degital-foot-print
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Put a GitHub token in `.env` (`GITHUB_TOKEN=...`) for better public search.

```bat
python main.py you@example.com
python main.py +9198XXXXXXXX
python main.py github:yourlogin
python main.py example.com
python main.py --web
```

Open the printed `HTML:` path in a browser.

## Live server

See **[USER_MANUAL.md](USER_MANUAL.md)** — what to install, `.env` keys, nginx, systemd, and the access token.

Do not bind `0.0.0.0` without `WEB_TOKEN`. Put HTTPS (nginx) in front.

## License

MIT. Author: [nirajj87](https://github.com/nirajj87)
