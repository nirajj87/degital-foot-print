# User manual — Digital Footprint Analyzer

This guide covers local use and putting the dashboard on a live Linux server.

Scan **only your own** identifiers, or assets you have written permission to assess.

---

## 1. What the tool does

| Input | What it checks |
|---|---|
| Email | **~139 site registration checks** (121 built-in + 18 extras) — account exists signals; breaches; Gravatar/Keybase; GitHub; social handle of the local-part; domain of custom mail (not Gmail) |
| Phone | Country/carrier parse, public GitHub mentions, local project files, search links |
| Username / `github:name` / profile URL | Public profile matrix across **67** sites (`core/username_sites.py`) + GitHub card |
| Domain | WHOIS summary, SPF/DMARC, SSL days left, site title, certificate-transparency names |

Site inventory: **[docs/SITES_CATALOG.md](./docs/SITES_CATALOG.md)**. Add username URLs in `core/username_sites.py`; add email checkers in `core/extra_email_sites.py`.

Second wave (after GitHub is found): inspect the website on the profile, flag public `.env`-like files and emails in READMEs, compare with the last scan.

**It will not:** dump Instagram/Facebook private data, Truecaller names, WhatsApp chats, or purchased leak files.

Skip the 120+ site email check with `--no-sites` or `ACCOUNT_PRESENCE_ENABLED=false`.

---

## 2. Install (local PC)

Need: Python 3.10 or newer.

```powershell
cd degital-foot-print
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Linux / Mac:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

---

## 3. What to put in `.env`

| Variable | Required? | Why |
|---|---|---|
| `GITHUB_TOKEN` | Strongly recommended | Public user/repo/code search, hygiene, email→GitHub link. Create at GitHub → Settings → Developer settings → Personal access tokens (classic: `public_repo` is enough for public data). |
| `HIBP_API_KEY` | Optional | Official Have I Been Pwned. If empty, XposedOrNot is used. |
| `DARKWEB_KEY` | Optional | IntelX mentions. Skip if you do not have a key. |
| `ACCOUNT_PRESENCE_ENABLED` | Optional | Default `true`. Set `false` to skip the 120+ site email scan. |
| `ACCOUNT_PRESENCE_TIMEOUT` | Optional | Per-request timeout seconds (default `10`). |
| `WEB_TOKEN` | **Required on a public server** | Password for the web form. Long random string. |
| `WEB_HOST` | Optional | Default `127.0.0.1`. Live server: `127.0.0.1` (nginx proxies) or `0.0.0.0`. |
| `WEB_PORT` | Optional | Default `8765`. |

Do not commit `.env`. Unused keys can stay blank.

---

## 4. Operate (CLI)

```bat
python main.py you@example.com
python main.py you@example.com --type email
python main.py you@example.com --no-sites
python main.py +9198XXXXXXXX --type phone
python main.py myhandle --type username
python main.py github:myhandle
python main.py https://github.com/myhandle
python main.py mysite.com --type domain
```

Email targets run the **120+ site presence scan** by default. Use `--no-sites` for a faster scan without it.

Reports:

- `osint_output/report_<target>_<time>.html` — open this
- `osint_output/report_<target>_<time>.json`
- CSV summary next to them

Dashboard (this machine only):

```bat
python main.py --web
```

Browser: http://127.0.0.1:8765

---

## 5. Live server — what to install

Example: Ubuntu 22.04, domain `footprint.yourdomain.com`.

### 5.1 Packages

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx git
```

Optional SSL:

```bash
sudo apt install -y certbot python3-certbot-nginx
```

### 5.2 App user and code

```bash
sudo adduser --system --group --home /opt/dfanalyzer dfanalyzer
sudo mkdir -p /opt/dfanalyzer/app
sudo git clone https://github.com/nirajj87/degital-foot-print.git /opt/dfanalyzer/app
sudo chown -R dfanalyzer:dfanalyzer /opt/dfanalyzer
```

```bash
sudo -u dfanalyzer -H bash -lc '
  cd /opt/dfanalyzer/app
  python3 -m venv venv
  venv/bin/pip install -r requirements.txt
  cp .env.example .env
'
```

Edit secrets (do this as root or the app user):

```bash
sudo nano /opt/dfanalyzer/app/.env
```

Set at least:

```
GITHUB_TOKEN=ghp_...
WEB_TOKEN=change-this-to-a-long-random-string
WEB_HOST=127.0.0.1
WEB_PORT=8765
```

`WEB_HOST=127.0.0.1` means only nginx on the same machine can reach the app. That is the correct live setup.

### 5.3 systemd service

Copy `deploy/dfanalyzer.service` to `/etc/systemd/system/dfanalyzer.service` (paths already match `/opt/dfanalyzer/app`).

```bash
sudo cp /opt/dfanalyzer/app/deploy/dfanalyzer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dfanalyzer
sudo systemctl status dfanalyzer
```

### 5.4 nginx + HTTPS

1. Point DNS A record of `footprint.yourdomain.com` to the server IP.
2. Copy `deploy/nginx.example.conf` to `/etc/nginx/sites-available/dfanalyzer`.
3. Replace `footprint.yourdomain.com`.
4. Enable the site and get a certificate:

```bash
sudo ln -s /etc/nginx/sites-available/dfanalyzer /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d footprint.yourdomain.com
```

### 5.5 What you type in the browser

1. Open `https://footprint.yourdomain.com`
2. Enter the **access token** (`WEB_TOKEN`)
3. Enter email / phone / GitHub / domain
4. Wait for the HTML report

Without the token the form is rejected. There is a short per-IP pause between scans.

### 5.6 Updates

```bash
sudo -u dfanalyzer -H bash -lc 'cd /opt/dfanalyzer/app && git pull && venv/bin/pip install -r requirements.txt'
sudo systemctl restart dfanalyzer
```

---

## 6. Windows VPS (IIS / no nginx)

Not recommended. If you must:

1. Install Python 3.10+.
2. Same `venv` + `.env` as local.
3. Run `python main.py --web --host 127.0.0.1 --port 8765`
4. Put IIS or Caddy as reverse proxy to `127.0.0.1:8765`
5. Bind a certificate on 443. Do not publish port 8765 to the internet.

---

## 7. Firewall

- Allow 80 and 443 from the internet.
- Do **not** allow 8765 from the internet if nginx talks to 127.0.0.1.
- If you set `WEB_HOST=0.0.0.0`, you must set `WEB_TOKEN` or the process exits.

---

## 8. Domain email (DMARC)

If the report says DMARC is missing, add a DNS **TXT** record. See `dns/example-dmarc.txt`.

---

## 9. Limits and legal

- Public APIs have rate limits. A GitHub token avoids most empty GitHub sections.
- Reports can contain personal data. Keep `osint_output/` off public git and off world-readable web roots (nginx only proxies the app, it does not serve that folder directly).
- Unauthorized scanning of other people can be illegal. This tool is for awareness and authorized review.

---

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `GITHUB_TOKEN missing` / weak GitHub section | Add token in `.env` |
| Web UI will not start on `0.0.0.0` | Set `WEB_TOKEN` |
| 502 from nginx | `systemctl status dfanalyzer`; app must listen on 127.0.0.1:8765 |
| Empty phone GitHub hits | Token + wait; also check your own repos locally |
| WHOIS/SSL on Gmail | Ignored on purpose (consumer mail) |
