#!/usr/bin/env python3
import argparse
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from colorama import Fore, Style, init

from config import CONFIG
from core.breaches import normalize_breaches
from core.correlate import build_graph
from core.darkweb import darkweb_check
from core.domain_intel import host_from_url, inspect_hosts
from core.enrichment import hibp_check
from core.findings import CONSUMER_MAIL, build_findings, is_consumer_mail
from core.github_hygiene import scan_accounts
from core.github_public import enrich_username, find_accounts_for_email, websites_from_accounts
from core.history import diff_reports, previous_report
from core.account_presence import scan_email_accounts
from core.identity import classify_target
from core.network_tools import dns_lookup, fetch_ssl, whois_lookup
from core.phone_public import find_public_mentions
from core.presence import (
    check_username,
    flatten_public_links,
    gravatar_lookup,
    keybase_email_lookup,
    parse_phone,
    public_search_links,
)
from core.risk_engine import risk_score
from core.utils import now_str
from output.formatter import short_summary
from output.html_report import write_html_report
from output.saver import save_outputs

# Set by CLI / web; email scans run 120+ site registration checks unless disabled.
_SITES_OVERRIDE: bool | None = None


def set_account_presence_enabled(enabled: bool | None) -> None:
    global _SITES_OVERRIDE
    _SITES_OVERRIDE = enabled


def _account_presence_wanted() -> bool:
    if _SITES_OVERRIDE is not None:
        return _SITES_OVERRIDE
    return bool(CONFIG.get("ACCOUNT_PRESENCE_ENABLED", True))

init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "osint_output")
os.makedirs(OUT_DIR, exist_ok=True)

SKIP_HOSTS = CONSUMER_MAIL | {
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "twitter.com",
    "x.com",
    "facebook.com",
    "instagram.com",
    "youtube.com",
}


def _github_token():
    return CONFIG.get("GITHUB_TOKEN")


def analyze_email(identity):
    email = identity["value"]
    local = identity.get("username")
    domain = identity.get("domain")
    results = {}
    tasks = {
        "presence": lambda: check_username(local, _github_token()),
        "gravatar": lambda: gravatar_lookup(email),
        "keybase": lambda: keybase_email_lookup(email),
        "hibp": lambda: hibp_check(email, CONFIG.get("HIBP_API_KEY")),
        "github_accounts": lambda: find_accounts_for_email(email, _github_token()),
        "darkweb": lambda: darkweb_check(email, CONFIG.get("DARKWEB_KEY"), CONFIG.get("DARKWEB_URL")),
    }
    if domain and not is_consumer_mail(domain):
        tasks["whois"] = lambda: whois_lookup(domain)
        tasks["dns"] = lambda: dns_lookup(domain)
        tasks["ssl"] = lambda: fetch_ssl(domain)
    if _account_presence_wanted():
        timeout = float(CONFIG.get("ACCOUNT_PRESENCE_TIMEOUT") or 10)
        print(f"{Fore.CYAN}Sites:{Style.RESET_ALL} email account presence scan (120+ sites)…")
        tasks["account_presence"] = lambda: scan_email_accounts(email, timeout=timeout)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as e:
                results[name] = {"error": str(e)}

    results["breaches"] = normalize_breaches(email, results.get("hibp"), CONFIG.get("HIBP_API_KEY"))
    results["search_links"] = public_search_links(email)
    sites = results.get("account_presence") or {}
    if sites.get("status") == "ok":
        print(
            f"{Fore.CYAN}Sites:{Style.RESET_ALL} "
            f"{sites.get('found_count', 0)} found / "
            f"{sites.get('checked', 0)} checked "
            f"({sites.get('rate_limited_count', 0)} rate-limited)"
        )
    elif sites.get("status") == "unavailable":
        print(f"{Fore.YELLOW}Site scan skipped:{Style.RESET_ALL} {sites.get('reason')}")
    return results


def analyze_username(identity):
    username = identity.get("username") or identity["value"]
    results = {
        "presence": check_username(username, _github_token()),
        "github_profile": enrich_username(username, _github_token()),
        "search_links": public_search_links(username),
    }
    if results["github_profile"].get("status") == "found":
        results["github_accounts"] = {
            "accounts": [results["github_profile"]],
            "query": username,
        }
    return results


def analyze_phone(identity):
    parsed = parse_phone(identity["value"])
    local_roots = [BASE_DIR, os.path.join(os.path.dirname(BASE_DIR), "e-commerce-with-react")]
    mentions = (
        find_public_mentions(parsed, _github_token(), workspace_roots=local_roots)
        if parsed.get("status") == "ok"
        else {}
    )
    return {
        "phone": parsed,
        "phone_mentions": mentions,
        "search_links": mentions.get("search_links") or public_search_links(f'"{parsed.get("e164") or identity["value"]}"'),
        "presence": {"query": None, "profiles": [], "found_count": 0},
    }


def analyze_domain(identity):
    target = identity["value"]
    return {
        "domains": inspect_hosts([target], limit=1),
        "search_links": public_search_links(target),
        "presence": {"query": None, "profiles": [], "found_count": 0},
    }


def _accounts(results):
    accounts = list((results.get("github_accounts") or {}).get("accounts") or [])
    one = results.get("github_profile")
    if one and one.get("status") == "found" and one.get("profile"):
        login = (one["profile"].get("login") or "").lower()
        if login not in {((a.get("profile") or {}).get("login") or "").lower() for a in accounts}:
            accounts.append(one)
    return accounts


def _second_wave(identity, results):
    """Follow GitHub -> website / other handles / public leak files."""
    accounts = _accounts(results)
    if accounts and not (results.get("github_accounts") or {}).get("accounts"):
        results["github_accounts"] = {"accounts": accounts, "query": identity.get("value")}

    hosts = []
    if identity.get("domain") and not is_consumer_mail(identity.get("domain")):
        hosts.append(identity["domain"])
    for acc in accounts:
        p = acc.get("profile") or {}
        if p.get("blog"):
            hosts.append(p["blog"])
        for repo in acc.get("repos") or []:
            if repo.get("homepage"):
                hosts.append(repo["homepage"])
    hosts = [h for h in hosts if (host_from_url(h) or "") not in SKIP_HOSTS]
    if hosts:
        results["domains"] = inspect_hosts(hosts, limit=3)

    email = identity["value"] if identity.get("type") == "email" else None
    if accounts:
        results["github_hygiene"] = scan_accounts(accounts, email=email, token=_github_token())

    extra_handles = []
    local = (identity.get("username") or "").lower()
    for acc in accounts:
        login = ((acc.get("profile") or {}).get("login") or "").lower()
        if login and login != local:
            extra_handles.append(login)
    if extra_handles:
        extra = check_username(extra_handles[0], _github_token())
        base = results.get("presence") or {"profiles": []}
        merged = list(base.get("profiles") or [])
        seen = {(p.get("site"), p.get("url")) for p in merged}
        for p in extra.get("profiles") or []:
            key = (p.get("site"), p.get("url"))
            if key not in seen:
                merged.append(p)
                seen.add(key)
        found = [p for p in merged if p.get("status") == "found"]
        results["presence"] = {
            "query": [base.get("query"), extra.get("query")],
            "checked": len(merged),
            "found_count": len(found),
            "profiles": merged,
            "linked_from_profiles": (base.get("linked_from_profiles") or []) + (extra.get("linked_from_profiles") or []),
        }
    return results


def _extra_links(results):
    extras = []
    extras.extend(websites_from_accounts((results.get("github_accounts") or {}).get("accounts") or []))
    one = results.get("github_profile")
    if one and one.get("status") == "found":
        extras.extend(websites_from_accounts([one]))
    gravatar = results.get("gravatar") or {}
    if gravatar.get("status") == "found":
        extras.append({"label": "Gravatar", "url": gravatar.get("profile_url"), "status": "found"})
        for acc in gravatar.get("accounts") or []:
            extras.append({"label": f"Gravatar · {acc.get('shortname')}", "url": acc.get("url"), "status": "found"})
    keybase = results.get("keybase") or {}
    if keybase.get("status") == "found":
        extras.append({"label": "Keybase", "url": keybase.get("profile_url"), "status": "found"})
    return extras


def run_scan(target: str, forced_type: str | None = None) -> dict:
    identity = classify_target(target, forced_type)
    print(f"{Style.BRIGHT}{Fore.CYAN}Scanning {identity['original']} ({identity['type']}){Style.RESET_ALL}")
    start = time.time()
    report = {
        "target": identity["original"],
        "type": identity["type"],
        "identity": identity,
        "timestamp": now_str(),
        "results": {},
    }

    if identity["type"] == "email":
        report["results"] = analyze_email(identity)
    elif identity["type"] == "phone":
        report["results"] = analyze_phone(identity)
    elif identity["type"] == "domain":
        report["results"] = analyze_domain(identity)
    else:
        report["results"] = analyze_username(identity)

    report["results"] = _second_wave(identity, report["results"])
    report["public_links"] = flatten_public_links(
        report["results"].get("presence") or {}, _extra_links(report["results"])
    )
    prev = previous_report(OUT_DIR, identity["original"])
    report["view"] = build_findings(report)
    report["graph"] = build_graph(report)
    report["view"]["graph"] = report["graph"]
    report["risk_analysis"] = risk_score(report["results"], report["view"])
    report["results"]["history"] = diff_reports(prev, report)
    report["view"]["history"] = report["results"]["history"]

    safe_target = re.sub(r"[^A-Za-z0-9\-_]", "_", str(identity["original"]).replace("@", "_at_"))
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    json_path = os.path.join(OUT_DIR, f"report_{safe_target}_{stamp}.json")
    html_path = os.path.join(OUT_DIR, f"report_{safe_target}_{stamp}.html")
    save_outputs(report, json_path)
    write_html_report(report, html_path)
    elapsed = round(time.time() - start, 2)
    print()
    print(short_summary(report))
    print(f"{Fore.GREEN}JSON: {json_path}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}HTML: {html_path}{Style.RESET_ALL}")
    print(f"Completed in {elapsed}s")
    return {"report": report, "json_path": json_path, "html_path": html_path, "elapsed": elapsed}


def main():
    parser = argparse.ArgumentParser(
        description="Digital footprint report: breaches, 120+ site presence, GitHub, domain hygiene."
    )
    parser.add_argument("target", nargs="?", help="email | phone | username | github:name | domain")
    parser.add_argument("--type", dest="forced_type", choices=["email", "phone", "username", "domain"])
    parser.add_argument(
        "--no-sites",
        action="store_true",
        help="Skip email account presence scan (120+ sites)",
    )
    parser.add_argument(
        "--sites",
        action="store_true",
        help="Force site presence scan on (overrides ACCOUNT_PRESENCE_ENABLED=false)",
    )
    parser.add_argument("--web", action="store_true", help="Start the HTML dashboard")
    parser.add_argument("--host", help="Dashboard bind host (default WEB_HOST or 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Dashboard port (default WEB_PORT or 8765)")
    args = parser.parse_args()

    if args.no_sites and args.sites:
        parser.error("use either --sites or --no-sites, not both")
    if args.no_sites:
        set_account_presence_enabled(False)
    elif args.sites:
        set_account_presence_enabled(True)

    if args.web:
        from output.webui import start_web

        start_web(
            OUT_DIR,
            lambda target: run_scan(target),
            host=args.host,
            port=args.port,
        )
        return
    if not args.target:
        parser.error("target is required (or use --web)")
    run_scan(args.target, args.forced_type)


if __name__ == "__main__":
    main()
