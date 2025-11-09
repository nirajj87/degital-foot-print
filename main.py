#!/usr/bin/env python3
import os, argparse, time, json, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
init(autoreset=True)

# project imports
from core.utils import now_str, safe_get, json_safe_dump
from core.network_tools import whois_lookup, dns_lookup, fetch_ssl
from core.enrichment import hibp_check, github_deep_scan
from core.darkweb import darkweb_check
from core.social import twitter_search, github_search_user
from core.risk_engine import risk_score
from output.formatter import short_summary
from output.saver import save_outputs
import os, time, re
from datetime import datetime

# load config from environment or fallback to module CONFIG in a single-file scenario
try:
    from config import CONFIG
except Exception:
    # try environment variables
    CONFIG = {
        "HIBP_API_KEY": os.environ.get("HIBP_API_KEY"),
        "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN"),
        "SHODAN_API_KEY": os.environ.get("SHODAN_API_KEY"),
        "HUNTER_API_KEY": os.environ.get("HUNTER_API_KEY"),
        "CLEARBIT_KEY": os.environ.get("CLEARBIT_KEY"),
        "FULLCONTACT_KEY": os.environ.get("FULLCONTACT_KEY"),
        "URLSCAN_API_KEY": os.environ.get("URLSCAN_API_KEY"),
        "IPINFO_TOKEN": os.environ.get("IPINFO_TOKEN"),
        "DARKWEB_KEY": os.environ.get("DARKWEB_KEY"),
        "DARKWEB_URL": os.environ.get("DARKWEB_URL", "https://free.intelx.io/")
    }

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "osint_output")
os.makedirs(OUT_DIR, exist_ok=True)

def analyze_email(target):
    local, domain = target.split("@",1)
    results = {}
    # define concurrent tasks
    tasks = {
        "whois": lambda: whois_lookup(domain),
        "dns": lambda: dns_lookup(domain),
        "ssl": lambda: fetch_ssl(domain),
        "hibp": lambda: hibp_check(target, CONFIG.get("HIBP_API_KEY")),
        "github": lambda: github_deep_scan(local, CONFIG.get("GITHUB_TOKEN")),
        "darkweb": lambda: darkweb_check(target, CONFIG.get("DARKWEB_KEY"), CONFIG.get("DARKWEB_URL")),
        "twitter": lambda: twitter_search(local, max_results=15)
    }
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as e:
                results[name] = {"error": str(e)}
    return results

def analyze_domain(target):
    results = {}
    tasks = {
        "whois": lambda: whois_lookup(target),
        "dns": lambda: dns_lookup(target),
        "ssl": lambda: fetch_ssl(target),
        "builtwith": lambda: __import__('core.network_tools').network_tools.builtwith_info(target) if False else {"skipped": True},
        "reverse_ip": lambda: __import__('core.network_tools').network_tools.reverse_ip_lookup(target) if False else {"skipped": True},
        "urlscan": lambda: __import__('core.enrichment').enrichment.urlscan_lookup(target) if False else {"skipped": True},
    }
    # run sequentially (domain tasks often quick)
    for k, fn in tasks.items():
        try:
            results[k] = fn()
        except Exception as e:
            results[k] = {"error": str(e)}
    return results

def analyze_username(target):
    results = {}
    tasks = {
        "github_user": lambda: github_search_user(target, CONFIG.get("GITHUB_TOKEN")),
        "github_deep": lambda: github_deep_scan(target, CONFIG.get("GITHUB_TOKEN")),
        "twitter": lambda: twitter_search(target, max_results=20)
    }
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(fn): name for name, fn in tasks.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as e:
                results[name] = {"error": str(e)}
    return results

def main():
    parser = argparse.ArgumentParser(description="Ultra OSINT Analyzer (modular)")
    parser.add_argument("target", help="email | domain | username")
    args = parser.parse_args()

    target = args.target.strip()
    print(f"{Style.BRIGHT}{Fore.CYAN}Starting analysis for: {target}{Style.RESET_ALL}")
    start = time.time()
    report = {"target": target, "timestamp": now_str(), "results": {}}

    try:
        if "@" in target:
            report["type"] = "email"
            report["results"] = analyze_email(target)
        elif "." in target:
            report["type"] = "domain"
            report["results"] = analyze_domain(target)
        else:
            report["type"] = "username"
            report["results"] = analyze_username(target)
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        return

    report["risk_analysis"] = risk_score(report["results"])
    # save outputs
    target = target

    # Sanitize target for filename (replace @ with _at_ and remove unsafe chars)
    safe_target = re.sub(r'[^A-Za-z0-9\-_]', '_', target.replace('@', '_at_'))

    # Create timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Final paths with target + timestamp
    json_path = os.path.join(OUT_DIR, f"report_{safe_target}_{timestamp}.json")
   # csv_path  = os.path.join(OUT_DIR, f"summary_{safe_target}_{timestamp}.csv")
    #save_outputs(report, json_path, csv_path)
    save_outputs(report, json_path)
    # pretty print
    print(short_summary(report))
    print(f"{Fore.GREEN}Saved JSON → {json_path}{Style.RESET_ALL}")
    #print(f"{Fore.GREEN}Saved CSV  → {csv_path}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Log file:  {os.path.join(OUT_DIR,'.')}{Style.RESET_ALL}")
    print(f"Completed in {round(time.time()-start,2)}s")

if __name__ == "__main__":
    main()