import logging, requests
from .utils import safe_get

def hibp_check(email, key=None):
    # prefer official HIBP when key provided; otherwise fallback to xposedornot
    headers = {"User-Agent":"DFAnalyzer/1.0"}
    if key:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers["hibp-api-key"] = key
        params = {"truncateResponse":"false"}
    else:
        url = f"https://api.xposedornot.com/v1/check-email/{email}"
        params = None
    r = safe_get(url, headers=headers, params=params, timeout=15)
    if not r:
        return {"error":"request_failed"}
    if r.status_code == 200:
        try:
            return r.json()
        except Exception:
            return {"raw": r.text}
    if r.status_code == 404:
        return []
    return {"status": r.status_code, "text": r.text}

def github_deep_scan(query, token=None):
    if not token:
        return {"skipped": True, "message": "GITHUB_TOKEN missing"}
    headers = {"Authorization": f"Bearer {token}", "Accept":"application/vnd.github+json"}
    base = "https://api.github.com/search"
    sections = {}
    for kind in ("users","repositories","code","commits"):
        try:
            r = requests.get(f"{base}/{kind}?q={query}", headers=headers, timeout=10)
            sections[kind] = r.json() if r.ok else {"error": r.status_code, "text": r.text}
        except Exception as e:
            logging.debug(f"github_deep_scan {kind} error: {e}")
            sections[kind] = {"error": str(e)}
    return {"query": query, "sections": sections}