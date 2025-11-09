import logging, requests
from .utils import safe_get

def twitter_search(query, max_results=20):
    # try snscrape via subprocess-less import if available; fallback handled by main if not installed
    try:
        import snscrape.modules.twitter as sntwitter
    except Exception:
        sntwitter = None
    if not sntwitter:
        return {"skipped": True, "message": "snscrape not installed"}
    items = []
    try:
        for i, t in enumerate(sntwitter.TwitterSearchScraper(query).get_items()):
            if i >= max_results: break
            items.append({"date": str(t.date), "content": t.content, "user": t.user.username, "url": t.url})
    except Exception as e:
        logging.debug(f"snscrape error: {e}")
        return {"error": str(e)}
    return items

def github_search_user(username, token=None):
    if not token:
        return {"skipped": True, "message": "GITHUB_TOKEN missing"}
    headers = {"Authorization": f"Bearer {token}", "Accept":"application/vnd.github+json"}
    url = f"https://api.github.com/search/users?q={username}+in:login"
    r = safe_get(url, headers=headers, timeout=10)
    if not r: return {"error":"request_failed"}
    if r.status_code == 200:
        return r.json()
    return {"status": r.status_code, "text": r.text}