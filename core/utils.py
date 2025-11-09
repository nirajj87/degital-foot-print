import json, logging, time
from datetime import datetime, timezone
import requests

def now_str():
    return datetime.now(timezone.utc).isoformat()

def safe_get(url, headers=None, params=None, timeout=15):
    try:
        r = requests.get(url, headers=headers or {"User-Agent": "DFAnalyzer/1.0"}, params=params, timeout=timeout)
        return r
    except Exception as e:
        logging.debug(f"safe_get failed: {url} -> {e}")
        return None

def json_safe_dump(obj):
    return json.loads(json.dumps(obj, default=str))