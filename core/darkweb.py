import time, requests, re, logging
from typing import Dict, Any, List

def _intelx_poll_results(api_base: str, search_id: str, key: str, max_wait: float = 10.0, poll_interval: float = 0.8, format: int = 1):
    deadline = time.time() + max_wait
    res_url = api_base.rstrip("/") + "/live/search/result"
    params = {"id": search_id, "format": format, "k": key}
    last_json = None
    while time.time() < deadline:
        try:
            r = requests.get(res_url, params=params, timeout=10)
        except Exception as e:
            return {"status":"error","error":f"result_request_failed:{e}"}
        if not r:
            return {"status":"error","error":"no_response"}
        try:
            j = r.json()
            last_json = j
        except Exception:
            text = r.text or ""
            if "No results" in text or "No records" in text:
                return {"status":"empty","count":0,"raw":text}
            return {"status":"unknown","raw_text": text[:800]}
        if isinstance(j, dict):
            if j.get("status") == 0 and (j.get("records") or j.get("items")):
                records = j.get("records") or j.get("items") or []
                return {"status":"ok","count":len(records),"raw":j,"records":records}
            if j.get("status") == 3:
                return {"status":"empty","count":0,"raw":j}
            for k in ("records","items","result"):
                if k in j and isinstance(j[k], list):
                    return {"status":"ok","count":len(j[k]),"raw":j,"records":j[k]}
        time.sleep(poll_interval)
    return {"status":"timeout","raw": last_json}

def darkweb_check(email: str, key: str = None, api_url: str = "https://free.intelx.io/", max_items: int = 50):
    if not key:
        # fallback public search page
        try:
            web_search_url = api_url.rstrip("/") + "/?s=" + requests.utils.quote(email)
            r = requests.get(web_search_url, timeout=10, headers={"User-Agent":"DFAnalyzer/1.0"})
            if not r or r.status_code != 200:
                return {"status":"skipped","message":"site_unreachable"}
            snippet = r.text[:800] if r.text else ""
            return {"status":"fallback_html","count":None,"items":[],"raw":{"url":web_search_url,"snippet":snippet}}
        except Exception as e:
            return {"status":"error","error":str(e)}

    create_url = api_url.rstrip("/") + "/live/search/create"
    params = {"k": key}
    payload = {"q": email, "bucket":"", "format":1, "limit": max_items}
    headers = {"User-Agent":"DFAnalyzer/1.0","Accept":"application/json"}
    try:
        r = requests.post(create_url, params=params, json=payload, headers=headers, timeout=12)
    except Exception as e:
        return {"status":"error","error":f"create_failed:{e}"}
    if not r or r.status_code >= 400:
        try:
            r2 = requests.get(create_url, params={"k":key,"q":email,"limit":max_items}, headers=headers, timeout=12)
            r = r2
        except Exception as e:
            return {"status":"error","error":f"retry_failed:{e}"}
    if not r:
        return {"status":"error","error":"no_response"}
    if r.status_code in (401,402,403):
        return {"status":"error","error":f"auth_or_payment_required_http_{r.status_code}","text": r.text[:400]}
    try:
        j = r.json()
    except Exception:
        txt = r.text or ""
        m = re.search(r"[0-9a-fA-F\\-]{36}", txt)
        if m:
            search_id = m.group(0)
            poll = _intelx_poll_results(api_url, search_id, key, max_wait=12, poll_interval=0.8, format=1)
            if poll.get("status") == "ok":
                recs = poll.get("records") or []
                return {"status":"ok","count":len(recs),"items":recs[:max_items],"raw": poll.get("raw")}
            return poll
        return {"status":"error","error":"unexpected_create_response","text": txt[:400]}
    search_id = j.get("id") or j.get("searchid") or j.get("job") or None
    if not search_id:
        for k in ("records","items","results"):
            if k in j and isinstance(j[k], list):
                items = j[k][:max_items]
                return {"status":"ok","count":len(items),"items": items,"raw": j}
        return {"status":"error","error":"no_search_id","raw": j}
    poll = _intelx_poll_results(api_url, search_id, key, max_wait=20, poll_interval=0.8, format=1)
    if poll.get("status") != "ok":
        return poll
    records = poll.get("records") or []
    items = []
    for rec in records[:max_items]:
        it = {}
        if isinstance(rec, dict):
            it["systemid"] = rec.get("systemid") or rec.get("id") or rec.get("storageid")
            it["date"] = rec.get("date")
            it["name"] = rec.get("name") or rec.get("title")
            it["bucket"] = rec.get("bucket")
            if "text" in rec:
                it["text_preview"] = rec.get("text")[:1000] if rec.get("text") else None
            if "keyvalues" in rec:
                it["keyvalues"] = rec.get("keyvalues")
        else:
            it["raw"] = rec
        items.append(it)
    return {"status":"ok","count":len(items),"items": items,"raw": poll.get("raw")}