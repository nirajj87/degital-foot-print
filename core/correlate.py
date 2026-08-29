"""Build a small identity graph from confirmed public links."""
from __future__ import annotations


def build_graph(report: dict) -> dict:
    nodes = []
    edges = []
    seen = set()

    def add_node(nid, label, kind):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "label": label, "kind": kind})

    def add_edge(src, dst, why):
        edges.append({"from": src, "to": dst, "why": why})

    identity = report.get("identity") or {}
    target = report.get("target")
    if identity.get("type") == "email":
        add_node("email", target, "email")
    elif identity.get("type") == "username":
        add_node("handle", target, "username")
    else:
        add_node("target", target, identity.get("type") or "target")

    results = report.get("results") or {}
    view = report.get("view") or {}

    for acc in view.get("github_accounts") or []:
        p = acc.get("profile") or {}
        login = p.get("login")
        if not login:
            continue
        nid = f"gh:{login}"
        add_node(nid, f"GitHub @{login}", "github")
        add_edge("email" if "email" in seen else "handle" if "handle" in seen else "target", nid, acc.get("matched_via") or "public search / profile")
        if p.get("blog"):
            wid = f"web:{p['blog']}"
            add_node(wid, p["blog"], "website")
            add_edge(nid, wid, "GitHub blog field")
        if p.get("company"):
            cid = f"org:{p['company']}"
            add_node(cid, p["company"], "org")
            add_edge(nid, cid, "GitHub company")

    for flag in (results.get("github_hygiene") or {}).get("flags") or []:
        if flag.get("kind") == "email_in_readme" and "email" in seen:
            repo = flag.get("repo")
            rid = f"repo:{repo}"
            add_node(rid, repo, "repo")
            add_edge("email", rid, "email published in README")

    for domain in results.get("domains") or []:
        d = domain.get("domain")
        if not d:
            continue
        did = f"dns:{d}"
        add_node(did, d, "domain")
        if "email" in seen:
            add_edge("email", did, "discovered website / domain")
        for issue in domain.get("issues") or []:
            add_edge(did, did, issue)

    # drop self-loop issue edges — keep issues on the node instead
    edges = [e for e in edges if e["from"] != e["to"]]
    return {"nodes": nodes, "edges": edges}
