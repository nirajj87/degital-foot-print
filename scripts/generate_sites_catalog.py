"""Regenerate docs/SITES_CATALOG.md"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.extra_email_sites import EXTRA_EMAIL_SITE_META
from core.username_sites import SITES
from holehe.core import get_functions, import_submodules

OUT = ROOT / "docs" / "SITES_CATALOG.md"


def main() -> None:
    funcs = get_functions(import_submodules("holehe.modules"))
    builtin = sorted({getattr(f, "__name__", str(f)) for f in funcs})
    extras = EXTRA_EMAIL_SITE_META
    names = set(builtin) | {e["name"] for e in extras}
    user_sites = SITES

    lines = [
        "# Sites catalog",
        "",
        "Inventory for Digital Footprint Analyzer.",
        "",
        "## Totals",
        "",
        "| Kind | Count | Where to edit |",
        "|---|---:|---|",
        f"| **Email registration (built-in pack)** | {len(builtin)} | installed package modules |",
        f"| **Email registration (project extras)** | {len(extras)} | `core/extra_email_sites.py` |",
        f"| **Email scan total (unique names)** | **{len(names)}** | merged + deduped at runtime |",
        f"| **Username / handle profiles** | {len(user_sites)} | `core/username_sites.py` |",
        "",
        "Email scan = built-in pack + extras.",
        "Username scan = `core/username_sites.py` only.",
        "",
        "## Email — project extras",
        "",
    ]
    for e in extras:
        lines.append(f"- `{e['name']}` — {e['domain']}")
    lines.extend(["", "## Email — built-in pack", ""])
    for n in builtin:
        lines.append(f"- `{n}`")
    lines.extend(["", "## Username / handle sites", ""])
    for s in user_sites:
        lines.append(f"- **{s['name']}** (`{s['id']}`) — `{s['url']}`")
    lines.append("")

    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"email_builtin={len(builtin)} extras={len(extras)} unique={len(names)} username={len(user_sites)}")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
