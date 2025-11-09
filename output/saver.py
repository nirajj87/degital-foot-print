import json
import pandas as pd
import os
import re
from datetime import datetime

def _safe_filename(s: str, maxlen: int = 120) -> str:
    """
    Sanitize target name for filename
    (replace @ with _at_ and non-alphanumeric chars with underscores)
    """
    if not s:
        s = "target"
    s = s.strip().replace("@", "_at_")
    s = re.sub(r'[^A-Za-z0-9\.\-_]', '_', s)
    if len(s) > maxlen:
        s = s[:maxlen]
    return s

def save_outputs(data, json_path: str = None, csv_path: str = None, out_dir: str = None):
    """
    Save output files as <target>_<datetime>.json and <target>_<datetime>.csv
    """

    # Setup output directory
    if out_dir is None:
        out_dir = os.path.join(os.getcwd(), "osint_output")
    os.makedirs(out_dir, exist_ok=True)

    # Create filename base from target + timestamp
    target = str(data.get("target") or "target")
    base = _safe_filename(target)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{base}_{timestamp}"

    # Default file paths
    if not json_path:
        json_path = os.path.join(out_dir, f"{base_name}.json")
    if not csv_path:
        csv_path = os.path.join(out_dir, f"{base_name}.csv")

    # Handle datetime serialization
    def default(o):
        if isinstance(o, datetime):
            return o.isoformat()
        return str(o)

    # Save JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=default)

    # Prepare summary CSV
    risk = data.get("risk_analysis", {})
    summary = {
        "target": data.get("target"),
        "type": data.get("type"),
        "risk_level": risk.get("level"),
        "score": risk.get("score"),
        "timestamp": data.get("timestamp") or datetime.now().isoformat()
    }
    pd.DataFrame([summary]).to_csv(csv_path, index=False)

    print(f"\n📄 JSON saved → {json_path}\n📊 CSV saved → {csv_path}")

    return json_path, csv_path
