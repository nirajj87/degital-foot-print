def risk_score(results):
    score = 0
    reasons = []
    hibp = results.get("hibp")
    if isinstance(hibp, list) and hibp:
        score += 40; reasons.append(f"{len(hibp)} breaches found")
    if results.get("shodan") and isinstance(results.get("shodan"), dict) and "error" not in results.get("shodan"):
        score += 20; reasons.append("Shodan data present (possible exposure)")
    if results.get("darkweb") and isinstance(results.get("darkweb"), dict) and results["darkweb"].get("status")=="ok":
        score += 25; reasons.append("Darkweb mentions found")
    level = "Low"
    if score>=60: level="High"
    elif score>=30: level="Medium"
    return {"score": score, "level": level, "reasons": reasons}