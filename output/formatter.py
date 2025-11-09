from colorama import Fore, Style

def short_summary(data):
    lines = []
    target = data.get("target")
    dtype = data.get("type")
    risk = data["risk_analysis"]

    lines.append(f"{Fore.CYAN}🎯 Target:{Style.RESET_ALL} {target}")
    lines.append(f"{Fore.YELLOW}Type:{Style.RESET_ALL} {dtype}")
    lines.append(f"{Fore.MAGENTA}Risk Level:{Style.RESET_ALL} {risk['level']} ({risk['score']})")

    if risk.get("notes"):
        lines.append(f"{Fore.GREEN}Notes:{Style.RESET_ALL} " + ", ".join(risk["notes"]))

    lines.append(f"{Fore.CYAN}Timestamp:{Style.RESET_ALL} {data.get('timestamp')}")

    return "\n".join(lines)
