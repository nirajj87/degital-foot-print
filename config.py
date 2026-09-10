import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

_PLACEHOLDERS = {"", "your_key_here", "your_token_here", "none", "null"}


def _key(name: str, default=None):
    val = os.environ.get(name)
    if val is None:
        val = default
    if val is None:
        return None
    text = str(val).strip()
    if text.lower() in _PLACEHOLDERS:
        return None
    return text


def _bool(name: str, default: bool = True) -> bool:
    raw = _key(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "on"}


CONFIG = {
    "HIBP_API_KEY": _key("HIBP_API_KEY"),
    "GITHUB_TOKEN": _key("GITHUB_TOKEN"),
    "SHODAN_API_KEY": _key("SHODAN_API_KEY"),
    "HUNTER_API_KEY": _key("HUNTER_API_KEY"),
    "CLEARBIT_KEY": _key("CLEARBIT_KEY"),
    "FULLCONTACT_KEY": _key("FULLCONTACT_KEY"),
    "URLSCAN_API_KEY": _key("URLSCAN_API_KEY"),
    "IPINFO_TOKEN": _key("IPINFO_TOKEN"),
    "DARKWEB_KEY": _key("DARKWEB_KEY"),
    "DARKWEB_URL": _key("DARKWEB_URL", "https://free.intelx.io/"),
    "ACCOUNT_PRESENCE_ENABLED": _bool("ACCOUNT_PRESENCE_ENABLED", True),
    "ACCOUNT_PRESENCE_TIMEOUT": float(_key("ACCOUNT_PRESENCE_TIMEOUT", "10") or "10"),
    "WEB_TOKEN": _key("WEB_TOKEN"),
    "WEB_HOST": _key("WEB_HOST", "127.0.0.1") or "127.0.0.1",
    "WEB_PORT": int(_key("WEB_PORT", "8765") or "8765"),
}
