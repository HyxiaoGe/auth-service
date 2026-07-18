"""OAuth 回调 URI 的统一安全策略。"""

from ipaddress import ip_address
from urllib.parse import urlsplit


def oauth_redirect_uri_allowed(redirect_uri: str) -> bool:
    """仅允许 HTTPS、Electron app://- 与 loopback HTTP 回调。"""
    if not redirect_uri or any(char in redirect_uri for char in "\r\n\t"):
        return False
    try:
        parsed = urlsplit(redirect_uri)
        port = parsed.port
    except ValueError:
        return False
    if not parsed.netloc or parsed.fragment or parsed.username is not None or parsed.password is not None:
        return False
    if any(char in parsed.netloc for char in "'\"; "):
        return False
    if parsed.scheme == "https":
        return parsed.hostname is not None
    if parsed.scheme == "app":
        return parsed.netloc == "-" and port is None
    if parsed.scheme != "http":
        return False
    host = parsed.hostname
    if host == "localhost":
        return True
    try:
        return host is not None and ip_address(host).is_loopback
    except ValueError:
        return False


def oauth_redirect_origin(redirect_uri: str) -> str | None:
    """返回可安全写入 CSP 的回调 origin，不包含路径、查询参数或 fragment。"""
    if not oauth_redirect_uri_allowed(redirect_uri):
        return None
    parsed = urlsplit(redirect_uri)
    return f"{parsed.scheme}://{parsed.netloc}"
