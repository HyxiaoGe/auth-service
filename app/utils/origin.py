"""浏览器 Origin 与 schemeful site 的安全判定。"""

from ipaddress import ip_address
from urllib.parse import SplitResult, urlsplit

import tldextract

# 使用随依赖发布的 PSL 快照，避免请求路径首次命中时联网；private suffix 必须纳入，
# 否则 tenant-a.github.io 与 tenant-b.github.io 会被误判为同站。
_extract_site = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
)


def _normalized_host(parsed: SplitResult) -> str | None:
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if parsed.netloc.endswith(":") and port is None:
        return None
    if host is None or parsed.username is not None or parsed.password is not None:
        return None
    try:
        return host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def _is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _parse_web_url(value: str | None, *, origin_only: bool) -> tuple[str, str] | None:
    if not value or value == "null" or any(char in value for char in "\r\n\t"):
        return None
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if origin_only and (parsed.path or parsed.query or parsed.fragment):
        return None
    host = _normalized_host(parsed)
    if host is None:
        return None
    if parsed.scheme == "http" and not _is_loopback_host(host):
        return None
    return parsed.scheme, host


def _registrable_site(host: str) -> str | None:
    try:
        ip_address(host)
    except ValueError:
        extracted = _extract_site(host)
        return extracted.top_domain_under_public_suffix or None
    return None


def schemeful_web_origin_same_site(auth_base_url: str, origin: str | None) -> bool:
    """仅接受与 auth-service 同 schemeful site 的 HTTPS 或 loopback HTTP Origin。

    端口不属于 site。localhost 与 IP 不进入 PSL：只有同一个规范化 host 才算同站，
    避免把 localhost、127.0.0.1 或不同 IP 互相归并。
    """

    auth = _parse_web_url(auth_base_url, origin_only=False)
    candidate = _parse_web_url(origin, origin_only=True)
    if auth is None or candidate is None:
        return False
    auth_scheme, auth_host = auth
    candidate_scheme, candidate_host = candidate
    if auth_scheme != candidate_scheme:
        return False
    if auth_host == candidate_host:
        return True
    if _is_loopback_host(auth_host) or _is_loopback_host(candidate_host):
        return False
    auth_site = _registrable_site(auth_host)
    candidate_site = _registrable_site(candidate_host)
    return auth_site is not None and auth_site == candidate_site
