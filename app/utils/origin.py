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


def _web_origin(value: str | None) -> str | None:
    """规范化 web URL 的 origin，保留显式端口但移除 path/query/fragment。"""
    if not value or value == "null" or any(char in value for char in "\r\n\t"):
        return None
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or (parsed.netloc.endswith(":") and port is None)
    ):
        return None
    host = _normalized_host(parsed)
    if host is None:
        return None
    rendered_host = f"[{host}]" if ":" in host else host
    rendered_port = f":{port}" if port is not None else ""
    return f"{parsed.scheme}://{rendered_host}{rendered_port}"


def trusted_auth_frontchannel_origin(
    request_url: str,
    auth_base_url: str,
    auth_browser_aliases: list[str],
) -> str | None:
    """返回请求实际命中的受信 auth frontchannel origin。

    不能仅凭 RP Origin 或 Host 的“看起来像 localhost”放行；当前请求 origin 必须与
    canonical auth origin 或显式 development loopback alias 精确匹配。
    """
    request_origin = _web_origin(request_url)
    if request_origin is None:
        return None
    trusted_origins = {
        origin
        for candidate in (auth_base_url, *auth_browser_aliases)
        if (origin := _web_origin(candidate)) is not None
    }
    return request_origin if request_origin in trusted_origins else None


def auth_browser_alias_origin_matches(
    origin: str | None,
    auth_browser_aliases: list[str],
) -> bool:
    """origin 是否精确命中显式配置的浏览器 auth alias。"""
    normalized_origin = _web_origin(origin)
    if normalized_origin is None:
        return False
    return normalized_origin in {
        alias_origin
        for candidate in auth_browser_aliases
        if (alias_origin := _web_origin(candidate)) is not None
    }


def trusted_auth_request_origin(
    request_url: str,
    auth_base_url: str,
    auth_browser_aliases: list[str],
    *,
    peer_host: str | None,
    trusted_proxy_networks: tuple,
    forwarded_proto: str | None,
    forwarded_host: str | None,
) -> str | None:
    """解析浏览器实际命中的受信 auth origin，并安全兼容 HTTPS 反向代理。

    先接受 ASGI 已还原的 canonical/alias origin。只有直连 peer 命中显式可信代理
    网段时，才读取单值 ``X-Forwarded-Proto`` / ``X-Forwarded-Host``；这避免公网
    Cloudflare/反代把容器内 HTTP 误判为不可信，也不把攻击者自报转发头当事实。
    """
    direct_origin = trusted_auth_frontchannel_origin(
        request_url,
        auth_base_url,
        auth_browser_aliases,
    )
    if direct_origin is not None:
        return direct_origin
    if peer_host is None:
        return None
    try:
        peer_address = ip_address(peer_host)
    except ValueError:
        return None
    if not any(peer_address in network for network in trusted_proxy_networks):
        return None

    if forwarded_proto is None or "," in forwarded_proto:
        return None
    scheme = forwarded_proto.strip()
    if scheme not in {"http", "https"}:
        return None
    try:
        parsed_request = urlsplit(request_url)
    except ValueError:
        return None
    host = parsed_request.netloc
    if forwarded_host is not None:
        if "," in forwarded_host:
            return None
        host = forwarded_host.strip()
    if not host:
        return None
    return trusted_auth_frontchannel_origin(
        f"{scheme}://{host}",
        auth_base_url,
        auth_browser_aliases,
    )


def auth_frontchannel_origin_matches(
    request_url: str,
    auth_base_url: str,
    auth_browser_aliases: list[str],
    rp_origin: str | None,
) -> bool:
    """当前 auth frontchannel 与 RP Origin 是否属于同一 schemeful site。"""
    frontchannel = trusted_auth_frontchannel_origin(
        request_url,
        auth_base_url,
        auth_browser_aliases,
    )
    return frontchannel is not None and schemeful_web_origin_same_site(frontchannel, rp_origin)


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
