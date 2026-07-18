"""OAuth 回调 URL 与敏感重定向响应的统一安全处理。"""

from collections.abc import Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi.responses import RedirectResponse

OAUTH_RESERVED_QUERY_KEYS = frozenset({"code", "state", "error", "error_description"})


def append_oauth_query(url: str, params: Mapping[str, str]) -> str:
    """保留业务查询参数，并由当前响应唯一替换 OAuth 保留参数。"""
    parts = urlsplit(url)
    query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key not in OAUTH_RESERVED_QUERY_KEYS
    ]
    query.extend(params.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def oauth_redirect(url: str, params: Mapping[str, str]) -> RedirectResponse:
    """生成禁止缓存且不泄露 Referer 的 OAuth code/error 重定向。"""
    response = RedirectResponse(url=append_oauth_query(url, params), status_code=302)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
