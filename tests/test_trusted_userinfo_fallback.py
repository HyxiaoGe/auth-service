from types import SimpleNamespace

import jwt
import pytest

from app.security import deps


class _Response:
    def __init__(self, status_code: int, body: dict):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class _AsyncClient:
    response = _Response(500, {})
    requests: list[tuple[str, dict]] = []
    client_kwargs: list[dict] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.client_kwargs.append(kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, url: str, **kwargs):
        self.requests.append((url, kwargs))
        return self.response


@pytest.fixture(autouse=True)
def _reset_client():
    _AsyncClient.requests = []
    _AsyncClient.client_kwargs = []
    _AsyncClient.response = _Response(500, {})


@pytest.mark.asyncio
async def test_get_current_user_uses_explicit_trusted_userinfo_after_local_signature_failure(monkeypatch):
    monkeypatch.setattr(
        deps,
        "settings",
        SimpleNamespace(
            app_env="development",
            jwt_trusted_issuer="https://auth.example.com",
        ),
    )
    monkeypatch.setattr(
        deps,
        "decode_token",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(jwt.InvalidSignatureError("bad signature")),
    )
    monkeypatch.setattr(deps.httpx, "AsyncClient", _AsyncClient)
    monkeypatch.setattr(deps, "is_user_access_revoked", lambda *_args, **_kwargs: None)
    _AsyncClient.response = _Response(
        200,
        {
            "id": "f6d3827e-3827-4c4c-8e5e-6880a1c05f22",
            "email": "admin@example.com",
            "is_superuser": True,
            "is_active": True,
        },
    )

    user = await deps.get_current_user(
        credentials=SimpleNamespace(credentials="opaque-access-token"),
    )

    assert user.sub == "f6d3827e-3827-4c4c-8e5e-6880a1c05f22"
    assert user.email == "admin@example.com"
    assert user.scopes == ["admin"]
    assert _AsyncClient.requests == [
        (
            "https://auth.example.com/auth/userinfo",
            {"headers": {"Authorization": "Bearer opaque-access-token"}},
        )
    ]
    assert _AsyncClient.client_kwargs == [
        {"timeout": 5.0, "follow_redirects": False, "trust_env": False}
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("app_env", "trusted_issuer"),
    [("production", "https://auth.example.com"), ("development", "")],
)
async def test_get_current_user_does_not_use_remote_fallback_without_development_trust(
    monkeypatch,
    app_env: str,
    trusted_issuer: str,
):
    monkeypatch.setattr(
        deps,
        "settings",
        SimpleNamespace(app_env=app_env, jwt_trusted_issuer=trusted_issuer),
    )
    monkeypatch.setattr(
        deps,
        "decode_token",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(jwt.InvalidSignatureError("bad signature")),
    )
    monkeypatch.setattr(deps.httpx, "AsyncClient", _AsyncClient)

    with pytest.raises(deps.HTTPException) as exc_info:
        await deps.get_current_user(credentials=SimpleNamespace(credentials="opaque-access-token"))

    assert exc_info.value.status_code == 401
    assert _AsyncClient.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("response", "expected_status"),
    [
        (_Response(401, {"detail": "Invalid token"}), 401),
        (_Response(403, {"detail": "Forbidden"}), 401),
        (_Response(200, {"id": "not-a-uuid", "email": "admin@example.com", "is_superuser": True}), 401),
        (_Response(200, {"id": "f6d3827e-3827-4c4c-8e5e-6880a1c05f22", "email": "", "is_superuser": True}), 401),
    ],
)
async def test_get_current_user_rejects_untrusted_or_invalid_userinfo(monkeypatch, response, expected_status):
    monkeypatch.setattr(
        deps,
        "settings",
        SimpleNamespace(
            app_env="development",
            jwt_trusted_issuer="https://auth.example.com",
        ),
    )
    monkeypatch.setattr(
        deps,
        "decode_token",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(jwt.InvalidSignatureError("bad signature")),
    )
    monkeypatch.setattr(deps.httpx, "AsyncClient", _AsyncClient)
    _AsyncClient.response = response

    with pytest.raises(deps.HTTPException) as exc_info:
        await deps.get_current_user(credentials=SimpleNamespace(credentials="opaque-access-token"))

    assert exc_info.value.status_code == expected_status
