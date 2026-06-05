"""Rotation grace window + per-app revoke scope on refresh-token reuse detection.

When a rotation RESPONSE is lost over a flaky tunnel the client keeps the old (now-revoked)
token and replays it. The original code treated ANY replay of a revoked token as a reuse
attack and revoked every token the user held -- across all apps -- logging them out. Two
fixes live here:

* Grace window: re-issue the successor ONCE for a token that was killed by a normal rotation
  within the last few seconds (a lost-response retry), while keeping the revoke-all hammer for
  everything that actually looks like theft.
* Per-app revoke scope: when reuse IS treated as theft, revoke only the offending app's tokens
  (``stored.app_client_id``) instead of every app's. Each first-party app holds an independent
  rotation lineage; nuking them all turns one app's lost-rotation replay into a cross-app
  spurious logout (observed live). Deliberate account-wide logout still sweeps every app.

These tests follow the suite's no-real-DB style (see ``test_logout``): the DB query and the
two terminal helpers (``_issue_tokens`` / ``_revoke_all_user_tokens``) are faked/monkeypatched
so we assert the *decision* the branch makes. The single-consumption atomicity itself rides on
``SELECT ... FOR UPDATE`` (a Postgres row lock) which can't be exercised without a real DB; the
``grace_consumed`` flag logic that the lock protects is covered by
``test_already_consumed_replay_revokes_all``.
"""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.security import revocation
from app.services import auth_service


class _FakeResult:
    def __init__(self, obj):
        self._obj = obj

    def scalar_one_or_none(self):
        return self._obj


class _FakeDB:
    """Returns a preset ``stored`` from execute(); commit is a no-op (terminal helpers faked)."""

    def __init__(self, stored):
        self._stored = stored

    async def execute(self, *_args, **_kwargs):
        return _FakeResult(self._stored)

    async def commit(self):
        pass

    def add(self, *_args, **_kwargs):
        pass


def _stored(*, is_revoked, rotated_at, grace_consumed=False, is_active=True, user_id=None):
    uid = user_id or uuid.uuid4()
    return SimpleNamespace(
        is_revoked=is_revoked,
        rotated_at=rotated_at,
        grace_consumed=grace_consumed,
        app_client_id="app_x",
        user_id=uid,
        user=SimpleNamespace(id=uid, is_active=is_active),
    )


@pytest.fixture
def patched(monkeypatch):
    """Neutralize token decode/hash and record which terminal helper the branch calls."""
    monkeypatch.setattr(auth_service, "decode_token", lambda *a, **k: None)
    monkeypatch.setattr(auth_service, "hash_token", lambda _s: "h")

    calls = {"issued": False, "issued_user": None, "revoked": False, "revoked_app": "UNSET"}

    async def fake_issue(user, app_client_id, db):
        calls["issued"] = True
        calls["issued_user"] = user
        return "TOKENS"

    async def fake_revoke(user_id, db, app_client_id=None):
        calls["revoked"] = True
        calls["revoked_app"] = app_client_id

    monkeypatch.setattr(auth_service, "_issue_tokens", fake_issue)
    monkeypatch.setattr(auth_service, "_revoke_all_user_tokens", fake_revoke)
    return calls


async def _refresh(stored):
    return await auth_service.refresh_access_token("tok", _FakeDB(stored))


# ---- happy path -------------------------------------------------------------------------


async def test_normal_rotation_tags_rotated_at(patched):
    stored = _stored(is_revoked=False, rotated_at=None)
    result = await _refresh(stored)
    assert result == "TOKENS"
    assert patched["issued"] is True and patched["revoked"] is False
    assert stored.is_revoked is True
    assert stored.rotated_at is not None and stored.revoked_at is not None


# ---- grace window -----------------------------------------------------------------------


async def test_within_grace_unconsumed_reissues_successor(patched):
    """(1) Lost-response retry: revoked-by-rotation, fresh, unconsumed -> one successor, no nuke."""
    stored = _stored(is_revoked=True, rotated_at=datetime.now(UTC) - timedelta(seconds=1))
    result = await _refresh(stored)
    assert result == "TOKENS"
    assert patched["issued"] is True and patched["revoked"] is False
    assert stored.grace_consumed is True  # gate flipped so a second replay can't reuse it


async def test_already_consumed_replay_revokes_all(patched):
    """(2) Second replay of the same token (gate already flipped) -> 401 + revoke-all."""
    stored = _stored(is_revoked=True, rotated_at=datetime.now(UTC) - timedelta(seconds=1), grace_consumed=True)
    with pytest.raises(HTTPException) as exc:
        await _refresh(stored)
    assert exc.value.status_code == 401
    assert patched["revoked"] is True and patched["issued"] is False


async def test_beyond_grace_window_revokes_all(patched, monkeypatch):
    """(4) Replay long after rotation -> indistinguishable from theft -> 401 + revoke-all."""
    monkeypatch.setattr(auth_service.settings, "refresh_reuse_grace_seconds", 5)
    stored = _stored(is_revoked=True, rotated_at=datetime.now(UTC) - timedelta(seconds=10))
    with pytest.raises(HTTPException) as exc:
        await _refresh(stored)
    assert exc.value.status_code == 401
    assert patched["revoked"] is True and patched["issued"] is False


async def test_unknown_token_401_without_revoke_all(patched):
    """(5) Forged/unknown hash -> hard 401 but NOT revoke-all (no user to punish)."""
    with pytest.raises(HTTPException) as exc:
        await _refresh(None)
    assert exc.value.status_code == 401
    assert patched["revoked"] is False and patched["issued"] is False


async def test_logout_revoked_token_not_graced(patched):
    """(6) Token killed by /logout (rotated_at NULL) is never whitelisted -> 401 + revoke-all."""
    stored = _stored(is_revoked=True, rotated_at=None)
    with pytest.raises(HTTPException) as exc:
        await _refresh(stored)
    assert exc.value.status_code == 401
    assert patched["revoked"] is True and patched["issued"] is False


async def test_grace_disabled_revokes_all(patched, monkeypatch):
    """(8) Rollback switch: grace=0 reverts to the original revoke-all even inside the window."""
    monkeypatch.setattr(auth_service.settings, "refresh_reuse_grace_seconds", 0)
    stored = _stored(is_revoked=True, rotated_at=datetime.now(UTC) - timedelta(seconds=1))
    with pytest.raises(HTTPException) as exc:
        await _refresh(stored)
    assert exc.value.status_code == 401
    assert patched["revoked"] is True and patched["issued"] is False


async def test_inactive_account_within_grace_not_graced(patched):
    """(9) Disabled account inside the window: not whitelisted -> revoke-all (accepted LOW: the
    semantics differ from the live path's 403, which is fine -- the account is dead either way)."""
    stored = _stored(is_revoked=True, rotated_at=datetime.now(UTC) - timedelta(seconds=1), is_active=False)
    with pytest.raises(HTTPException) as exc:
        await _refresh(stored)
    assert exc.value.status_code == 401
    assert patched["revoked"] is True and patched["issued"] is False


# ---- M3: SLO logout marker must veto a grace re-issue -----------------------------------


async def test_logout_marker_after_rotation_blocks_grace(patched):
    """(7) User logged out (marker) AFTER this token was rotated: a fresh successor would have
    iat > marker and silently outlive the logout, so grace is vetoed -> 401 + revoke-all."""
    stored = _stored(is_revoked=True, rotated_at=datetime.now(UTC) - timedelta(seconds=1))
    await revocation.revoke_user_access_tokens(str(stored.user_id), at_epoch=datetime.now(UTC).timestamp(), ttl=900)
    with pytest.raises(HTTPException) as exc:
        await _refresh(stored)
    assert exc.value.status_code == 401
    assert patched["revoked"] is True and patched["issued"] is False


async def test_logout_marker_before_rotation_still_graced(patched):
    """A logout marker from an EARLIER session (predating this token's rotation) does not apply
    to this chain, so a lost-response replay is still graced."""
    rotated_at = datetime.now(UTC) - timedelta(seconds=1)
    stored = _stored(is_revoked=True, rotated_at=rotated_at)
    await revocation.revoke_user_access_tokens(str(stored.user_id), at_epoch=rotated_at.timestamp() - 100, ttl=900)
    result = await _refresh(stored)
    assert result == "TOKENS"
    assert patched["issued"] is True and patched["revoked"] is False


async def test_marker_check_fails_open_to_grace(patched, monkeypatch):
    """A shared-Redis blip on the marker lookup must not break the lost-response retry path:
    fail open (treat as no logout) and still grace, matching the resource-server denylist."""

    async def boom(_user_id):
        raise ConnectionError("redis down")

    monkeypatch.setattr(auth_service, "get_user_revoked_at", boom)
    stored = _stored(is_revoked=True, rotated_at=datetime.now(UTC) - timedelta(seconds=1))
    result = await _refresh(stored)
    assert result == "TOKENS"
    assert patched["issued"] is True and patched["revoked"] is False


# ---- per-app revoke scope (cross-app collateral fix) ------------------------------------


async def test_reuse_revoke_scoped_to_offending_app(patched):
    """Reuse detected on app_x's token revokes the user's tokens ONLY for app_x. Other apps'
    independent rotation lineages must survive, or one app's lost-rotation replay logs the user
    out everywhere (observed live: an audio replay collaterally revoked a valid fusion token)."""
    stored = _stored(is_revoked=True, rotated_at=None)  # /logout-style kill -> straight to revoke
    with pytest.raises(HTTPException) as exc:
        await _refresh(stored)
    assert exc.value.status_code == 401
    assert patched["revoked"] is True
    assert patched["revoked_app"] == "app_x"  # scoped, not the account-wide None


class _CapturingDB:
    """Captures the SELECT statement and yields preset tokens so we can assert the WHERE scope
    of ``_revoke_all_user_tokens`` itself (no real DB; we inspect the compiled whereclause)."""

    def __init__(self, tokens):
        self._tokens = tokens
        self.stmt = None
        self.committed = False

    async def execute(self, stmt, *_a, **_k):
        self.stmt = stmt
        return SimpleNamespace(scalars=lambda: list(self._tokens))

    async def commit(self):
        self.committed = True


def _revocable():
    return SimpleNamespace(is_revoked=False, revoked_at=None)


async def test_revoke_with_app_client_id_filters_by_app():
    tokens = [_revocable(), _revocable()]
    db = _CapturingDB(tokens)
    await auth_service._revoke_all_user_tokens(uuid.uuid4(), db, app_client_id="app_x")
    assert "app_client_id" in str(db.stmt.whereclause)  # WHERE-only -> the app filter is present
    assert all(t.is_revoked for t in tokens) and db.committed


async def test_revoke_without_app_client_id_is_account_wide():
    tokens = [_revocable()]
    db = _CapturingDB(tokens)
    await auth_service._revoke_all_user_tokens(uuid.uuid4(), db)  # /logout path -> sweep every app
    assert "app_client_id" not in str(db.stmt.whereclause)  # no per-app narrowing
    assert tokens[0].is_revoked is True and db.committed
