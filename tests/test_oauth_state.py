"""oauth_state carries the /authorize context across the social-login round-trip.

Design deviation (documented): rather than a second `authorize_state:` namespace, the
app's CSRF `state` rides as a passenger field (`app_state`) inside the existing
`oauth_state:` payload. It is NEVER a Redis key and is NEVER sent to Google -- only the
random oauth_state value is -- so the two states are not conflated (red-team #4). The
legacy direct flow stores exactly {client_id, redirect_uri} as before (zero-breakage).
"""

from app.services import oauth_service

CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


async def test_legacy_state_payload_is_unchanged():
    state = await oauth_service.create_oauth_state("appA", "https://app/cb")
    data = await oauth_service.verify_and_consume_state(state)
    assert data == {"client_id": "appA", "redirect_uri": "https://app/cb"}  # no extra keys


async def test_authorize_context_is_carried_and_recovered():
    state = await oauth_service.create_oauth_state(
        "appA",
        "https://app/cb",
        app_state="S1",
        prompt="login",
        provider="google",
        response_type="code",
        code_challenge=CHALLENGE,
        code_challenge_method="S256",
    )
    data = await oauth_service.verify_and_consume_state(state)
    assert data["app_state"] == "S1"
    assert data["code_challenge"] == CHALLENGE
    assert data["code_challenge_method"] == "S256"
    assert data["prompt"] == "login"
    assert data["provider"] == "google"


async def test_none_context_fields_are_not_stored():
    # Passing app_state but no challenge should not inject a None code_challenge key.
    state = await oauth_service.create_oauth_state("appA", "https://app/cb", app_state="S1")
    data = await oauth_service.verify_and_consume_state(state)
    assert data["app_state"] == "S1"
    assert "code_challenge" not in data


# ==================== State-loss recovery (durable routing copy) ====================
# The main oauth_state is single-use (getdel) + short TTL; its loss takes client_id/
# redirect_uri with it, leaving the callback no app to return the user to. A second,
# read-only, longer-lived copy carries ONLY the routing (client_id + redirect_uri) so a
# lost/duplicate/slow callback can still bounce back instead of dead-ending. The recovery
# copy is non-secret (both fields are public) and is only ever used to emit an error
# redirect to an already-registered uri.


async def test_recover_state_routing_returns_routing_after_create():
    state = await oauth_service.create_oauth_state("appA", "https://app/cb", app_state="S1")
    routing = await oauth_service.recover_state_routing(state)
    assert routing == {"client_id": "appA", "redirect_uri": "https://app/cb"}


async def test_recover_state_routing_unknown_returns_none():
    # A forged/garbage state has no recovery copy -> unrecoverable (branded page stays the
    # last resort). The recovery copy's mere existence is the "we minted this" proof.
    assert await oauth_service.recover_state_routing("does-not-exist") is None


async def test_recovery_copy_survives_main_state_consume():
    # The durable recovery copy must OUTLIVE the single-use main state: after the main
    # getdel consumes the state, routing is still recoverable -- this is what lets a
    # duplicate/slow callback bounce the user back rather than hit a dead end.
    state = await oauth_service.create_oauth_state("appA", "https://app/cb")
    await oauth_service.verify_and_consume_state(state)  # consumes the single-use main key
    routing = await oauth_service.recover_state_routing(state)
    assert routing == {"client_id": "appA", "redirect_uri": "https://app/cb"}
