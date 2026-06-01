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
