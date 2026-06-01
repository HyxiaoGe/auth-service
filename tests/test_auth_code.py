"""mint_auth_code(): the one place that creates a one-time auth code.

Shared by the social callbacks and /authorize's silent path. When a code_challenge is
given it is bound into the code payload, which is what later makes /token's conditional
PKCE gate require a matching verifier. Without a challenge the payload omits the key, so
legacy codes stay exactly as before.
"""

from app.services import oauth_service
from app.utils.redis import consume_auth_code

CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


async def test_mint_auth_code_payload_shape():
    code = await oauth_service.mint_auth_code(
        user_id="u1", client_id="appA", redirect_uri="https://app/cb", provider="google"
    )
    data = await consume_auth_code(code)
    assert data == {
        "user_id": "u1",
        "app_client_id": "appA",
        "redirect_uri": "https://app/cb",
        "provider": "google",
    }


async def test_mint_auth_code_binds_challenge_when_given():
    code = await oauth_service.mint_auth_code(
        user_id="u1",
        client_id="appA",
        redirect_uri="https://app/cb",
        provider="google",
        code_challenge=CHALLENGE,
    )
    data = await consume_auth_code(code)
    assert data["code_challenge"] == CHALLENGE


async def test_mint_auth_code_is_single_use():
    code = await oauth_service.mint_auth_code(
        user_id="u1", client_id="appA", redirect_uri="https://app/cb", provider="google"
    )
    assert await consume_auth_code(code) is not None
    assert await consume_auth_code(code) is None  # consumed
