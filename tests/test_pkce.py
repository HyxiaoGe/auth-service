"""PKCE (RFC 7636) S256 verification: BASE64URL(SHA256(code_verifier)) == code_challenge.

Public clients (our SPAs) hold no client_secret, so an intercepted auth code must be
useless without the matching code_verifier. These tests pin the S256 transform against
the canonical RFC 7636 Appendix B test vector plus the obvious negative cases.
"""

from app.services import oauth_service


def test_verify_pkce_accepts_rfc7636_test_vector():
    # RFC 7636 Appendix B canonical pair.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert oauth_service.verify_pkce(verifier, challenge) is True


def test_verify_pkce_rejects_wrong_verifier():
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert oauth_service.verify_pkce("not-the-right-verifier", challenge) is False


def test_verify_pkce_rejects_empty_verifier():
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert oauth_service.verify_pkce("", challenge) is False


def test_verify_pkce_no_base64_padding_in_challenge():
    # The S256 transform must emit base64url *without* '=' padding (RFC 7636 §4.2).
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    # A padded variant must NOT be accepted as equivalent.
    assert oauth_service.verify_pkce(verifier, challenge + "=") is False
