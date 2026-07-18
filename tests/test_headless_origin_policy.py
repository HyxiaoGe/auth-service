import pytest

from app.utils.origin import schemeful_web_origin_same_site


@pytest.mark.parametrize(
    ("auth_base_url", "origin", "expected"),
    [
        ("https://authmail.seanfield.org", "https://dev.seanfield.org", True),
        ("https://auth.example.com", "https://app.other.com", False),
        ("https://auth.example.co.uk", "https://app.example.co.uk", True),
        ("https://tenant-a.github.io", "https://tenant-b.github.io", False),
        ("https://auth.seanfield.org", "http://dev.seanfield.org", False),
        ("http://localhost:8100", "http://localhost:3000", True),
        ("http://localhost:8100", "http://127.0.0.1:3000", False),
        ("http://127.0.0.1:8100", "http://127.0.0.1:3000", True),
        ("http://127.0.0.1:8100", "http://127.0.0.2:3000", False),
        ("https://192.0.2.10", "https://192.0.2.10:8443", True),
        ("https://192.0.2.10", "https://192.0.2.11", False),
        ("https://auth.example.com", "https://example.com.evil.test", False),
        ("https://auth.example.com", "https://app.example.com/path", False),
        ("https://auth.example.com", "app://-", False),
        ("https://auth.example.com", "null", False),
        ("https://auth.example.com", None, False),
        ("http://auth.seanfield.org", "http://app.seanfield.org", False),
    ],
)
def test_schemeful_web_origin_same_site(auth_base_url, origin, expected):
    assert schemeful_web_origin_same_site(auth_base_url, origin) is expected
