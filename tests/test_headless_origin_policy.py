from ipaddress import ip_network

import pytest

from app.utils.origin import (
    auth_browser_alias_origin_matches,
    auth_frontchannel_origin_matches,
    schemeful_web_origin_same_site,
    trusted_auth_frontchannel_origin,
    trusted_auth_request_origin,
)


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


def test_trusted_auth_frontchannel_accepts_canonical_and_exact_loopback_alias():
    aliases = ["http://localhost:8100"]

    assert (
        trusted_auth_frontchannel_origin(
            "https://auth.example.com/auth/session/resume",
            "https://auth.example.com",
            aliases,
        )
        == "https://auth.example.com"
    )
    assert (
        trusted_auth_frontchannel_origin(
            "http://localhost:8100/auth/session/resume",
            "https://auth.example.com",
            aliases,
        )
        == "http://localhost:8100"
    )


@pytest.mark.parametrize(
    "request_url",
    [
        "http://127.0.0.1:8100/auth/session/resume",
        "http://localhost:8101/auth/session/resume",
        "https://auth.example.com.evil.test/auth/session/resume",
    ],
)
def test_trusted_auth_frontchannel_rejects_unconfigured_request_origin(request_url):
    assert (
        trusted_auth_frontchannel_origin(
            request_url,
            "https://auth.example.com",
            ["http://localhost:8100"],
        )
        is None
    )


def test_browser_alias_match_never_treats_canonical_auth_as_alias():
    aliases = ["http://localhost:8100"]

    assert auth_browser_alias_origin_matches("http://localhost:8100", aliases)
    assert not auth_browser_alias_origin_matches("https://auth.example.com", aliases)
    assert not auth_browser_alias_origin_matches("http://localhost:8101", aliases)


def test_auth_frontchannel_alias_only_accepts_same_site_rp_origin():
    aliases = ["http://localhost:8100"]

    assert auth_frontchannel_origin_matches(
        "http://localhost:8100/auth/session/resume",
        "https://auth.example.com",
        aliases,
        "http://localhost:3000",
    )
    assert not auth_frontchannel_origin_matches(
        "http://localhost:8100/auth/session/resume",
        "https://auth.example.com",
        aliases,
        "http://127.0.0.1:3000",
    )


def test_trusted_proxy_can_restore_public_https_auth_origin():
    assert (
        trusted_auth_request_origin(
            "http://auth.example.com/auth/oauth/token",
            "https://auth.example.com",
            [],
            peer_host="172.25.0.10",
            trusted_proxy_networks=(ip_network("172.25.0.0/24"),),
            forwarded_proto="https",
            forwarded_host=None,
        )
        == "https://auth.example.com"
    )


@pytest.mark.parametrize(
    ("peer_host", "forwarded_proto", "forwarded_host"),
    [
        ("198.51.100.8", "https", None),
        ("172.25.0.10", "https,http", None),
        ("172.25.0.10", "javascript", None),
        ("172.25.0.10", "https", "evil.example"),
    ],
)
def test_forwarded_auth_origin_fails_closed_outside_trusted_exact_proxy_context(
    peer_host,
    forwarded_proto,
    forwarded_host,
):
    assert (
        trusted_auth_request_origin(
            "http://auth.example.com/auth/oauth/token",
            "https://auth.example.com",
            [],
            peer_host=peer_host,
            trusted_proxy_networks=(ip_network("172.25.0.0/24"),),
            forwarded_proto=forwarded_proto,
            forwarded_host=forwarded_host,
        )
        is None
    )
