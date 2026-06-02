"""_client_ip is attacker-controlled (X-Forwarded-For) and feeds straight into log lines.

Two hazards the helper must defend against, since it is the source of the ``client_ip=``
field in every oauth_state.* record:
  1. Log injection -- a forged newline in XFF would otherwise split one log record into
     two, letting a caller fabricate entries. The returned value must be a single line.
  2. Empty diagnostics -- a whitespace-only XFF must fall back to the direct peer instead
     of yielding ``client_ip=`` with nothing after it (defeats the instrumentation).
"""

from starlette.requests import Request

from app.routers import oauth


def _req(xff: str | None = None, peer: str = "10.0.0.9") -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return Request({"type": "http", "headers": headers, "client": (peer, 0)})


def test_client_ip_strips_newline_to_prevent_log_injection():
    # A forged newline + fake record must not survive into the logged value.
    ip = oauth._client_ip(_req(xff="203.0.113.7\n2026-01-01 CRITICAL forged admin login"))
    assert ip == "203.0.113.7"
    assert "\n" not in ip
    assert "CRITICAL" not in ip


def test_client_ip_whitespace_only_xff_falls_back_to_peer():
    # "   " is truthy but strips to empty -> must fall back to the direct peer, not "".
    assert oauth._client_ip(_req(xff="   ")) == "10.0.0.9"


def test_client_ip_first_hop_preserved_for_normal_xff():
    # Regression guard: the ordinary multi-hop case still returns the first hop verbatim.
    assert oauth._client_ip(_req(xff="203.0.113.7, 10.0.0.1")) == "203.0.113.7"


def test_client_ip_no_xff_uses_peer():
    assert oauth._client_ip(_req(xff=None, peer="198.51.100.22")) == "198.51.100.22"
