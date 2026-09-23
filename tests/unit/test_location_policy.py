from types import SimpleNamespace

import pytest

from app.core import client_ip
from app.services import location_policy_service


def test_untrusted_peer_cannot_spoof_forwarded_address(monkeypatch):
    monkeypatch.setattr(
        client_ip, "get_settings", lambda: SimpleNamespace(TRUSTED_PROXY_CIDRS=["10.0.0.0/8"])
    )
    assert client_ip.resolve_client_ip("198.51.100.7", "203.0.113.9") == "198.51.100.7"


def test_trusted_proxy_chain_selects_first_untrusted_hop(monkeypatch):
    monkeypatch.setattr(
        client_ip, "get_settings", lambda: SimpleNamespace(TRUSTED_PROXY_CIDRS=["10.0.0.0/8"])
    )
    assert client_ip.resolve_client_ip(
        "10.0.0.4", "203.0.113.9, 10.0.0.3"
    ) == "203.0.113.9"


def test_ipv4_mapped_ipv6_is_normalized():
    assert client_ip.normalize_ip("::ffff:192.0.2.1") == "192.0.2.1"


def test_cidr_and_country_all_mode(monkeypatch):
    monkeypatch.setattr(location_policy_service, "country_for_ip", lambda _ip: "IN")
    assert location_policy_service.evaluate(
        "203.0.113.10", ["203.0.113.0/24"], ["IN"], "all", True
    ) == (True, "IN", None)
    allowed, country, reason = location_policy_service.evaluate(
        "198.51.100.10", ["203.0.113.0/24"], ["IN"], "all", True
    )
    assert (allowed, country, reason) == (False, "IN", "LOCATION_NOT_ALLOWED")


def test_country_lookup_fails_closed(monkeypatch):
    monkeypatch.setattr(location_policy_service, "country_for_ip", lambda _ip: None)
    assert location_policy_service.evaluate(
        "203.0.113.10", [], ["IN"], "all", True
    ) == (False, None, "GEOIP_LOOKUP_FAILED")
