"""Trusted-proxy-aware client IP resolution."""

from ipaddress import ip_address, ip_network

from app.core.config import get_settings


def normalize_ip(value: str) -> str:
    address = ip_address(value.strip().split("%", 1)[0])
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def resolve_client_ip(peer: str | None, forwarded_for: str | None) -> str:
    if not peer:
        return "unknown"
    try:
        normalized_peer = normalize_ip(peer)
        peer_address = ip_address(normalized_peer)
        trusted = [ip_network(value, strict=False) for value in get_settings().TRUSTED_PROXY_CIDRS]
    except ValueError:
        return "unknown"
    if not forwarded_for or not any(peer_address in network for network in trusted):
        return normalized_peer

    chain: list[str] = []
    try:
        chain = [normalize_ip(value) for value in forwarded_for.split(",")]
    except ValueError:
        return normalized_peer
    chain.append(normalized_peer)
    for value in reversed(chain):
        address = ip_address(value)
        if not any(address in network for network in trusted):
            return value
    return chain[0]
