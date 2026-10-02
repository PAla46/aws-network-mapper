"""CIDR / IP helpers built on the stdlib ``ipaddress`` module."""

from __future__ import annotations

import ipaddress
from typing import Iterable, Optional, Tuple


def parse_net(value: Optional[str]):
    """Parse a CIDR into an ``_BaseNetwork``/``_BaseAddress`` or None."""
    if not value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def parse_ip(value: Optional[str]):
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def to_cidr(value: Optional[str]) -> str:
    return str(value) if value else ""


def prefix_len(net) -> int:
    return int(net.prefixlen)


def is_default_route(cidr: str) -> bool:
    net = parse_net(cidr)
    return net is not None and net.prefixlen == 0


def version_of(value: Optional[str]) -> int:
    net = parse_net(value)
    return net.version if net is not None else 0


def ip_in_net(ip: str, cidr: str) -> bool:
    addr = parse_ip(ip)
    net = parse_net(cidr)
    if addr is None or net is None or addr.version != net.version:
        return False
    return addr in net


def nets_overlap(a: str, b: str) -> bool:
    na, nb = parse_net(a), parse_net(b)
    if na is None or nb is None or na.version != nb.version:
        return False
    return na.overlaps(nb)


def cidr_contains(outer: str, inner: str) -> bool:
    no, ni = parse_net(outer), parse_net(inner)
    if no is None or ni is None or no.version != ni.version:
        return False
    return ni.subnet_of(no)


def longest_prefix_match(
    candidates: Iterable[str], ip: str, fallback: Optional[str] = None
) -> Optional[str]:
    """Return the most specific CIDR from *candidates* that contains *ip*.

    Falls back to *fallback* (used for ``0.0.0.0/0`` / ``::/0``) when nothing
    matches. Ties are broken by lexical order so results are deterministic.
    """
    addr = parse_ip(ip)
    if addr is None:
        return None
    best = None
    best_key: Tuple[int, str] = (-1, "")
    for cand in candidates:
        net = parse_net(cand)
        if net is None or net.version != addr.version:
            continue
        if addr in net:
            key = (net.prefixlen, str(net))
            if key > best_key:
                best_key = key
                best = str(net)
    if best is not None:
        return best
    if fallback:
        return fallback
    # default routes for the address family
    default = "0.0.0.0/0" if addr.version == 4 else "::/0"
    return default if fallback is None else None


def summarize(cidrs: Iterable[str], limit: int = 4) -> str:
    """Compact human summary of a set of CIDRs, collapsing an IPv4 /16+ set."""
    uniq = sorted({c for c in cidrs if c})
    if not uniq:
        return "-"
    if len(uniq) > limit:
        return f"{', '.join(uniq[:limit])} (+{len(uniq) - limit} more)"
    return ", ".join(uniq)


def sort_key(cidr: str) -> Tuple[int, int, str]:
    net = parse_net(cidr)
    if net is None:
        return (9, 0, cidr)
    return (net.version, -net.prefixlen, str(net))
