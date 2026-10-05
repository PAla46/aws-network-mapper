"""Shared helpers with no AWS or model dependencies.

Pure functions over IPs and CIDRs. Nothing here knows what a VPC is, which keeps
it cheap to test and safe to import from anywhere.
"""

from .cidr import (  # noqa: F401
    cidr_contains,
    ip_in_net,
    is_default_route,
    longest_prefix_match,
    nets_overlap,
    parse_ip,
    parse_net,
    prefix_len,
    sort_key,
    summarize,
    to_cidr,
    version_of,
)

__all__ = [
    "cidr_contains",
    "ip_in_net",
    "is_default_route",
    "longest_prefix_match",
    "nets_overlap",
    "parse_ip",
    "parse_net",
    "prefix_len",
    "sort_key",
    "summarize",
    "to_cidr",
    "version_of",
]
