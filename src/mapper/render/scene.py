"""Format-neutral presentation shared by every diagram renderer.

Everything here is free of diagram syntax: the label text, the colour palette,
and the node-id sets that decide what a diagram is allowed to reference.

``mermaid.py`` and ``d2.py`` both build on these, so a label that says
"Type: PUBLIC - 0.0.0.0/0 -> Internet Gateway" cannot drift into a different
wording in one format than the other. Only the syntax that wraps these strings
is per-renderer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set

from . import kinds
from .. import model as M
from ..graph import connectivity as flow
from ..graph import Topology


@dataclass(frozen=True)
class Style:
    """One palette row, in a form no diagram language owns.

    A renderer turns this into its own syntax: Mermaid walks it into a
    comma-joined ``classDef`` string, D2 into a ``style`` block.
    """

    fill: str = ""
    stroke: str = ""
    text: str = ""
    dashed: bool = False


# One row per classification, in a stable order that renderers preserve so their
# style blocks always come out in the same sequence.
PALETTE: Dict[str, Style] = {
    "internet": Style("#dbeafe", "#1d4ed8", "#0f172a"),
    "igw": Style("#bfdbfe", "#1d4ed8", "#0f172a"),
    "nat": Style("#cffafe", "#0e7490", "#0f172a"),
    "tgw": Style("#ede9fe", "#6d28d9", "#1e1b4b"),
    "peering": Style("#f5d0fe", "#a21caf", "#3b0764"),
    "vgw": Style("#e0e7ff", "#4338ca", "#1e1b4b"),
    "endpoint": Style("#ccfbf1", "#0f766e", "#042f2e"),
    "public": Style("#fed7aa", "#c2410c", "#431407"),
    "private": Style("#e2e8f0", "#475569", "#0f172a"),
    "data": Style("#dcfce7", "#15803d", "#052e16"),
    "rtb": Style("#f1f5f9", "#64748b", "#0f172a", dashed=True),
    "onprem": Style("#e7e5e4", "#57534e", "#1c1917"),
    "blocked": Style("#fee2e2", "#b91c1c", "#450a0a"),
    "warn": Style(dashed=True),
    "component": Style("#e2e8f0", "#334155", "#0f172a"),
}


# Subnet draw order within an availability zone: public, then private, then
# isolated. Shared so both renderers order a VPC the same way.
CLASS_ORDER = {"public": 0, "private": 1, "isolated": 2}

# Hard ceiling on subnets drawn per VPC, independent of --max-diagram-subnets.
MAX_TOPOLOGY_SUBNETS = 400


def trunc(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def service_short(service_name: str) -> str:
    """``com.amazonaws.eu-west-1.ecr.api`` -> ``ecr.api`` (not just ``api``)."""
    parts = [p for p in service_name.split(".") if p]
    while parts and parts[0] in ("com", "amazonaws") or (
        parts
        and parts[0].startswith(
            ("aws-", "us-", "eu-", "ap-", "sa-", "ca-", "me-", "af-", "il-")
        )
    ):
        parts.pop(0)
    return ".".join(parts[-2:]) or service_name


def nacl_counts(nacl: M.Nacl) -> str:
    inbound = sum(1 for e in nacl.entries if not e.egress)
    outbound = len(nacl.entries) - inbound
    return f"{inbound} in / {outbound} out"


def classification_reason(info) -> str:
    """One line: how this subnet was classified, and the route that proves it."""
    if info.default_route is None:
        return "Type: ISOLATED \u2014 no 0.0.0.0/0 route in its route table"
    kind = flow.target_kind(info.default_route)
    phrase = flow.TARGET_PHRASE.get(kind, kind)
    return f"Type: {info.classification.upper()} \u2014 0.0.0.0/0 \u2192 {phrase}"


def short_id(raw: str) -> str:
    """Abbreviate a long AWS identifier. Full value stays in the report."""
    text = raw or ""
    if text.startswith("arn:"):
        tail = text.rsplit(":", 1)[-1]
        parts = [seg for seg in tail.split("/") if seg]
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[-1]}"
        return tail or text
    return text


def short_sg_list(sg_ids: List[str]) -> str:
    """Security group ids, abbreviated. Full ids live in the report."""
    out = []
    for sg in sg_ids[:2]:
        out.append(sg if len(sg) <= 24 else sg[:20] + "..")
    extra = f" (+{len(sg_ids) - 2})" if len(sg_ids) > 2 else ""
    return ", ".join(out) + extra


def workload_title(wl: M.Workload) -> str:
    return f"{kinds.style_for(wl.kind).title(wl)} {wl.name or short_id(wl.id)}"


def known_node_ids(topo: Topology) -> Set[str]:
    """Every node id the topology could legitimately produce, drawn or not."""
    ids: Set[str] = {flow.internet_node(), flow.onprem_node()}
    ids.update(flow.sid(s.id) for s in topo.subnets.values())
    ids.update(flow.wid(w.id) for w in topo.workloads.values())
    for kind, coll in (
        ("igw", topo.igws), ("nat", topo.nat_gateways), ("tgw", topo.tgws),
        ("pcx", topo.peerings), ("vpce", topo.endpoints), ("vgw", topo.vpn_gateways),
    ):
        ids.update(flow.nid(kind, r.id) for r in coll.values())
    ids.update(flow.nid("eni", e.id) for e in topo.enis.values())
    return ids


def component_node_ids(topo: Topology) -> Set[str]:
    """Node ids for network-path components that must never be omitted.

    Section 14: when a diagram is over budget we shed subnet headers and
    workload detail, never the gateways and NAT devices that a route arrow
    points at. Hiding those would turn "this path exists" into "I could not
    draw this path", which is a very different claim.
    """
    ids: Set[str] = set()
    for kind, coll in (
        ("igw", topo.igws), ("nat", topo.nat_gateways), ("tgw", topo.tgws),
        ("pcx", topo.peerings), ("vpce", topo.endpoints), ("vgw", topo.vpn_gateways),
    ):
        ids.update(flow.nid(kind, r.id) for r in coll.values())
    ids.add(flow.internet_node())
    ids.add(flow.onprem_node())
    return ids
