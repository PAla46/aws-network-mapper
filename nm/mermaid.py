"""Mermaid ``flowchart`` rendering.

Every diagram is built through :class:`MermaidBuilder`, which guarantees valid
node ids and escapes labels, so generated files always parse.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import model as M
from .cidrutil import is_default_route
from .model import RouteTable, Subnet, Workload
from .topology import Topology

ESCAPES = {
    '"': "#quot;",
    "#": "#35;",
    "&": "#amp;",
    "<": "#lt;",
    ">": "#gt;",
    "|": "#124;",
    "`": "#96;",
    "\\": "#92;",
    "{": "#123;",
    "}": "#125;",
    ";": "#59;",
}

CLASSES = {
    "internet": ("fill:#dbeafe,stroke:#1d4ed8,color:#0f172a",),
    "igw": ("fill:#bfdbfe,stroke:#1d4ed8,color:#0f172a",),
    "nat": ("fill:#cffafe,stroke:#0e7490,color:#0f172a",),
    "tgw": ("fill:#ede9fe,stroke:#6d28d9,color:#1e1b4b",),
    "peering": ("fill:#f5d0fe,stroke:#a21caf,color:#3b0764",),
    "endpoint": ("fill:#ccfbf1,stroke:#0f766e,color:#042f2e",),
    "public": ("fill:#fed7aa,stroke:#c2410c,color:#431407",),
    "private": ("fill:#e2e8f0,stroke:#475569,color:#0f172a",),
    "data": ("fill:#dcfce7,stroke:#15803d,color:#052e16",),
    "rtb": ("fill:#f1f5f9,stroke:#64748b,color:#0f172a,stroke-dasharray:4 3",),
    "onprem": ("fill:#e7e5e4,stroke:#57534e,color:#1c1917",),
    "blocked": ("fill:#fee2e2,stroke:#b91c1c,color:#450a0a",),
    "warn": ("stroke-dasharray:4 3",),
}

SLUG_RE = re.compile(r"[^a-z0-9]+")


def slug(text: str, limit: int = 40) -> str:
    out = SLUG_RE.sub("-", (text or "").lower()).strip("-")
    return (out or "x")[:limit].strip("-")


ESCAPE_RE = re.compile("[" + re.escape("".join(ESCAPES)) + "]")


# Mermaid link tokens, from the flowchart link table. A bare "->" or "-.-" is NOT
# valid: the lexer splits them and reports "got 'MINUS'".
VALID_LINK_STYLES = frozenset({"-->", "---", "-.->", "==>", "===", "<-.->", "<-->", "<==>"})


def esc(text: object) -> str:
    """Escape a label in a single pass (never escape our own escapes).

    Newlines become <br/> so multi-line labels keep their structure.
    """
    raw = str(text if text is not None else "").replace("\r", "")
    lines = [
        ESCAPE_RE.sub(lambda m: ESCAPES[m.group()], part).strip()
        for part in raw.split("\n")
    ]
    return "<br/>".join(l for l in lines if l) or " "


def trunc(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


class MermaidBuilder:
    def __init__(self, title: str = "", direction: str = "TB"):
        self.title = title
        self.direction = direction
        self._lines: List[str] = []
        self._ids: Dict[str, str] = {}
        self._counter = 0
        self._used_classes: Set[str] = set()
        self._defined: Set[str] = set()
        self._edges: Set[str] = set()
        self._class_of: Dict[str, str] = {}

    # -- nodes -----------------------------------------------------------
    def nid(self, key: str) -> str:
        if key not in self._ids:
            self._counter += 1
            self._ids[key] = f"n{self._counter}"
        return self._ids[key]

    def node(
        self,
        key: str,
        label: str,
        shape: str = "box",
        cls: Optional[str] = None,
        label_limit: int = 60,
    ) -> str:
        nid = self.nid(key)
        text = esc(trunc(label, label_limit))
        rendered = {
            "box": f'{nid}["{text}"]',
            "round": f'{nid}("{text}")',
            "stadium": f'{nid}(["{text}"])',
            "diamond": f'{nid}{{"{text}"}}',
            "subroutine": f'{nid}[["{text}"]]',
            "hex": f'{nid}{{{{"{text}"}}}}',
        }.get(shape, f'{nid}["{text}"]')
        if nid not in self._defined:
            self._lines.append(rendered)
            self._defined.add(nid)
        if cls and self._class_of.get(nid) != cls:
            self._lines.append(f"  class {nid} {cls};")
            self._used_classes.add(cls)
            self._class_of[nid] = cls
        return nid

    def edge(
        self,
        src: str,
        dst: str,
        label: str = "",
        style: str = "-->",
        label_limit: int = 40,
    ) -> None:
        if style not in VALID_LINK_STYLES:
            raise ValueError(
                f"invalid mermaid link style {style!r}; expected one of {sorted(VALID_LINK_STYLES)}"
            )
        a, b = self.nid(src), self.nid(dst)
        body = f"  {a} {style}|{esc(trunc(label, label_limit))}| {b}" if label else f"  {a} {style} {b}"
        if body in self._edges:
            return
        self._edges.add(body)
        self._lines.append(body)

    def link_nodes(self, src_key: str, dst_key: str, **kwargs) -> None:
        self.edge(src_key, dst_key, **kwargs)

    # -- subgraphs -------------------------------------------------------
    @contextmanager
    def subgraph(self, key: str, label: str):
        sid = f"sg{abs(hash(key)) % 100000}"
        self._lines.append(f'subgraph {sid}["{esc(label)}"]')
        self._lines.append("  direction " + self.direction)
        try:
            yield sid
        finally:
            self._lines.append("end")

    def free(self, line: str) -> None:
        self._lines.append(line)

    def legend(self, pairs: Sequence[Tuple[str, str]]) -> None:
        self._lines.append("  %% legend: " + "; ".join(f"{k} = {v}" for k, v in pairs))

    # -- render ----------------------------------------------------------
    def render(self) -> str:
        out = [f"flowchart {self.direction}"]
        if self.title:
            out.append(f"%% {self.title}")
        out.extend(self._lines)
        for name, styles in CLASSES.items():
            if name in self._used_classes:
                out.append(f"  classDef {name} {styles[0]};")
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# subnets / workloads
# --------------------------------------------------------------------------- #


def subnet_tier(subnet: Subnet, rtb: Optional[RouteTable]) -> str:
    name = (subnet.name or "").lower()
    if any(h in name for h in ("public", "dmz", "edge", "nat", "bastion", "elb")):
        return "public"
    if any(h in name for h in ("db", "data", "rds", "aurora")):
        return "data"
    return "private"


def subnet_class(subnet: Subnet, rtb: Optional[RouteTable]) -> str:
    tier = subnet_tier(subnet, rtb)
    if rtb and any(
        r.target_kind in (M.T_INTERNET, M.T_EIGW) and r.state == "active" for r in rtb.routes
    ):
        return "public"
    return tier


def workload_key(wl: Workload) -> str:
    return f"wl:{wl.region}:{wl.id}"


def workload_label(wl: Workload, max_targets: int = 0) -> str:
    base = wl.label if wl.name else wl.id
    lines = [f"{wl.kind.upper()} {base}"]
    if wl.engine and wl.kind not in ("alb", "nlb", "gwlb"):
        lines.append(wl.engine)
    if wl.extra.get("scheme"):
        lines.append(str(wl.extra["scheme"]))
    if wl.state:
        lines.append(wl.state)
    if max_targets and wl.extra.get("targets"):
        lines.append(f"{len(wl.extra['targets'])} targets")
    return "\n".join(lines)


def route_table_label(rtb: RouteTable, detail: bool = True) -> str:
    if not detail:
        return rtb.label
    interesting = [
        r
        for r in rtb.routes
        if r.target_kind != M.T_LOCAL and r.state == "active"
    ]
    lines = [f"{rtb.label}", f"{rtb.id} ({len(rtb.routes)} routes)"]
    for route in interesting[:4]:
        lines.append(f"{route.destination} \u2192 {route.target_id}")
    if len(interesting) > 4:
        lines.append(f"+{len(interesting) - 4} more")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# diagrams
# --------------------------------------------------------------------------- #


def render_overview(topo, max_vpcs: int = 40) -> str:
    """One high-level diagram: VPCs and how they are connected."""
    b = MermaidBuilder("AWS network overview", "LR")
    vpcs = sorted(topo.vpcs.values(), key=lambda v: (v.region, v.name or v.id))
    vpcs = vpcs[:max_vpcs]
    for vpc in vpcs:
        with b.subgraph(f"vpc:{vpc.id}", f"{vpc.label}\n{vpc.region} {vpc.cidr}\n{vpc.id}"):
            subnets = topo.subnets_by_vpc.get(vpc.id, [])
            public = [s for s in subnets if _subnet_is_public(topo, s)]
            private = [s for s in subnets if s not in public]
            igw = topo.igw_for_vpc(vpc.id)
            if igw:
                b.node(f"igw:{vpc.id}", f"IGW {igw.id[-6:]}", "stadium", "igw")
            atts = topo.tgw_attachments_for_vpc(vpc.id)
            for att in atts:
                b.node(
                    f"tgwatt:{att.id}",
                    f"TGW attach\n{', '.join(att.cidr_blocks) or vpc.cidr}",
                    "stadium",
                    "tgw",
                )
            b.node(
                f"vpc:{vpc.id}:subnets",
                f"{len(subnets)} subnets\n({len(public)} public / {len(private)} private)"
                if subnets
                else "no subnets",
                "box",
                "private",
            )
            wls = topo.workloads_by_vpc.get(vpc.id, [])
            if wls:
                counts: Dict[str, int] = {}
                for wl in wls:
                    counts[wl.kind] = counts.get(wl.kind, 0) + 1
                summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
                b.node(f"vpc:{vpc.id}:wl", summary, "box", "private")
                b.edge(f"vpc:{vpc.id}:subnets", f"vpc:{vpc.id}:wl", "hosts")

    # connectivity edges
    for tgw in topo.tgws.values():
        key = f"tgw:{tgw.id}"
        b.node(key, f"TGW\n{tgw.label}\n{tgw.region}", "stadium", "tgw")
        for att in tgw.attachments:
            if att.resource_type != "vpc":
                continue
            for anchor in (f"tgwatt:{att.id}", f"vpc:{att.resource_id}:subnets"):
                if anchor in b._ids:
                    b.edge(anchor, key, att.cidr_blocks[0] if att.cidr_blocks else "", "-.->")
        for att in tgw.attachments:
            if att.resource_type in ("vpn", "dXGateway", "TransitGateway", "peering"):
                b.node(
                    f"att:{att.id}",
                    f"{att.resource_type} attach\n{att.resource_id}",
                    "hex",
                    "tgw",
                )
                b.edge(key, f"att:{att.id}", att.state, "-.->")

    for pcx in topo.peerings.values():
        if pcx.status != "active" or pcx.vpc_id not in topo.vpcs or pcx.peer_vpc_id not in topo.vpcs:
            continue
        a, c = f"vpc:{pcx.vpc_id}:subnets", f"vpc:{pcx.peer_vpc_id}:subnets"
        if a in b._ids and c in b._ids:
            suffix = f" ({pcx.peer_region})" if not pcx.intra_region else ""
            b.edge(a, c, f"peering{suffix}", "<-.->")

    has_onprem = bool(topo.vpn_gateways or topo.vpn_connections)
    if has_onprem:
        b.node("onprem", "On-premises / Direct Connect", "stadium", "onprem")
        for vgw in topo.vpn_gateways.values():
            if vgw.vpc_id in topo.vpcs:
                b.edge("onprem", f"vpc:{vgw.vpc_id}:subnets", vgw.state, "-.->")
    if topo.igws:
        b.node("internet", "INTERNET", "stadium", "internet")
        for vpc_id in topo.vpcs:
            if topo.igw_for_vpc(vpc_id):
                b.edge("internet", f"vpc:{vpc_id}:subnets", "IGW", "-.->")
    return b.render()


def _subnet_is_public(topo, subnet: Subnet) -> bool:
    rtb = topo.rtb_for_subnet(subnet.id)
    if not rtb:
        return False
    return any(
        r.target_kind in (M.T_INTERNET, M.T_EIGW) and r.state == "active" for r in rtb.routes
    )


def render_vpc(topo, vpc_id: str, max_subnets: int = 40, max_workloads: int = 40) -> str:
    """Detail diagram for one VPC: subnets, their route tables and workloads."""
    vpc = topo.vpcs.get(vpc_id)
    b = MermaidBuilder(f"VPC {vpc.label if vpc else vpc_id}", "TB")
    igw = topo.igw_for_vpc(vpc_id)
    if igw:
        b.node(f"igw:{igw.id}", f"Internet Gateway\n{igw.name}", "stadium", "igw")
        b.node("internet", "INTERNET", "stadium", "internet")
        b.edge("internet", f"igw:{igw.id}", "", "-.->")
    for eigw_route in _egress_only(topo, vpc_id):
        b.node(f"eigw:{eigw_route}", "Egress-only IGW", "stadium", "igw")
    for ep in topo.endpoints_by_vpc.get(vpc_id, []):
        b.node(
            f"ep:{ep.id}",
            f"VPC Endpoint\n{ep.short_service}\n{ep.vpc_endpoint_type}",
            "hex",
            "endpoint",
        )
    for att in topo.tgw_attachments_for_vpc(vpc_id):
        tgw = topo.tgws.get(att.tgw_id)
        if tgw:
            b.node(f"tgw:{tgw.id}", f"Transit Gateway\n{tgw.label}\n{tgw.region}", "stadium", "tgw")
        b.node(
            f"tgwatt:{att.id}",
            f"Transit Gateway attach\n{', '.join(att.cidr_blocks) or vpc.cidr if vpc else ''}\n{att.state}",
            "stadium",
            "tgw",
        )
        if tgw:
            b.edge(
                f"tgwatt:{att.id}",
                f"tgw:{tgw.id}",
                "",
                "-.->",
            )
    for pcx in topo.peers_of_vpc(vpc_id):
        peer = topo.vpcs.get(pcx.peer_vpc_id)
        b.node(
            f"pcx:{pcx.id}",
            f"Peering\n{peer.label if peer else pcx.peer_vpc_id}\n{pcx.status}",
            "hex",
            "peering" if pcx.status == "active" else "blocked",
        )
    for vgw in topo.vpn_gateways.values():
        if vgw.vpc_id == vpc_id:
            conns = [c for c in topo.vpn_connections.values() if c.vgw_id == vgw.id]
            b.node(
                f"vgw:{vgw.id}",
                f"VPN Gateway\n{', '.join(sorted({c.state for c in conns})) or vgw.state}",
                "stadium",
                "onprem",
            )
            b.node("onprem", "On-premises / DX", "stadium", "onprem")
            b.edge("onprem", f"vgw:{vgw.id}", "", "-.->")

    subnets = topo.subnets_by_vpc.get(vpc_id, [])
    shown = subnets[:max_subnets]
    workloads = topo.workloads_by_vpc.get(vpc_id, [])[:max_workloads]

    for subnet in shown:
        rtb = topo.rtb_for_subnet(subnet.id)
        key = f"sn:{subnet.id}"
        b.node(key, f"{subnet.name}\n{subnet.cidr}\n{subnet.az}\n{subnet.id}", "box", subnet_class(subnet, rtb))
        if rtb:
            rkey = f"rtb:{rtb.id}"
            b.node(rkey, route_table_label(rtb), "subroutine", "rtb")
            b.edge(key, rkey, "uses", "-.->")
            _wire_routes(b, topo, rtb, subnet=subnet)
        for wl in topo.workloads_by_subnet.get(subnet.id, []):
            wkey = workload_key(wl)
            if wkey not in b._ids:
                b.node(wkey, workload_label(wl), "round", _workload_class(wl))
                b.edge(wkey, key, "attached", "-.->")
    for wl in workloads:
        wkey = workload_key(wl)
        if wkey not in b._ids and wl.subnet_ids:
            b.node(wkey, workload_label(wl), "round", _workload_class(wl))
            anchor = next((f"sn:{s}" for s in wl.subnet_ids if f"sn:{s}" in b._ids), None)
            if anchor:
                b.edge(wkey, anchor, "spans", "-.->")

    if len(subnets) > max_subnets:
        b.node(f"sn:more", f"+{len(subnets) - max_subnets} more subnets (not drawn)", "box", "warn")
    if len(topo.workloads_by_vpc.get(vpc_id, [])) > max_workloads:
        b.node(
            f"wl:more",
            f"+{len(topo.workloads_by_vpc.get(vpc_id, [])) - max_workloads} more workloads",
            "box",
            "warn",
        )
    return b.render()


def _egress_only(topo, vpc_id: str) -> List[str]:
    out = []
    for rtb in topo.rtbs_by_vpc.get(vpc_id, []):
        for route in rtb.routes:
            if route.target_kind == M.T_EIGW and route.target_id not in out:
                out.append(route.target_id)
    return out


def _workload_class(wl: Workload) -> str:
    if wl.kind == "rds":
        return "data"
    if wl.extra.get("public_ips") or wl.extra.get("public") or wl.extra.get("scheme") == "internet-facing":
        return "public"
    if wl.kind in ("alb", "nlb", "gwlb"):
        return "public" if wl.extra.get("scheme") == "internet-facing" else "private"
    return "private"


def _wire_routes(b: MermaidBuilder, topo, rtb: RouteTable, subnet: Optional[Subnet] = None) -> None:
    src = f"rtb:{rtb.id}"
    drawn = 0
    for route in rtb.routes:
        if route.state != "active":
            continue
        kind = route.target_kind
        dst_key = None
        if kind == M.T_INTERNET:
            igw = topo.igws.get(route.target_id)
            dst_key = f"igw:{route.target_id}" if igw else None
        elif kind == M.T_EIGW:
            dst_key = f"eigw:{route.target_id}"
        elif kind == M.T_NAT:
            dst_key = f"nat:{route.target_id}"
        elif kind == M.T_TGW:
            for att in topo.tgw_attachments_for_vpc(rtb.vpc_id):
                if att.tgw_id == route.target_id:
                    dst_key = f"tgwatt:{att.id}"
                    break
        elif kind == M.T_PEERING:
            dst_key = f"pcx:{route.target_id}"
        elif kind == M.T_VGW:
            dst_key = f"vgw:{route.target_id}"
        elif kind == M.T_ENDPOINT:
            dst_key = f"ep:{route.target_id}"
        elif kind == M.T_ENI:
            eni = topo.enis.get(route.target_id)
            if eni:
                dst_key = workload_key_wl(wl=eni) or None
        if dst_key is None or dst_key not in b._ids:
            continue
        label = route.destination if not is_default_route(route.destination) else "default"
        b.edge(src, dst_key, label, "-->" if not is_default_route(route.destination) else "==>", 46)
        drawn += 1
        if drawn >= 8:
            break
    if subnet is not None:
        nat = topo.nat_in_subnet(subnet.id)
        if nat and f"nat:{nat.id}" not in b._ids:
            b.node(f"nat:{nat.id}", f"NAT Gateway\n{nat.name}\n{nat.state}", "hex", "nat")
            if f"nat:{nat.id}" in b._ids and f"sn:{subnet.id}" in b._ids:
                b.edge(f"nat:{nat.id}", f"sn:{subnet.id}", "resides in", "-.->")


def workload_key_wl(wl) -> Optional[str]:
    if getattr(wl, "workload_id", ""):
        return f"wl:{wl.region}:{wl.workload_id}"
    return None


def render_tgw(topo) -> str:
    b = MermaidBuilder("Transit gateway topology", "LR")
    for tgw in topo.tgws.values():
        with b.subgraph(f"tgw:{tgw.id}", f"{tgw.label} ({tgw.region}) state={tgw.state}"):
            tkey = f"tgw:{tgw.id}"
            b.node(tkey, f"TGW {tgw.id}", "stadium", "tgw")
            for rtb in tgw.route_tables:
                rkey = f"tgwrtb:{rtb.id}"
                routes = "\n".join(
                    f"{r.destination} \u2192 {r.target_id[:8]}" for r in rtb.routes[:6]
                ) or "no routes"
                more = f"\n+{len(rtb.routes) - 6} more" if len(rtb.routes) > 6 else ""
                b.node(
                    rkey,
                    f"{rtb.name or rtb.id}\n{'default-association' if rtb.default_association else 'explicit'}\n{routes}{more}",
                    "subroutine",
                    "rtb",
                )
                b.edge(rkey, tkey, "routes via", "-.->")
            for att in tgw.attachments:
                akey = f"att:{att.id}"
                target = topo.vpcs.get(att.resource_id) if att.resource_type == "vpc" else None
                label = (
                    f"{att.resource_type} attach\n{target.label if target else att.resource_id}\n"
                    f"{', '.join(att.cidr_blocks) or 'no cidr'}\nstate={att.state}"
                )
                cls = "tgw" if att.state == "available" else "blocked"
                b.node(akey, label, "hex", cls)
                b.edge(tkey, akey, "", "-->")
                for rtb in tgw.route_tables:
                    if att.id in rtb.associations:
                        b.edge(f"tgwrtb:{rtb.id}", akey, "associated", "-.->")
    if not topo.tgws:
        b.node("none", "no transit gateways in this account", "box")
    return b.render()


def render_internet(topo) -> str:
    b = MermaidBuilder("Internet egress and ingress paths", "TB")
    b.node("internet", "INTERNET", "stadium", "internet")
    if not topo.igws and not topo.nat_gateways:
        b.node("none", "no internet gateways or NAT gateways", "box")
        return b.render()
    for igw in topo.igws.values():
        vpc = topo.vpcs.get(igw.vpc_id)
        key = f"igw:{igw.id}"
        b.node(
            key,
            f"IGW {igw.id}\n{vpc.label if vpc else igw.vpc_id or 'not attached'}\n"
            f"{'attached' if igw.attached else 'DETACHED'}",
            "stadium",
            "igw" if igw.attached else "blocked",
        )
        b.edge("internet", key, "", "-->")
        for subnet in topo.subnets_by_vpc.get(igw.vpc_id, []):
            rtb = topo.rtb_for_subnet(subnet.id)
            if not rtb:
                continue
            if not any(
                r.target_kind == M.T_INTERNET and r.state == "active" and r.target_id == igw.id
                for r in rtb.routes
            ):
                continue
            skey = f"sn:{subnet.id}"
            if skey not in b._ids:
                b.node(skey, f"{subnet.name}\n{subnet.cidr}\n{subnet.id}", "box", "public")
                for wl in topo.workloads_by_subnet.get(subnet.id, [])[:6]:
                    wkey = workload_key(wl)
                    b.node(wkey, workload_label(wl), "round", _workload_class(wl))
                    b.edge(wkey, skey, style="-.->")
            b.edge(key, skey, "public subnets", "-->")
    for nat in topo.nat_gateways.values():
        vpc = topo.vpcs.get(nat.vpc_id)
        key = f"nat:{nat.id}"
        b.node(
            key,
            f"NAT {nat.id}\n{vpc.label if vpc else ''}\n{nat.connect_type} / {nat.state}",
            "hex",
            "nat" if nat.state == "available" else "blocked",
        )
        igw = topo.igw_for_vpc(nat.vpc_id)
        if igw:
            b.edge(key, f"igw:{igw.id}", "outbound", "-->")
        for subnet in topo.subnets_by_vpc.get(nat.vpc_id, []):
            rtb = topo.rtb_for_subnet(subnet.id)
            if not rtb:
                continue
            if any(r.target_kind == M.T_NAT and r.target_id == nat.id for r in rtb.routes):
                skey = f"sn:{subnet.id}"
                if skey not in b._ids:
                    b.node(skey, f"{subnet.name}\n{subnet.cidr}\n{subnet.id}", "box", "private")
                b.edge(skey, key, "default route", "-->")
    return b.render()


def render_subnet(topo, subnet_id: str) -> str:
    subnet = topo.subnets.get(subnet_id)
    b = MermaidBuilder(f"Subnet {subnet.label if subnet else subnet_id}", "TB")
    if not subnet:
        b.node("missing", f"subnet {subnet_id} not found", "box")
        return b.render()
    b.node("internet", "INTERNET", "stadium", "internet")
    skey = f"sn:{subnet.id}"
    b.node(skey, f"{subnet.name}\n{subnet.cidr}\n{subnet.az}\n{subnet.id}", "box", subnet_class(subnet, topo.rtb_for_subnet(subnet.id)))
    rtb = topo.rtb_for_subnet(subnet.id)
    if rtb:
        b.node(f"rtb:{rtb.id}", route_table_label(rtb), "subroutine", "rtb")
        b.edge(skey, f"rtb:{rtb.id}", f"{subnet.rtb_association} association", "-.->")
        _wire_routes(b, topo, rtb, subnet=subnet)
    for eni in topo.enis_by_subnet.get(subnet.id, []):
        ekey = f"eni:{eni.id}"
        ip = eni.private_ip + (f" / {eni.public_ip}" if eni.public_ip else "")
        b.node(ekey, f"{eni.label}\n{ip}\n{', '.join(eni.sg_ids) or 'no sg'}", "round", "public" if eni.public_ip else "private")
        b.edge(ekey, skey, "in", "-.->")
    for wl in topo.workloads_by_subnet.get(subnet.id, []):
        wkey = workload_key(wl)
        if wkey not in b._ids:
            b.node(wkey, workload_label(wl), "round", _workload_class(wl))
            b.edge(wkey, skey, "attached", "-.->")
    return b.render()


def render_connectivity(topo, paths: Sequence) -> str:
    """Diagram of evaluated flows, one swimlane-ish box per result."""
    b = MermaidBuilder("Evaluated connectivity", "LR")
    if not paths:
        b.node("none", "no flows evaluated", "box")
        return b.render()
    for i, p in enumerate(paths):
        key = f"flow:{i}"
        verdict = getattr(p, "verdict", "unknown")
        cls = {"reachable": "private", "blocked": "blocked"}.get(verdict, "warn")
        hops = " \u2192 ".join(
            str(getattr(h, "label", h)).split("\n")[0] for h in getattr(p, "hops", [])
        )
        b.node(key, f"{verdict.upper()}\n{trunc(hops, 90)}", "box", cls)
    return b.render()
