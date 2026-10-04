"""Mermaid ``flowchart`` rendering.

Every diagram is built through :class:`MermaidBuilder`, which guarantees valid
node ids and escapes labels, so generated files always parse.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import flow, model as M
from .model import Subnet, Workload
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
    "vgw": ("fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b",),
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
        self._subgraph_counter = 0

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
    def subgraph(self, key: str, label: str) -> "_Subgraph":
        return _Subgraph(self, key, label)

    def defined(self, key: str) -> bool:
        return key in self._ids and self._ids[key] in self._defined

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


class _Subgraph:
    """Deterministic nested subgraph context manager.

    Ids come from a counter rather than ``hash()`` so the same inventory always
    renders byte-identical output (Python randomizes string hashes per process).
    """

    def __init__(self, builder: MermaidBuilder, key: str, label: str):
        self.b = builder
        self.key = key
        self.label = label
        self.id = ""

    def __enter__(self) -> str:
        self.b._subgraph_counter += 1
        self.id = f"sg{self.b._subgraph_counter}"
        self.b._lines.append(f'subgraph {self.id}["{esc(self.label)}"]')
        self.b._lines.append("  direction " + self.b.direction)
        return self.id

    def __exit__(self, *exc) -> bool:
        self.b._lines.append("end")
        return False


# --------------------------------------------------------------------------- #
# subnets / workloads
# --------------------------------------------------------------------------- #


def _sg_ingress_summary(topo: Topology, sg_ids: Sequence[str], limit: int = 3) -> List[str]:
    """Human-readable ingress rules, the thing that decides if a flow is allowed."""
    out: List[str] = []
    for sg_id in sg_ids:
        sg = topo.security_groups.get(sg_id)
        if not sg:
            continue
        name = sg.name or sg.id
        for rule in sg.ingress[:limit]:
            src = rule.cidr or (f"sg {rule.sg_id}" if rule.sg_id else "any")
            proto = rule.protocol.upper() if rule.protocol not in ("-1", "all") else "any"
            out.append(f"{name}: {proto} {rule.port_range} from {src}")
        if len(sg.ingress) > limit:
            out.append(f"{name}: +{len(sg.ingress) - limit} more")
    return out


# --------------------------------------------------------------------------- #
# THE single topology diagram
# --------------------------------------------------------------------------- #
#
# One diagram for the whole account. Two visual languages, never mixed:
#
#   containers   AWS Account > VPC > Availability Zone > Subnet
#                where a thing LIVES
#   arrows       network traffic path, always labelled with the route that
#                justifies it (destination, next hop, port)
#
# NACLs and security groups are never nodes. They are lines inside the label of
# the container (NACL) or the resource (SG). ``local`` is never a node either --
# it appears in the label of an intra-VPC arrow.

MAX_TOPOLOGY_SUBNETS = 400
MAX_SG_RULES = 2

CLASS_ORDER = {"public": 0, "private": 1, "isolated": 2}


def _known_node_ids(topo: Topology) -> Set[str]:
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


def render_topology(
    topo: Topology,
    model: Optional["flow.FlowModel"] = None,
    *,
    max_vpcs: int = 60,
    max_subnets: int = MAX_TOPOLOGY_SUBNETS,
) -> str:
    """Render the one and only AWS network connectivity / traffic flow map."""
    if model is None:
        model = flow.build_flow_model(topo)

    b = MermaidBuilder(
        f"AWS network connectivity / traffic flow map ({topo.account_id or 'account'})", "TB"
    )
    b.free("  %% containers = where a resource lives; arrows = network traffic path")
    b.free("  %% NACL and security groups are metadata inside labels, never nodes")
    b.free("  %% arrow labels show the route that justifies the path (longest-prefix match)")

    defined: Set[str] = set()

    # -- external networks ------------------------------------------------
    b.node(flow.internet_node(), "INTERNET", "stadium", "internet", 60)
    defined.add(flow.internet_node())

    # On-premises exists as soon as anything hybrid is present.
    if topo.vpn_gateways or topo.vpn_connections or topo.tgws:
        b.node(
            flow.onprem_node(),
            "ON-PREMISES\nCORPORATE / DATA CENTRE",
            "box",
            "onprem",
            60,
        )
        defined.add(flow.onprem_node())

    # AWS service endpoints a VPC endpoint fronts.
    for endpoint in list(topo.endpoints.values())[:12]:
        svc = endpoint.service_name or "aws service"
        node = flow.service_node(svc)
        if node in defined:
            continue
        short = _service_short(svc)
        b.node(node, f"AWS SERVICE\n{short}", "stadium", "endpoint", 120)
        defined.add(node)

    # An IGW that is not attached to any VPC is still a route target, so it must
    # appear or its arrows would dangle. This is a real misconfiguration.
    attached = {i.id for v in topo.vpcs.values() for i in topo.igw_by_vpc.get(v.id, [])}
    for igw in topo.igws.values():
        if igw.id in attached:
            continue
        node = flow.nid("igw", igw.id)
        b.node(
            node,
            f"INTERNET GATEWAY\n{igw.id}\nNOT ATTACHED TO ANY VPC",
            "round",
            "blocked",
            200,
        )
        defined.add(node)

    # -- transit gateways (regional, not inside any VPC) ------------------
    for tgw in list(topo.tgws.values())[:8]:
        node = flow.nid("tgw", tgw.id)
        label = [f"TRANSIT GATEWAY {tgw.label}"]
        label.append(f"{tgw.id}")
        if tgw.state:
            label.append(tgw.state)
        label.extend(model.notes.get(node, []))
        b.node(node, "\n".join(label), "hex", "tgw", 200)
        defined.add(node)

    # -- VPCs -------------------------------------------------------------
    vpcs = list(topo.vpcs.values())[:max_vpcs]
    for vpc in vpcs:
        _emit_vpc(b, model, topo, vpc, defined, max_subnets)

    # Anything an arrow points at must exist, or Mermaid drops the arrow (and
    # reports a parse error). A resource can be referenced without being drawn:
    # its subnet failed collection, or its VPC was over the diagram budget. Emit
    # a placeholder rather than a dangling reference.
    referenced = {e.src for e in model.edges} | {e.dst for e in model.edges}
    known = _known_node_ids(topo)
    for node in sorted(referenced - defined):
        # Two very different reasons for a missing node, and conflating them
        # would send you hunting for a resource that is right there in the API.
        if node in known:
            why = "exists, but over the diagram budget\nraise --max-diagram-vpcs / --max-diagram-subnets"
        else:
            why = "not present in the inventory\nits subnet or VPC may have failed collection"
        b.node(
            node,
            f"OFF DIAGRAM\n{node.replace('_', ' ')}\nreferenced by a route\n{why}",
            "round",
            "blocked",
            220,
        )
        defined.add(node)

    # -- arrows -----------------------------------------------------------
    for edge in model.edges:
        if edge.src in defined and edge.dst in defined:
            b.edge(edge.src, edge.dst, edge.label, edge.style, 120)

    # -- anything referenced but never placed gets an honest stub ---------
    for edge in model.edges:
        for key in (edge.src, edge.dst):
            if key in defined:
                continue
            defined.add(key)
            b.node(key, f"unresolved {key}", "box", "warn", 80)

    b.free("")
    _legend(b, topo, model, len(vpcs))

    text = b.render()
    if len(topo.vpcs) > max_vpcs:
        text += f"%% NOTE: showing {max_vpcs} of {len(topo.vpcs)} VPCs\n"
    return text


def _emit_vpc(b, model, topo, vpc, defined: Set[str], budget: int) -> None:
    cidrs = ", ".join(topo.vpc_cidrs(vpc.id)[:3]) or "no CIDR"
    title = f"AWS ACCOUNT {topo.account_id or ''}\nVPC {vpc.label}  \u2014  {vpc.id}\n{cidrs}"
    if vpc.flow_log_status and vpc.flow_log_status != "unknown":
        title += f"\nVPC Flow Logs: {vpc.flow_log_status}"

    with b.subgraph(f"vpc:{vpc.id}", title):
        # VPC-scoped gateways: not located in any single subnet.
        for igw in topo.igw_by_vpc.get(vpc.id, []):
            node = flow.nid("igw", igw.id)
            b.node(
                node,
                f"INTERNET GATEWAY\n{igw.id}\nattached to VPC {vpc.id}",
                "round",
                "igw",
                200,
            )
            defined.add(node)

        for vgw in topo.vpn_gateways.values():
            if vgw.vpc_id != vpc.id:
                continue
            node = flow.nid("vgw", vgw.id)
            label = f"VPN GATEWAY\n{vgw.id}\n{vgw.state or ''}\n{vgw.vpn_type or ''}"
            label = "\n".join([label, *model.notes.get(node, [])])
            b.node(node, label, "round", "vgw", 200)
            defined.add(node)

        for peer in topo.peerings_by_vpc.get(vpc.id, []):
            node = flow.nid("pcx", peer.id)
            other = peer.peer_vpc_id or "unknown vpc"
            label = [f"VPC PEERING {peer.name}", f"{peer.id}", f"peers with {other}"]
            label.extend(model.notes.get(node, []))
            b.node(node, "\n".join(label), "hex", "peering", 220)
            defined.add(node)

        for endpoint in topo.endpoints_by_vpc.get(vpc.id, []):
            node = flow.nid("vpce", endpoint.id)
            svc = (endpoint.service_name or "").split(".")[-1] or "aws"
            where = ", ".join(
                (topo.subnets[s].az or "?") for s in (endpoint.subnet_ids or [])[:3] if s in topo.subnets
            )
            lines = [f"VPC ENDPOINT {svc}", endpoint.id, endpoint.vpc_endpoint_type or ""]
            if where:
                lines.append(f"ENIs in AZ: {where}")
            ep_sgs: List[str] = list(endpoint.sg_ids or [])
            if not ep_sgs:
                for eni_id in endpoint.network_interface_ids or []:
                    eni = topo.enis.get(eni_id)
                    if eni and eni.sg_ids:
                        ep_sgs = list(eni.sg_ids)
                        break
            lines.append(f"SG: {', '.join(ep_sgs[:2])}" if ep_sgs else "SG: none")
            b.node(node, "\n".join(lines), "hex", "endpoint", 220)
            defined.add(node)

        # Interfaces already represented by a node we draw: workload ENIs, the
        # NAT gateway's interface, and load balancer interfaces.
        owned_eni_ids: Set[str] = set()
        for wl in topo.workloads_by_vpc.get(vpc.id, []):
            owned_eni_ids.update(wl.eni_ids or [])
        for nat in topo.nat_by_vpc.get(vpc.id, []):
            for eni in topo.enis_by_subnet.get(nat.subnet_id or "", []):
                if eni.interface_type == "natGateway" or nat.id in (eni.description or ""):
                    owned_eni_ids.add(eni.id)
        for eni in topo.enis.values():
            if eni.interface_type in ("loadBalancer", "network_load_balancer", "vpce"):
                owned_eni_ids.add(eni.id)

        subnets = list(topo.subnets_by_vpc.get(vpc.id, []))[:budget]
        by_az: Dict[str, List[Subnet]] = {}
        for subnet in subnets:
            by_az.setdefault(subnet.az or "unknown-az", []).append(subnet)

        for az in sorted(by_az):
            with b.subgraph(f"az:{vpc.id}:{az}", f"AVAILABILITY ZONE {az}"):
                ordered = sorted(
                    by_az[az],
                    key=lambda s: (
                        CLASS_ORDER.get(model.routing_for(s.id).classification, 3),
                        s.cidr,
                    ),
                )
                for subnet in ordered:
                    _emit_subnet(b, model, topo, vpc, subnet, defined, owned_eni_ids)


def _emit_subnet(b, model, topo, vpc, subnet: Subnet, defined: Set[str], owned_eni_ids: Set[str]) -> None:
    info = model.routing_for(subnet.id)
    cls = info.classification

    title = f"{cls.upper()} SUBNET  \u00b7  {subnet.name}"
    with b.subgraph(f"subnet:{subnet.id}", title):
        # Container header. Carries identity, route table, NACL and the routes as
        # text. It has no edges, so it can never be mistaken for a hop in the path.
        header = [
            f"{subnet.id}  \u00b7  {subnet.cidr or 'no cidr'}  \u00b7  AZ {subnet.az or 'unknown'}",
        ]
        if info.rtb_id:
            header.append(f"Route table: {info.rtb_name or info.rtb_id} ({info.rtb_id})")
        else:
            header.append("Route table: none associated (main table only)")
        nacl = topo.nacl_by_subnet.get(subnet.id)
        if nacl is not None:
            header.append(f"NACL: {nacl.id}  \u00b7  {_nacl_counts(nacl)}")
        else:
            header.append("NACL: none found")
        header.append(_classification_reason(info))
        for extra in info.extra_summary:
            header.append(extra)
        node = flow.sid(subnet.id)
        b.node(node, "\n".join(header), "box", cls if cls in CLASSES else "private", 220)
        defined.add(node)

        # Resources that physically live here.
        for nat in topo.nat_by_vpc.get(vpc.id, []):
            if nat.subnet_id != subnet.id:
                continue
            nat_node = flow.nid("nat", nat.id)
            lines = [f"NAT GATEWAY\n{nat.id}"]
            if nat.state:
                lines.append(nat.state)
            if nat.connect_type:
                lines.append(f"{nat.connect_type}")
            if nat.address:
                lines.append(nat.address)
            nat_sgs: List[str] = []
            for eni in topo.enis_by_subnet.get(subnet.id, []):
                if eni.interface_type == "natGateway" or nat.id in (eni.description or ""):
                    nat_sgs = [s for s in eni.sg_ids]
                    break
            lines.append(f"SG: {', '.join(nat_sgs[:2])}" if nat_sgs else "SG: none")
            lines.extend(model.notes.get(nat_node, []))
            b.node(nat_node, "\n".join(lines), "round", "nat", 220)
            defined.add(nat_node)

        for wl in topo.workloads_by_subnet.get(subnet.id, []):
            _emit_workload(b, model, topo, wl, defined, cls)

        for eni in topo.enis_by_subnet.get(subnet.id, []):
            _emit_eni(b, topo, eni, defined, owned_eni_ids)


def _service_short(service_name: str) -> str:
    """`com.amazonaws.eu-west-1.ecr.api` -> `ecr.api` (not just `api`)."""
    parts = [p for p in service_name.split(".") if p]
    while parts and parts[0] in ("com", "amazonaws") or (parts and parts[0].startswith(("aws-", "us-", "eu-", "ap-", "sa-", "ca-", "me-", "af-", "il-"))):
        parts.pop(0)
    return ".".join(parts[-2:]) or service_name


def _nacl_counts(nacl: M.Nacl) -> str:
    inbound = sum(1 for e in nacl.entries if not e.egress)
    outbound = len(nacl.entries) - inbound
    return f"{inbound} in / {outbound} out"


def _classification_reason(info) -> str:
    """One line: how this subnet was classified, and the route that proves it."""
    if info.default_route is None:
        return "Type: ISOLATED \u2014 no 0.0.0.0/0 route in its route table"
    kind = flow.target_kind(info.default_route)
    phrase = flow.TARGET_PHRASE.get(kind, kind)
    return f"Type: {info.classification.upper()} \u2014 0.0.0.0/0 \u2192 {phrase}"


def _emit_workload(b, model, topo, wl: Workload, defined: Set[str], subnet_class: str) -> None:
    node = flow.wid(wl.id)
    if node in defined:
        return

    lines = [_workload_title(wl), wl.id]
    eni = topo.primary_ip_for_workload(wl)
    if eni is not None and eni.private_ip:
        lines.append(f"ENI {eni.private_ip}")
    if wl.engine and wl.kind not in ("alb", "nlb", "gwlb"):
        lines.append(wl.engine)
    if wl.extra.get("scheme"):
        lines.append(f"{wl.extra['scheme']} {wl.kind.upper()}")

    # A load balancer with ENIs in several subnets/AZs cannot be drawn inside all
    # of them at once, so state the full placement instead of duplicating it.
    if len(wl.subnet_ids) > 1:
        places = []
        for sid_ in wl.subnet_ids[:4]:
            host = topo.subnets.get(sid_)
            if host is not None:
                places.append(f"{host.az}: {host.cidr}")
        if places:
            lines.append(f"ENIs in {len(wl.subnet_ids)} subnets")
            lines.extend(places)

    sg_ids = list(wl.sg_ids)
    if not sg_ids and eni is not None:
        sg_ids = list(eni.sg_ids)  # RDS and friends carry their SGs on the ENI
    if sg_ids:
        shown = sg_ids[:2]
        extra = f" (+{len(sg_ids) - 2})" if len(sg_ids) > 2 else ""
        lines.append(f"SG: {', '.join(shown)}{extra}")
    else:
        lines.append("SG: none (default VPC SG behaviour)")

    for rule in _sg_ingress_summary(topo, sg_ids, MAX_SG_RULES)[:MAX_SG_RULES]:
        lines.append(f"in {rule.split(': ', 1)[-1]}")

    b.node(node, "\n".join(lines), _workload_shape(wl),
          subnet_class if subnet_class in CLASSES else "private", 320)
    defined.add(node)


def _workload_title(wl: Workload) -> str:
    kind = {"ec2": "EC2", "rds": "RDS", "alb": "ALB", "nlb": "NLB", "gwlb": "GWLB"}.get(
        wl.kind, wl.kind.upper()
    )
    return f"{kind} {wl.name or wl.id}"


def _workload_shape(wl: Workload) -> str:
    if wl.kind in ("alb", "nlb", "gwlb", "lb"):
        return "stadium"
    if wl.kind == "rds":
        return "hex"
    return "box"


def _emit_eni(b, topo, eni, defined: Set[str], owned_eni_ids: Set[str]) -> None:
    """Only draw ENIs that no workload or gateway node already accounts for.

    An ALB's ENIs would otherwise appear twice: once inside the ALB node and
    again as a loose interface box in the same subnet.
    """
    if eni.instance_id or eni.id in owned_eni_ids:
        return
    if eni.requester_managed and not eni.description:
        return
    node = f"eni_{flow._key(eni.id)}"
    if node in defined:
        return
    lines = [f"NETWORK INTERFACE\n{eni.id}", eni.private_ip]
    if eni.interface_type:
        lines.append(f"type: {eni.interface_type}")
    if eni.sg_ids:
        lines.append(f"SG: {', '.join(eni.sg_ids[:2])}")
    b.node(node, "\n".join(lines), "box", "rtb", 200)
    defined.add(node)


def _orphan_notes(b, topo) -> None:
    """Name security resources that exist but attach to nothing.

    These are audit-relevant (an unused security group is a common finding) and
    they have no place in the topology, so they are recorded as comments rather
    than being dropped without a trace.
    """
    used_rtb = {
        topo.rtb_for_subnet(s.id).id
        for s in topo.subnets.values()
        if topo.rtb_for_subnet(s.id)
    }
    orphan_rtb = [r.id for r in topo.route_tables.values() if r.id not in used_rtb]
    used_nacl = {
        topo.nacl_by_subnet[s.id].id for s in topo.subnets.values() if topo.nacl_by_subnet.get(s.id)
    }
    orphan_nacl = [a.id for a in topo.nacls.values() if a.id not in used_nacl]
    used_sg = set()
    for wl in topo.workloads.values():
        used_sg.update(wl.sg_ids or [])
    for eni in topo.enis.values():
        used_sg.update(eni.sg_ids or [])
    orphan_sg = [g.id for g in topo.security_groups.values() if g.id not in used_sg]

    if orphan_rtb:
        b.free("  %% not associated with any subnet (no traffic path to draw): "
               + ", ".join(sorted(orphan_rtb)))
    if orphan_nacl:
        b.free("  %% NACLs not associated with any subnet: " + ", ".join(sorted(orphan_nacl)))
    if orphan_sg:
        b.free("  %% security groups not attached to any ENI: " + ", ".join(sorted(orphan_sg)))


def _legend(b, topo, model, vpc_count: int) -> None:
    pub = sum(1 for r in model.routing.values() if r.classification == flow.PUBLIC)
    priv = sum(1 for r in model.routing.values() if r.classification == flow.PRIVATE)
    iso = len(model.routing) - pub - priv
    b.free("  %% ---- legend ----")
    b.free(f"  %% account {topo.account_id or 'n/a'} | {vpc_count} VPC(s) | "
           f"{len(model.routing)} subnets: {pub} public / {priv} private / {iso} isolated")
    b.free(f"  %% network paths drawn: {len(model.edges)} | "
           f"workload paths traced: {model.traced} | SG-blocked: {model.blocked} | "
           f"SG-conditional: {model.conditional}")
    b.free("  %% containers: AWS ACCOUNT > VPC > AVAILABILITY ZONE > SUBNET (where things live)")
    b.free("  %% solid arrow = network traffic path; label = the route / port that creates it")
    b.free("  %% 'local' is shown in an edge label only, never as a gateway node")
    b.free("  %% NACL appears in the subnet header; security groups in the resource node")
    b.free("  %% routes show configured reachability potential, not observed traffic")
    _orphan_notes(b, topo)
