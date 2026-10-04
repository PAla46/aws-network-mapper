"""Normalized network-connectivity model for the single topology diagram.

This module does not talk to AWS. It reads the already-normalized
:mod:`nm.model` objects hung off a :class:`~nm.topology.Topology` and derives:

* subnet classification (``public`` / ``private`` / ``isolated``) from the
  *effective route table*, never from the subnet name;
* the routing arrows (subnet -> next hop), each labelled with the route that
  justifies it;
* the workload arrows (resource -> resource), each labelled with the port plus
  the route AWS longest-prefix-match would actually select.

Two hard rules encode the design brief:

``local`` is never a node
    ``10.0.0.0/16 -> local`` authorizes traffic inside the VPC. It appears in the
    *label* of an intra-VPC arrow; it never becomes a fake gateway box.

NACLs and security groups are never nodes
    They are metadata rendered inside the subnet / resource label. The only way
    a security group reaches the diagram is a ``SG DENIES`` annotation on an
    arrow whose route genuinely exists.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import model as M
from .cidrutil import ip_in_net, is_default_route, parse_net
from .paths import BLOCKED, CONDITIONAL, PathEngine
from .topology import Topology

PUBLIC = "public"
PRIVATE = "private"
ISOLATED = "isolated"

NETWORK_TARGETS = {"igw", "nat", "tgw", "pcx", "vgw", "vpce"}

TARGET_PHRASE = {
    "igw": "Internet Gateway",
    "nat": "NAT Gateway",
    "tgw": "Transit Gateway",
    "pcx": "VPC Peering",
    "vgw": "Virtual Private Gateway",
    "vpce": "VPC Endpoint",
}

MAX_TGWS = 8
MAX_PEERINGS = 8
MAX_ENDPOINTS = 12
MAX_TARGETS_PER_LB = 12
MAX_EC2_FOR_TIERS = 40
MAX_RDS_FOR_TIERS = 10


def target_kind(route: M.Route) -> str:
    """Normalize a route target into ``igw`` / ``nat`` / ... / ``other``."""
    if route.target_kind in NETWORK_TARGETS:
        return route.target_kind
    tid = route.target_id or ""
    for prefix, kind in (
        ("igw-", "igw"),
        ("nat-", "nat"),
        ("tgw-", "tgw"),
        ("pcx-", "pcx"),
        ("vgw-", "vgw"),
        ("vpce-", "vpce"),
    ):
        if tid.startswith(prefix):
            return kind
    return route.target_kind or "other"


def route_label(route: Optional[M.Route]) -> str:
    """The label that explains *why* an arrow exists."""
    if route is None:
        return "no matching route"
    kind = target_kind(route)
    if kind == "local":
        return f"{route.destination} local"
    phrase = TARGET_PHRASE.get(kind)
    if phrase:
        return f"{route.destination} \u2192 {phrase}"
    return f"{route.destination} \u2192 {route.target_id or 'blackhole'}"


# ---------------------------------------------------------------------------
# subnet classification -- derived from routing, not from names
# ---------------------------------------------------------------------------


@dataclass
class SubnetRouting:
    """What the diagram needs to know about one subnet's routing."""

    subnet_id: str
    rtb_id: str = ""
    rtb_name: str = ""
    classification: str = ISOLATED
    default_route: Optional[M.Route] = None
    default_target_kind: str = ""
    egress: List[M.Route] = field(default_factory=list)
    hazards: List[M.Route] = field(default_factory=list)

    @property
    def extra_summary(self) -> List[str]:
        """Non-default routes worth naming on the subnet header."""
        out: List[str] = []
        for route in self.hazards:
            out.append(route_label(route))
        return out

    @property
    def default_summary(self) -> str:
        if self.default_route is None:
            return "no default route"
        return route_label(self.default_route)

    @property
    def egress_summary(self) -> str:
        if not self.egress:
            return ""
        parts = [route_label(r) for r in self.egress[:3]]
        extra = len(self.egress) - len(parts)
        if extra > 0:
            parts.append(f"+{extra} more")
        return "\n".join(parts)


def classify_subnet(topo: Topology, subnet: M.Subnet) -> SubnetRouting:
    """Classify a subnet from its effective default route.

    PUBLIC    default route points at an Internet Gateway
    PRIVATE   default route points at a NAT Gateway (or leaves via TGW/VGW)
    ISOLATED  no default route at all
    """
    info = SubnetRouting(subnet_id=subnet.id)
    rtb = topo.rtb_for_subnet(subnet.id)
    if rtb is None:
        return info

    info.rtb_id = rtb.id
    info.rtb_name = rtb.label

    for route in rtb.routes:
        if route.state == "active" and is_default_route(route.destination):
            info.default_route = route
            break

    if info.default_route is not None:
        kind = target_kind(info.default_route)
        info.default_target_kind = kind
        info.classification = PUBLIC if kind == "igw" else PRIVATE

    info.hazards = [
        r
        for r in rtb.routes
        if r.state == "active"
        and not is_default_route(r.destination)
        and target_kind(r) in ("tgw", "pcx", "vgw", "vpce", "eni")
    ][:3]
    info.egress = [
        r
        for r in rtb.routes
        if r.state == "active"
        and is_default_route(r.destination)
        and target_kind(r) in ("igw", "nat", "vgw", "tgw")
    ]
    return info


# ---------------------------------------------------------------------------
# node ids
# ---------------------------------------------------------------------------


def _key(raw: str) -> str:
    return raw.replace("-", "_").replace("/", "_").replace(":", "_")


def sid(subnet_id: str) -> str:
    return f"s_{_key(subnet_id)}"


def wid(workload_id: str) -> str:
    return f"w_{_key(workload_id)}"


def nid(kind: str, raw_id: str) -> str:
    return f"{kind}_{_key(raw_id)}"


def internet_node() -> str:
    return nid("net", "internet")


def onprem_node() -> str:
    return nid("net", "on-premises")


def service_node(name: str) -> str:
    return nid("svc", name)


# ---------------------------------------------------------------------------
# flow model
# ---------------------------------------------------------------------------


@dataclass
class FlowEdge:
    """One arrow in the diagram."""

    src: str
    dst: str
    label: str = ""
    style: str = "-->"
    kind: str = "route"


@dataclass
class FlowModel:
    """Normalized routing + connectivity model handed to the renderer."""

    topo: Topology
    routing: Dict[str, SubnetRouting] = field(default_factory=dict)
    edges: List[FlowEdge] = field(default_factory=list)
    notes: Dict[str, List[str]] = field(default_factory=dict)
    traced: int = 0
    blocked: int = 0
    conditional: int = 0

    def note(self, node_id: str, text: str) -> None:
        if not text:
            return
        bucket = self.notes.setdefault(node_id, [])
        if text not in bucket:
            bucket.append(text)

    def edge(
        self,
        src: str,
        dst: str,
        label: str = "",
        style: str = "-->",
        kind: str = "route",
    ) -> None:
        if not src or not dst or src == dst:
            return
        for existing in self.edges:
            if existing.src == src and existing.dst == dst and existing.label == label:
                return
        self.edges.append(FlowEdge(src, dst, label, style, kind))

    def routing_for(self, subnet_id: str) -> SubnetRouting:
        return self.routing.get(subnet_id) or SubnetRouting(subnet_id=subnet_id)

    def edges_from(self, node_id: str) -> List[FlowEdge]:
        return [e for e in self.edges if e.src == node_id]


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


def build_flow_model(topo: Topology) -> FlowModel:
    """Derive the complete routing/connectivity model for the whole account."""
    model = FlowModel(topo=topo)
    for subnet in topo.subnets.values():
        model.routing[subnet.id] = classify_subnet(topo, subnet)

    _add_external(model)
    _add_subnet_egress(model)
    _add_tgw(model)
    _add_peering(model)
    _add_endpoints(model)
    _add_workload_paths(model)
    return model


def _add_external(model: FlowModel) -> None:
    """External networks and VPC-scoped gateways that sit outside subnets."""
    topo = model.topo

    for igw in topo.igws.values():
        node = nid("igw", igw.id)
        model.edge(internet_node(), node, "inbound", kind="wan")
        model.edge(node, internet_node(), "egress", kind="wan")

    # A VPN gateway reaches on-premises, not the internet. Only a VPN connection
    # whose routes include 0.0.0.0/0 actually carries internet-bound traffic, so
    # the internet leg is drawn for that case alone rather than for every VGW.
    for vgw in topo.vpn_gateways.values():
        node = nid("vgw", vgw.id)
        conns = [c for c in topo.vpn_connections.values() if c.vgw_id == vgw.id]
        tunnel = "Direct Connect" if _is_direct_connect(vgw.vpn_type) else "IPsec tunnel"
        model.edge(onprem_node(), node, tunnel, kind="wan")
        model.edge(node, onprem_node(), tunnel, kind="wan")
        if not conns and not vgw.vpc_id:
            model.note(node, f"not attached to any VPC · {vgw.id}")
        for conn in conns:
            model.note(node, f"{conn.vpn_type or 'ipsec.1'} → {conn.customer_gw_id or 'customer gateway'}")
            if any(r.strip() in ("0.0.0.0/0", "::/0") for r in (conn.routes or [])):
                model.edge(node, internet_node(), "0.0.0.0/0 → on-premises network", kind="wan")

    if topo.vpn_gateways or topo.vpn_connections:
        model.note(onprem_node(), "customer gateway / on-premises")

    # A transit gateway reaches the outside world only through the attachments
    # that actually exist on it. A TGW with nothing but VPC attachments has no
    # Direct Connect and no internet path, and drawing either would be a lie.
    for tgw in list(topo.tgws.values())[:MAX_TGWS]:
        node = nid("tgw", tgw.id)
        types = {a.resource_type for a in (tgw.attachments or [])}
        if "dx-gateway" in types:
            model.edge(onprem_node(), node, "Direct Connect", kind="wan")
            model.edge(node, onprem_node(), "Direct Connect", kind="wan")
        if "vpn" in types:
            model.edge(onprem_node(), node, "IPsec tunnel", kind="wan")
            model.edge(node, onprem_node(), "IPsec tunnel", kind="wan")
        if _tgw_carries_internet(tgw):
            model.edge(node, internet_node(), "0.0.0.0/0", kind="wan")
        model.note(node, f"{len(tgw.attachments or [])} attachment(s) · {len(tgw.route_tables or [])} route table(s)")


def _is_direct_connect(vpn_type: str) -> bool:
    """True for Direct Connect gateway types (``vgw``, ``dxgw``)."""
    t = (vpn_type or "").lower()
    return t.startswith("vgw") or t.startswith("dxgw") or t.startswith("dx")


def _tgw_carries_internet(tgw) -> bool:
    """True when some TGW route table sends 0.0.0.0/0 to a VPN or DX attachment."""
    outside = {"vpn", "dx-gateway"}
    for rtb in tgw.route_tables or []:
        att_by_id = {a.id: a for a in (tgw.attachments or [])}
        for route in rtb.routes or []:
            if route.destination.strip() not in ("0.0.0.0/0", "::/0"):
                continue
            att = att_by_id.get(route.attachment_id or route.target_id)
            if att is not None and att.resource_type in outside:
                return True
    return False


def _add_subnet_egress(model: FlowModel) -> None:
    """subnet -> route -> next hop, plus the IGW ingress leg into public subnets."""
    topo = model.topo

    for subnet in topo.subnets.values():
        info = model.routing[subnet.id]
        rtb = topo.rtb_for_subnet(subnet.id)
        if rtb is None:
            continue
        source = sid(subnet.id)

        for route in rtb.routes:
            if route.state != "active":
                continue
            kind = target_kind(route)
            if kind not in ("igw", "nat", "vgw"):
                continue
            label = route_label(route)

            if kind == "nat":
                nat = topo.nat_gateways.get(route.target_id)
                nat_node = nid("nat", route.target_id)
                model.edge(source, nat_node, label, kind="route")
                if nat is not None:
                    host = topo.subnets.get(nat.subnet_id or "")
                    # The NAT's subnet can be absent from the inventory (failed
                    # collection, or a cross-account reference), so never assume it.
                    if host is not None:
                        model.note(
                            nat_node,
                            f"{host.az or 'unknown AZ'} / {host.cidr or 'no CIDR'}",
                        )
                    else:
                        model.note(
                            nat_node, f"subnet {nat.subnet_id} not found in inventory"
                        )
                igw = topo.igw_for_vpc(subnet.vpc_id)
                if igw is not None:
                    model.edge(
                        nat_node, nid("igw", igw.id), "via public subnet", kind="route"
                    )
                continue

            if kind == "igw":
                igw_node = nid("igw", route.target_id)
                model.edge(source, igw_node, label, kind="route")
                if info.classification == PUBLIC:
                    model.edge(
                        igw_node, source, f"inbound to {subnet.cidr}", kind="route"
                    )
                    _add_ingress_endpoints(model, topo, subnet)
                continue

            # A route to a VPN gateway leaves for on-premises, so complete the
            # leg to the on-premises node instead of stopping at the gateway.
            # The vgw <-> on-premises tunnel edge is drawn once in _add_external,
            # so this stops at the gateway instead of duplicating that arrow.
            model.edge(source, nid("vgw", route.target_id), label, kind="route")


def _add_tgw(model: FlowModel) -> None:
    """VPC -> Transit Gateway -> destination subnet.

    A TGW route table entry describes traffic the gateway *delivers into* the
    attached VPC. The next hop for that traffic is therefore not in the TGW
    route table at all -- it comes from the destination VPC's own route table.
    So for every TGW route we run a longest-prefix match inside the attached
    VPC and only draw the leg when a real subnet route exists.
    """
    topo = model.topo

    for tgw in list(topo.tgws.values())[:MAX_TGWS]:
        tgw_node = nid("tgw", tgw.id)
        attachments = [a for a in tgw.attachments if a.resource_type == "vpc"]
        reached = 0

        for att in attachments:
            vpc_id = att.vpc_id or att.resource_id
            if not vpc_id:
                continue
            tgw_rtb = topo.tgw_route_table_for_attachment(att)
            if tgw_rtb is None:
                continue

            for subnet in topo.subnets_by_vpc.get(vpc_id, []):
                vpc_rtb = topo.rtb_for_subnet(subnet.id)
                if vpc_rtb is None:
                    continue

                # Longest-prefix match inside the destination VPC for each CIDR the
                # TGW is willing to deliver.
                for tgw_route in tgw_rtb.routes:
                    if tgw_route.state != "active":
                        continue
                    probe = _probe_ip(tgw_route.destination)
                    if probe is None:
                        continue
                    next_hop = vpc_rtb.route_for(probe)
                    if next_hop is None:
                        continue
                    kind = target_kind(next_hop)
                    if kind not in ("local", "igw", "nat"):
                        continue

                    label = f"{tgw_route.destination} from TGW\nvia {vpc_rtb.label}"
                    if kind == "local":
                        label += f"\n{next_hop.destination} local"
                    else:
                        label += f"\n{next_hop.destination} \u2192 {TARGET_PHRASE.get(kind, kind)}"

                    model.edge(tgw_node, sid(subnet.id), label, kind="transit")
                    reached += 1
                    break  # one arrow per subnet: the best-matching TGW route wins

        model.note(tgw_node, f"{len(attachments)} VPC attachment(s)")
        if attachments and not reached:
            model.note(tgw_node, "no TGW route table entry reaches a subnet here")


def _add_ingress_endpoints(model: FlowModel, topo: Topology, subnet: M.Subnet) -> None:
    """Complete the inbound chain: internet -> IGW -> subnet -> what answers there.

    An internet-facing load balancer in a public subnet is where inbound traffic
    actually terminates, so the arrow continues into it. The port comes from that
    load balancer's own security group, which is the only listener information
    the collected API surface provides.
    """
    for wl in topo.workloads_by_subnet.get(subnet.id, []):
        if wl.kind not in ("alb", "nlb", "gwlb", "lb"):
            continue
        if wl.extra.get("scheme") != "internet-facing":
            continue
        ports: List[int] = []
        for sg_id in wl.sg_ids:
            sg = topo.security_groups.get(sg_id)
            if sg is None:
                continue
            for rule in sg.ingress:
                if rule.protocol not in ("-1", "all", "6", "tcp"):
                    continue
                if rule.from_port > 0:
                    ports.append(rule.from_port)
        shown = ", ".join(f":{p}" for p in sorted(set(ports))[:3]) or "ingress"
        model.edge(sid(subnet.id), wid(wl.id), f"terminates here {shown}", kind="target")


def _more_specific(candidate: M.Route, current: M.Route) -> bool:
    """True when *candidate* has the longer prefix than *current*."""
    a = parse_net(candidate.destination)
    b = parse_net(current.destination)
    if a is None or b is None:
        return False
    return a.prefixlen > b.prefixlen


def _probe_ip(cidr: str) -> Optional[str]:
    """A representative address inside *cidr*, for longest-prefix-match lookups."""
    try:
        net = parse_net(cidr)
        if net is None:
            return None
        return str(net.network_address)
    except Exception:
        return None


def _add_peering(model: FlowModel) -> None:
    """Only show a peering leg when a route table actually points at the peering."""
    topo = model.topo

    for peer in list(topo.peerings.values())[:MAX_PEERINGS]:
        peer_node = nid("pcx", peer.id)
        local_vpcs = [v for v in (peer.local_vpc_ids or []) if v]
        if peer.vpc_id and peer.vpc_id not in local_vpcs:
            local_vpcs.append(peer.vpc_id)
        remote = peer.peer_vpc_id
        if not remote:
            continue

        shown = 0
        for src_vpc in local_vpcs:
            # Collect the peering's reachable CIDRs from every route table in the
            # local VPC, then keep only the most specific route per destination.
            reachable: Dict[str, M.Route] = {}
            for subnet in topo.subnets_by_vpc.get(src_vpc, []):
                rtb = topo.rtb_for_subnet(subnet.id)
                if rtb is None:
                    continue
                for route in rtb.routes:
                    if route.state != "active" or route.target_id != peer.id:
                        continue
                    current = reachable.get(route.destination)
                    if current is None or _more_specific(route, current):
                        reachable[route.destination] = route

            for dst in topo.subnets_by_vpc.get(remote, []):
                if not dst.cidr:
                    continue
                probe = _probe_ip(dst.cidr)
                best: Optional[M.Route] = None
                for dest_cidr, route in reachable.items():
                    if probe is None or not ip_in_net(probe, dest_cidr):
                        continue
                    if best is None or _more_specific(route, best):
                        best = route
                if best is None:
                    continue
                model.edge(
                    peer_node,
                    sid(dst.id),
                    f"{best.destination} \u2192 {dst.cidr}",
                    kind="transit",
                )
                shown += 1

        model.note(peer_node, f"{peer.status or 'unknown status'}")
        if not shown:
            model.note(peer_node, "no route uses this peering")


def _add_endpoints(model: FlowModel) -> None:
    topo = model.topo

    for endpoint in list(topo.endpoints.values())[:MAX_ENDPOINTS]:
        ep_node = nid("vpce", endpoint.id)
        service = endpoint.service_name or "aws service"
        for subnet in topo.subnets.values():
            if subnet.id not in (endpoint.subnet_ids or []):
                continue
            rtb = topo.rtb_for_subnet(subnet.id)
            if rtb is None:
                continue
            for route in rtb.routes:
                if route.state == "active" and route.target_id == endpoint.id:
                    model.edge(sid(subnet.id), ep_node, route_label(route), kind="route")
        model.edge(ep_node, service_node(service), service, kind="route")


def _sg_suffix(verdict: str) -> str:
    if verdict == BLOCKED:
        return "\nSG DENIES"
    if verdict == CONDITIONAL:
        return "\nSG conditional"
    return ""


def _add_workload_paths(model: FlowModel) -> None:
    """The 'story' arrows: load balancer -> target, and compute tier -> data tier."""
    topo = model.topo
    engine = PathEngine(topo)

    for wl in topo.workloads.values():
        if wl.kind not in ("alb", "nlb", "gwlb", "lb"):
            continue
        src_eni = topo.primary_ip_for_workload(wl)
        if src_eni is None:
            continue
        for target in (wl.extra.get("targets") or [])[:MAX_TARGETS_PER_LB]:
            self_dst = target.get("id") or ""
            if not self_dst:
                continue
            dst_eni = topo.enis.get(self_dst) or _eni_for_instance(topo, self_dst)
            tgt = topo.workloads.get(self_dst)
            if dst_eni is None:
                continue
            dst_subnet = topo.subnets.get(dst_eni.subnet_id)
            if dst_subnet is None:
                continue

            port_raw = target.get("port") or ""
            port = int(port_raw) if str(port_raw).isdigit() else None
            res = engine.resolve(
                src_eni.private_ip,
                src_eni.subnet_id,
                dst_eni.private_ip,
                dst_vpc_id=dst_subnet.vpc_id,
                dst_subnet_id=dst_subnet.id,
                dst_sg_ids=tgt.sg_ids if tgt is not None else [],
                port=port,
                with_reverse=False,
            )
            label = f"TCP :{port_raw}" if port_raw else "target group"
            label += f"\nvia {route_label(res.route)}{_sg_suffix(res.sg_verdict)}"
            _tally(model, res.sg_verdict)
            model.edge(
                wid(wl.id),
                wid(tgt.id if tgt is not None else self_dst),
                label,
                kind="target",
            )

    _add_tier_paths(model, engine)


def _eni_for_instance(topo: Topology, instance_id: str) -> Optional[M.Eni]:
    for eni in topo.enis.values():
        if eni.instance_id == instance_id and eni.private_ip:
            return eni
    return None


def _add_tier_paths(model: FlowModel, engine: PathEngine) -> None:
    topo = model.topo
    datastores = [w for w in topo.workloads.values() if w.kind == "rds"][:MAX_RDS_FOR_TIERS]
    if not datastores:
        return

    for src in [w for w in topo.workloads.values() if w.kind == "ec2"][:MAX_EC2_FOR_TIERS]:
        src_eni = topo.primary_ip_for_workload(src)
        if src_eni is None:
            continue
        src_subnet = topo.subnets.get(src_eni.subnet_id)
        if src_subnet is None:
            continue
        for dst in datastores:
            if dst.vpc_id != src_subnet.vpc_id:
                continue
            dst_eni = topo.primary_ip_for_workload(dst)
            if dst_eni is None:
                continue
            port = 5432 if "postgres" in (dst.engine or "").lower() else 3306
            res = engine.resolve(
                src_eni.private_ip,
                src_eni.subnet_id,
                dst_eni.private_ip,
                dst_vpc_id=dst.vpc_id,
                dst_subnet_id=dst_eni.subnet_id,
                dst_sg_ids=dst.sg_ids,
                port=port,
                with_reverse=False,
            )
            if res.route is None:
                continue
            label = f"TCP :{port}\nvia {route_label(res.route)}{_sg_suffix(res.sg_verdict)}"
            _tally(model, res.sg_verdict)
            model.edge(wid(src.id), wid(dst.id), label, kind="target")


def _tally(model: FlowModel, verdict: str) -> None:
    if verdict == BLOCKED:
        model.blocked += 1
    elif verdict == CONDITIONAL:
        model.conditional += 1
    else:
        model.traced += 1
