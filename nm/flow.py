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
    ``10.0.0.0/16 local`` authorizes traffic inside the VPC. It appears in the
    *label* of an intra-VPC arrow; it never becomes a fake gateway box.

Arrow labels name the route, never the destination
    The arrowhead already says where an arrow goes, so repeating the target in
    the label is noise. The one exception is ``local``, which names a mechanism
    rather than a node.

NACLs and security groups are never nodes
    They are metadata rendered inside the subnet / resource label. The only way
    a security group reaches the diagram is the ``security:`` field on a path
    edge -- ``allowed``, ``blocked``, or ``unknown``. It is stated on every path
    edge, including when the answer is ``allowed``: an unevaluated rule must not
    be indistinguishable from a permitted one.

One arrow per journey
    Each path is drawn once, in the direction traffic travels. A reverse arrow is
    only drawn when routing really supports it, not as a mirror for symmetry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import model as M
from .cidrutil import ip_in_net, is_default_route, parse_net
from .paths import (
    SG_ALLOWED,
    SG_BLOCKED,
    SG_UNKNOWN,
    PathEngine,
    security_status,
)
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
    """The route that explains why an arrow exists.

    Section 6: show the route, not the target. The arrow already points at the
    target node, so repeating "NAT Gateway" in the label is noise. ``local`` is
    kept because it names the mechanism (the VPC local route) rather than a node.
    """
    if route is None:
        return "no matching route"
    if target_kind(route) == "local":
        return f"{route.destination} local"
    return route.destination


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
    """External networks and the gateways that sit outside any subnet.

    Section 7: the diagram shows the logical journey, so every edge here is drawn
    once, in the direction traffic travels. A blanket INTERNET <-> IGW pair per
    gateway would be redundant *and* wrong -- the real inbound path is INTERNET ->
    IGW -> public subnet, and the real outbound path is subnet -> NAT -> IGW ->
    INTERNET, both of which are drawn from the subnets that actually have those
    routes.
    """
    topo = model.topo

    # An IGW is only reachable from the internet if a public subnet fronts it, and
    # only sends traffic out if something in the VPC egresses through it.
    for igw in topo.igws.values():
        node = nid("igw", igw.id)
        vpc_subnets = [x for x in topo.subnets.values() if x.vpc_id == igw.vpc_id]
        public_here = [
            x for x in vpc_subnets
            if model.routing_for(x.id).classification == PUBLIC
        ]
        if public_here:
            model.edge(
                internet_node(), node,
                f"inbound to {igw.vpc_id}", kind="wan",
            )
        egress = any(
            target_kind(r) == "nat"
            for x in vpc_subnets
            for r in (topo.rtb_for_subnet(x.id).routes if topo.rtb_for_subnet(x.id) else [])
        )
        if egress:
            model.edge(node, internet_node(), "egress", kind="wan")

    # A VPN gateway reaches on-premises, not the internet. Only a VPN connection
    # whose routes include 0.0.0.0/0 actually carries internet-bound traffic.
    for vgw in topo.vpn_gateways.values():
        node = nid("vgw", vgw.id)
        conns = [c for c in topo.vpn_connections.values() if c.vgw_id == vgw.id]
        tunnel = "Direct Connect" if _is_direct_connect(vgw.vpn_type) else "IPsec tunnel"
        # The subnet -> gateway -> on-premises leg continues from _add_subnet_egress.
        model.edge(node, onprem_node(), tunnel, kind="wan")
        if not conns and not vgw.vpc_id:
            model.note(node, f"not attached to any VPC · {vgw.id}")
        for conn in conns:
            model.note(
                node,
                f"{conn.vpn_type or 'ipsec.1'} → {conn.customer_gw_id or 'customer gateway'}",
            )
            if any(r.strip() in ("0.0.0.0/0", "::/0") for r in (conn.routes or [])):
                model.edge(
                    node, internet_node(),
                    "0.0.0.0/0 via on-premises network", kind="wan",
                )

    if topo.vpn_gateways or topo.vpn_connections:
        model.note(onprem_node(), "customer gateway / on-premises")

    # A transit gateway reaches the outside world only through the attachments
    # that actually exist on it. A TGW with nothing but VPC attachments has no
    # Direct Connect and no internet path, and drawing either would be a lie.
    for tgw in list(topo.tgws.values())[:MAX_TGWS]:
        node = nid("tgw", tgw.id)
        types = {a.resource_type for a in (tgw.attachments or [])}
        if "dx-gateway" in types:
            model.edge(node, onprem_node(), "Direct Connect", kind="wan")
        if "vpn" in types:
            model.edge(node, onprem_node(), "IPsec tunnel", kind="wan")
        if _tgw_carries_internet(tgw):
            model.edge(node, internet_node(), "0.0.0.0/0", kind="wan")
        model.note(
            node,
            f"{len(tgw.attachments or [])} attachment(s) · "
            f"{len(tgw.route_tables or [])} route table(s)",
        )


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
                    # The NAT's subnet can be absent from the inventory (failed
                    # collection, or a cross-account reference), so never assume
                    # it. When it *is* present the node already prints the
                    # location, so only the anomaly is worth a note.
                    if topo.subnets.get(nat.subnet_id or "") is None:
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

                    # Route-only: the arrow points at the subnet, so naming the
                    # next hop in the label would just repeat the arrow.
                    label = (
                        f"{tgw_route.destination} from TGW\nvia {vpc_rtb.label}"
                        f"\n{route_label(next_hop)}"
                    )

                    model.edge(tgw_node, sid(subnet.id), label, kind="transit")
                    reached += 1
                    break  # one arrow per subnet: the best-matching TGW route wins

        model.note(tgw_node, f"{len(attachments)} VPC attachment(s)")
        if attachments and not reached:
            model.note(tgw_node, "no TGW route table entry reaches a subnet here")


def _add_ingress_endpoints(model: FlowModel, topo: Topology, subnet: M.Subnet) -> None:
    """Complete the inbound chain: internet -> IGW -> subnet -> what answers there.

    An internet-facing load balancer in a public subnet is where inbound traffic
    actually terminates, so the arrow continues into it. The ports come from that
    load balancer's own security group, which is the only listener information the
    collected API surface provides.

    The security status is stated here too: matching a TCP ingress rule on the
    load balancer's SG *is* an evaluation, so the arrow says "allowed". When no
    rule could be read it says "unknown" rather than staying silent -- an absent
    label would read as "no opinion needed", which is how a blocked listener
    gets mistaken for a working one.
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
        if ports:
            shown = ", ".join(f":{p}" for p in sorted(set(ports))[:3])
            status = SG_ALLOWED
        else:
            shown = "ingress"
            status = SG_UNKNOWN
        model.edge(
            sid(subnet.id), wid(wl.id),
            f"terminates here {shown}\nsecurity: {status}", kind="target",
        )


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
    """Always state the security status on a path.

    Omitting it when the answer is "allowed" makes an unevaluated rule look
    identical to a permitted one, which is the exact confusion section 16 warns
    about. Three states only: allowed, blocked, unknown.
    """
    return f"\nsecurity: {security_status(verdict)}"


class ResolvedTarget:
    """Where one registered target group target actually lands.

    ``node`` is the flow node id to point at, or None when the target resolves
    to no addressable resource (a Lambda target, or an IP we cannot place).
    """
    node: Optional[str] = None
    eni: Optional[M.Eni] = None
    workload: Optional[M.Workload] = None
    ip: str = ""
    note: str = ""


def _resolve_target(topo: Topology, target: Dict[str, Any]) -> ResolvedTarget:
    """Resolve one target group registration to a node.

    The registration is the authoritative relationship. Nothing here infers
    reachability from co-location: a target is drawn because it is registered,
    not because it shares a VPC, subnet, route table or security group.
    """
    out = ResolvedTarget()
    target_id = str(target.get("id") or "")
    if not target_id:
        out.note = "no target id"
        return out
    kind = (target.get("type") or "instance").lower()

    if kind == "instance":
        eni = topo.enis.get(target_id) or _eni_for_instance(topo, target_id)
        wl = topo.workloads.get(target_id)
        if wl is None and eni is not None and eni.workload_id:
            wl = topo.workloads.get(eni.workload_id)
        if eni is None:
            out.note = f"instance {target_id} has no collected ENI"
            return out
        out.eni, out.workload, out.ip = eni, wl, eni.private_ip
        out.node = wid(wl.id) if wl is not None else wid(target_id)
        return out

    if kind in ("ip", "instance-ip"):
        # An IP target is just an address; find the interface that holds it.
        eni = topo.enis_by_ip.get(target_id)
        if eni is None:
            out.ip = target_id
            out.node = f"ip_{target_id.replace('.', '_').replace(':', '_')}"
            out.note = "IP target with no matching ENI"
            return out
        out.eni, out.ip = eni, eni.private_ip
        out.workload = topo.workloads.get(eni.workload_id) if eni.workload_id else None
        out.node = (
            wid(out.workload.id)
            if out.workload is not None
            else f"ip_{target_id.replace('.', '_')}"
        )
        return out

    if kind == "ecs":
        # The target id is "container:port"; the service owns the task ENIs.
        name = target_id.split(":", 1)[0]
        for wl in topo.workloads.values():
            if wl.kind == "ecs-service" and wl.name == name:
                out.workload = wl
                out.node = wid(wl.id)
                out.ip = (wl.extra.get("task_ips") or [""])[0]
                out.eni = _eni_for_instance(topo, out.ip) if out.ip else None
                if out.eni is None:
                    for e in topo.enis.values():
                        if e.private_ip == out.ip:
                            out.eni = e
                            break
                if not wl.extra.get("running_tasks"):
                    out.note = "no running tasks"
                return out
        out.note = f"ECS service {name} not collected"
        return out

    if kind == "lambda":
        # The registration carries the function ARN, but be tolerant of a name.
        wl = topo.workloads.get(target_id) or next(
            (w for w in topo.workloads.values()
             if w.kind == "lambda" and w.name == target_id),
            None,
        )
        out.workload = wl
        out.node = wid(wl.id) if wl is not None else wid(target_id)
        if wl is None:
            out.note = f"Lambda {target_id} is not in the inventory"
            return out
        # A function reached through an ALB has a VPC ENI, so the path is
        # routable. Without one there is genuinely no path to draw, and saying
        # so beats inventing an address.
        eni = None
        for eid in (wl.eni_ids or []):
            candidate = topo.enis.get(eid)
            if candidate is not None and candidate.private_ip:
                eni = candidate
                break
        if eni is None:
            eni = next(
                (e for e in topo.enis.values()
                 if e.private_ip and e.subnet_id in (wl.subnet_ids or [])),
                None,
            )
        if eni is None:
            out.note = "Lambda has no VPC ENI in the inventory; no route is drawn"
            return out
        out.eni, out.ip = eni, eni.private_ip
        return out

    out.note = f"unsupported target type {kind!r}"
    return out


def _add_workload_paths(model: FlowModel) -> None:
    """The 'story' arrows: load balancer -> registered target, and tier paths.

    Every arrow here originates from a real target group registration. The
    listener supplies the client-facing port and protocol; the label carries the
    target group by name so the relationship is legible without a target group
    node of its own.
    """
    topo = model.topo
    engine = PathEngine(topo)

    for wl in topo.workloads.values():
        if wl.kind not in ("alb", "nlb", "gwlb", "lb"):
            continue
        src_eni = topo.primary_ip_for_workload(wl)
        if src_eni is None:
            continue
        for target in (wl.extra.get("targets") or [])[:MAX_TARGETS_PER_LB]:
            resolved = _resolve_target(topo, target)
            if resolved.note:
                model.note(wid(wl.id), f"target {target.get('id', '?')}: {resolved.note}")
            if resolved.node is None:
                continue

            listeners = target.get("listeners") or []
            front = _primary_listener(listeners)
            port_txt = f":{front['port']}" if front and front.get("port") else ""
            proto = front.get("protocol") if front else ""
            front_label = f"{proto}{port_txt}".strip() if front else ""
            tg_name = target.get("target_group") or ""

            res = None
            if src_eni.private_ip and resolved.ip:
                res = engine.resolve(
                    src_eni.private_ip,
                    src_eni.subnet_id,
                    resolved.ip,
                    dst_vpc_id=resolved.eni.vpc_id if resolved.eni else "",
                    dst_subnet_id=resolved.eni.subnet_id if resolved.eni else "",
                    dst_sg_ids=resolved.workload.sg_ids if resolved.workload else [],
                    port=_int_or(target.get("port"), None),
                    with_reverse=False,
                )

            label = front_label or (f"TCP :{target['port']}" if target.get("port") else "")
            if tg_name:
                label = f"{label}\nTG: {tg_name}" if label else f"TG: {tg_name}"
            if res is not None:
                label += f"\n{route_label(res.route)}"
                label += _sg_suffix(res.sg_verdict)
                _tally(model, res.sg_verdict)
            model.edge(wid(wl.id), resolved.node, label, kind="target")

    _add_tier_paths(model, engine)


TLS_PROTOCOLS = ("HTTPS", "TLS", "TCP_TLS", "SSL", "TCP-SSL")


def _primary_listener(listeners: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Pick the listener that represents the load balancer's real entry point.

    An internet-facing ALB normally has both :80 and :443 forwarding to the same
    group. Alphabetical order would pick HTTP, which is the wrong one to headline.
    Prefer a TLS listener, then the highest port, then the lowest.
    """
    if not listeners:
        return None

    def key(ln: Dict[str, Any]):
        proto = str(ln.get("protocol") or "")
        secure = 0 if proto.upper() in TLS_PROTOCOLS else 1
        return (secure, -_int_or(ln.get("port"), 0))

    return sorted(listeners, key=key)[0]


def _int_or(value: Any, fallback: Any) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


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
            label = f"TCP :{port}\n{route_label(res.route)}{_sg_suffix(res.sg_verdict)}"
            _tally(model, res.sg_verdict)
            model.edge(wid(src.id), wid(dst.id), label, kind="target")


def _tally(model: FlowModel, verdict: str) -> None:
    """Count paths by security status so the summary can report all three."""
    status = security_status(verdict)
    if status == SG_BLOCKED:
        model.blocked += 1
    elif status == SG_UNKNOWN:
        model.conditional += 1
    else:
        model.traced += 1
