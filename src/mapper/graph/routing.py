"""Route-table + security-group path evaluation.

The engine answers "can traffic actually flow here?" and, just as importantly,
"why not?". Every hop is recorded so the result can be rendered as a diagram
or pasted into an audit report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .. import model as M
from ..util.cidr import (
    ip_in_net,
    longest_prefix_match,
    nets_overlap,
    parse_ip,
    parse_net,
)
from ..model import Eni, Route, RouteTable, Subnet, Vpc, Workload
from . import Topology

# verdicts
REACHABLE = "reachable"
BLOCKED = "blocked"
CONDITIONAL = "conditional"
UNKNOWN = "unknown"
NOT_APPLICABLE = "n/a"

# Security status shown on a path. Deliberately three values, not four:
# a rule we could not evaluate must read as UNKNOWN, never as anything that
# could be mistaken for a decision. "conditional" is a reachability notion and
# collapses into UNKNOWN here on purpose.
SG_ALLOWED = "allowed"
SG_BLOCKED = "blocked"
SG_UNKNOWN = "unknown"


def security_status(sg_verdict: str) -> str:
    """Map an internal verdict onto the three security statuses we publish."""
    if sg_verdict == BLOCKED:
        return SG_BLOCKED
    if sg_verdict == REACHABLE:
        return SG_ALLOWED
    return SG_UNKNOWN

PRIVATE_V4 = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
)


def is_private(ip: str) -> bool:
    return any(ip_in_net(ip, c) for c in PRIVATE_V4)


@dataclass
class Hop:
    kind: str
    id: str
    label: str
    detail: str = ""


@dataclass
class PathResult:
    src: str
    dst: str
    verdict: str = UNKNOWN
    hops: List[Hop] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    route: Optional[Route] = None
    sg_verdict: str = NOT_APPLICABLE
    reverse: Optional["PathResult"] = None

    @property
    def asymmetric(self) -> bool:
        if self.reverse is None:
            return False
        return self.reverse.verdict != self.verdict

    @property
    def reachable(self) -> bool:
        return self.verdict == REACHABLE

    def add(self, kind: str, id_: str, label: str, detail: str = "") -> None:
        self.hops.append(Hop(kind, id_, label, detail))

    def note(self, msg: str) -> None:
        self.reasons.append(msg)


class PathEngine:
    def __init__(self, topo: Topology):
        self.t = topo

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------
    def resolve(
        self,
        src_ip: str,
        src_subnet_id: str,
        dst_ip: str,
        *,
        dst_vpc_id: str = "",
        dst_subnet_id: str = "",
        dst_sg_ids: Sequence[str] = (),
        port: Optional[int] = None,
        with_reverse: bool = True,
        with_sg: bool = True,
    ) -> PathResult:
        src_subnet = self.t.subnets.get(src_subnet_id)
        dst_subnet = self.t.subnets.get(dst_subnet_id) or None
        src_vpc_id = src_subnet.vpc_id if src_subnet else ""
        res = PathResult(src=src_ip, dst=dst_ip)
        res.add("source", src_subnet_id, src_subnet.name if src_subnet else src_subnet_id, src_ip)

        if not src_subnet:
            res.verdict = UNKNOWN
            res.note(f"source subnet {src_subnet_id} not in inventory")
            return res

        if not dst_vpc_id and dst_subnet:
            dst_vpc_id = dst_subnet.vpc_id

        if dst_ip and not dst_subnet and not dst_vpc_id:
            guess = self.t.subnet_for_ip(dst_ip)
            if guess:
                dst_subnet = guess
                dst_vpc_id = guess.vpc_id

        rtb = self.t.rtb_for_subnet(src_subnet_id)
        if rtb is None:
            res.verdict = BLOCKED
            res.note(f"no effective route table for subnet {src_subnet_id}")
            return res
        res.add("route-table", rtb.id, rtb.label, f"{len(rtb.routes)} routes")

        self._walk(res, src_ip, src_subnet, rtb, dst_ip, dst_vpc_id, dst_subnet)

        if with_reverse:
            back = self._reverse(res, src_ip, src_subnet, dst_ip, dst_subnet, dst_vpc_id, dst_sg_ids, port)
            res.reverse = back

        if with_sg and port:
            self._apply_sg(res, src_ip, src_subnet, dst_ip, dst_subnet, dst_sg_ids, port)

        return res

    def _reverse(
        self,
        res: PathResult,
        src_ip: str,
        src_subnet: Subnet,
        dst_ip: str,
        dst_subnet: Optional[Subnet],
        dst_vpc_id: str,
        dst_sg_ids: Sequence[str],
        port: Optional[int],
    ) -> Optional[PathResult]:
        if not dst_subnet or not dst_ip:
            return None
        try:
            return self.resolve(
                dst_ip,
                dst_subnet.id,
                src_ip,
                dst_vpc_id=src_subnet.vpc_id,
                dst_subnet_id=src_subnet.id,
                port=port,
                with_reverse=False,
                with_sg=False,
            )
        except Exception:  # noqa: BLE001 - reverse path is best effort
            return None

    # ------------------------------------------------------------------
    # route walking
    # ------------------------------------------------------------------
    def _walk(
        self,
        res: PathResult,
        src_ip: str,
        src_subnet: Subnet,
        rtb: RouteTable,
        dst_ip: str,
        dst_vpc_id: str,
        dst_subnet: Optional[Subnet],
    ) -> None:
        vpc = self.t.vpcs.get(src_subnet.vpc_id)
        route = rtb.route_for(dst_ip)
        res.route = route

        # local route to the VPC's own CIDRs
        if route is not None and route.target_kind == M.T_LOCAL:
            res.add("local", "local", "local route", route.destination)
            if not dst_ip:
                res.verdict = CONDITIONAL
                res.note("destination not specified")
                return
            target_subnet = dst_subnet
            if target_subnet is None and vpc:
                target_subnet = self._subnet_in_vpc(src_subnet.vpc_id, dst_ip)
            if target_subnet is None:
                res.verdict = BLOCKED
                res.note(
                    f"{dst_ip} matches the local route ({route.destination}) but falls inside no "
                    f"subnet of VPC {vpc.id if vpc else src_subnet.vpc_id}"
                )
                return
            res.add("subnet", target_subnet.id, target_subnet.name, target_subnet.cidr)
            if target_subnet.id == src_subnet.id:
                res.verdict = REACHABLE
                return
            res.verdict = REACHABLE
            res.note(
                "intra-VPC traffic is subject to network ACLs and security groups, "
                "not routing"
            )
            return

        if route is None:
            res.verdict = BLOCKED
            res.note(f"no route in {rtb.id} matches {dst_ip}")
            return

        if route.state == "blackhole":
            res.verdict = BLOCKED
            res.note(f"route {route.destination} -> {route.target_id} is in blackhole state")
            return

        target_kind = route.target_kind
        if target_kind == M.T_INTERNET:
            self._walk_igw(res, src_subnet, route, src_ip, dst_ip)
        elif target_kind == M.T_NAT:
            self._walk_nat(res, src_subnet, route, dst_ip)
        elif target_kind == M.T_TGW:
            self._walk_tgw(res, src_subnet, route, dst_ip, dst_vpc_id, dst_subnet)
        elif target_kind == M.T_PEERING:
            self._walk_peering(res, src_subnet, route, dst_ip, dst_vpc_id, dst_subnet)
        elif target_kind == M.T_VGW:
            self._walk_vgw(res, src_subnet, route)
        elif target_kind == M.T_ENI:
            self._walk_eni(res, route, dst_ip)
        elif target_kind == M.T_ENDPOINT:
            self._walk_endpoint(res, route, dst_ip)
        elif target_kind == M.T_EIGW:
            res.add("egress-only-igw", route.target_id, route.target_id, "IPv6 outbound")
            if is_private(dst_ip) or parse_ip(dst_ip).version == 4:
                res.verdict = BLOCKED
                res.note("egress-only IGW cannot route IPv4")
            else:
                res.verdict = REACHABLE
                res.note("IPv6 egress via egress-only internet gateway")
        elif target_kind in (M.T_CARRIER_GW, M.T_LOCAL_GW, M.T_CORE_NETWORK, M.T_UNKNOWN, M.T_INSTANCE):
            res.add(target_kind, route.target_id, route.target_id, route.destination)
            res.verdict = UNKNOWN
            res.note(
                f"route target type '{target_kind}' is not evaluated automatically - verify manually"
            )
        else:
            res.verdict = UNKNOWN
            res.note(f"unhandled route target kind {target_kind}")

    def _subnet_in_vpc(self, vpc_id: str, ip: str) -> Optional[Subnet]:
        for subnet in self.t.subnets_by_vpc.get(vpc_id, []):
            if ip_in_net(ip, subnet.cidr):
                return subnet
        return None

    # -- individual target kinds ----------------------------------------
    def _walk_igw(self, res: PathResult, src_subnet: Subnet, route: Route, src_ip: str, dst_ip: str) -> None:
        igw = self.t.igws.get(route.target_id)
        res.add("igw", route.target_id, igw.name if igw else route.target_id, route.destination)
        if not igw or not igw.attached:
            res.verdict = BLOCKED
            res.note(f"internet gateway {route.target_id} is not attached to a VPC")
            return
        if dst_ip and is_private(dst_ip):
            res.verdict = BLOCKED
            res.note(
                f"{dst_ip} is an RFC1918 address; an internet gateway cannot reach private space"
            )
            return
        res.add("internet", "internet", "Internet", "public destination")
        enis = self.t.enis_by_subnet.get(src_subnet.id, [])
        if not any(e.public_ip for e in enis):
            res.verdict = CONDITIONAL
            res.note(
                "no ENI with a public IP in this subnet: outbound internet requires a public "
                "address, a NAT gateway, or IPv6 egress"
            )
        else:
            res.verdict = REACHABLE
        if dst_ip and enis and not all(e.public_ip for e in enis if e.primary):
            res.note("hairpin: instances without public IPs cannot use IGW for return traffic")

    def _walk_nat(self, res: PathResult, src_subnet: Subnet, route: Route, dst_ip: str) -> None:
        nat = self.t.nat_gateways.get(route.target_id)
        nat_subnet = self.t.subnets.get(nat.subnet_id) if nat else None
        res.add("nat", route.target_id, nat.name if nat else route.target_id, route.destination)
        if not nat:
            res.verdict = BLOCKED
            res.note(f"NAT gateway {route.target_id} not found in inventory")
            return
        if nat.state != "available":
            res.verdict = BLOCKED
            res.note(f"NAT gateway {route.target_id} state is '{nat.state}'")
            return
        if not nat_subnet:
            res.verdict = BLOCKED
            res.note("NAT gateway subnet not in inventory")
            return
        nat_rtb = self.t.rtb_for_subnet(nat_subnet.id)
        if not nat_rtb:
            res.verdict = BLOCKED
            res.note(f"NAT gateway subnet {nat_subnet.id} has no effective route table")
            return
        res.add("subnet", nat_subnet.id, f"{nat_subnet.name} (NAT AZ)", nat_subnet.cidr)
        res.add("route-table", nat_rtb.id, f"{nat_rtb.label} (NAT AZ)", "")
        egress = nat_rtb.route_for("8.8.8.8")
        if egress is None:
            res.verdict = BLOCKED
            res.note("NAT gateway subnet has no default route")
            return
        if egress.target_kind == M.T_NAT:
            res.verdict = BLOCKED
            res.note("NAT gateway subnet default route points at another NAT gateway")
            return
        if egress.target_kind != M.T_INTERNET:
            res.verdict = CONDITIONAL
            res.note(
                f"NAT gateway subnet default route points at '{egress.target_kind}' "
                f"({egress.target_id}), not an internet gateway"
            )
        else:
            igw = self.t.igws.get(egress.target_id)
            res.add("igw", egress.target_id, igw.name if igw else egress.target_id, "0.0.0.0/0")
            if not igw or not igw.attached:
                res.verdict = BLOCKED
                res.note("internet gateway used by the NAT gateway is not attached")
                return
            res.add("internet", "internet", "Internet", "via NAT")
        if dst_ip and is_private(dst_ip):
            res.verdict = BLOCKED
            res.note("NAT gateway cannot reach RFC1918 destinations")
            return
        if res.verdict != BLOCKED:
            res.verdict = REACHABLE
            res.note("outbound via NAT gateway; inbound requires public IP or port forwarding")

    def _walk_tgw(
        self,
        res: PathResult,
        src_subnet: Subnet,
        route: Route,
        dst_ip: str,
        dst_vpc_id: str,
        dst_subnet: Optional[Subnet],
    ) -> None:
        tgw = self.t.tgws.get(route.target_id)
        res.add("tgw", route.target_id, tgw.label if tgw else route.target_id, route.destination)
        if not tgw:
            res.verdict = BLOCKED
            res.note(f"transit gateway {route.target_id} not found in inventory")
            return
        att = self._attachment(tgw, src_subnet.vpc_id)
        if not att:
            res.verdict = BLOCKED
            res.note(f"VPC {src_subnet.vpc_id} has no attachment to {tgw.id}")
            return
        res.add("tgw-attachment", att.id, f"{tgw.label} attachment", att.state)
        if att.state and att.state not in ("available",):
            res.verdict = BLOCKED
            res.note(f"TGW attachment state is '{att.state}'")
            return
        rtb = self.t.tgw_route_table_for_attachment(att)
        if not rtb:
            res.verdict = UNKNOWN
            res.note(f"could not resolve a TGW route table for attachment {att.id}")
            return
        res.add("tgw-route-table", rtb.id, rtb.name or rtb.id, "")
        tgw_route = self._tgw_route_for(rtb, dst_ip)
        if tgw_route is None:
            res.verdict = BLOCKED
            res.note(f"no route in TGW route table {rtb.id} matches {dst_ip}")
            return
        res.add(
            "tgw-route",
            tgw_route.destination,
            f"{tgw_route.destination} -> {tgw_route.target_id}",
            tgw_route.state,
        )
        if tgw_route.state == "blackhole":
            res.verdict = BLOCKED
            res.note(f"TGW route {tgw_route.destination} is blackholed")
            return
        target_att = self._attachment_by_id(tgw, tgw_route.target_id)
        if tgw_route.target_id == att.id:
            res.verdict = BLOCKED
            res.note("TGW route points back at the source attachment (hairpin unsupported)")
            return
        if not target_att:
            res.verdict = CONDITIONAL
            res.note(
                f"TGW route targets {tgw_route.target_kind} {tgw_route.target_id}, which is not "
                "a VPC attachment in this inventory (could be cross-region peering / on-prem)"
            )
            if dst_ip and is_private(dst_ip):
                res.note("destination is private space; confirm the remote side routing")
            return
        target_vpc_id = target_att.resource_id
        remote_vpc = self.t.vpcs.get(target_vpc_id)
        res.add("vpc", target_vpc_id, remote_vpc.label if remote_vpc else target_vpc_id, "remote VPC")
        self._remote_return(res, target_vpc_id, target_att, dst_ip, dst_subnet, src_subnet, tgw)

    def _remote_return(
        self,
        res: PathResult,
        target_vpc_id: str,
        target_att: M.TgwAttachment,
        dst_ip: str,
        dst_subnet: Optional[Subnet],
        src_subnet: Subnet,
        tgw: M.Tgw,
    ) -> None:
        """The destination VPC needs its own route back towards the source."""
        if target_vpc_id == src_subnet.vpc_id:
            res.verdict = REACHABLE
            res.note("same VPC; loopback through the TGW is not required")
            return
        if target_att.cidr_blocks and src_subnet.cidr:
            if not any(
                ip_in_net(src_subnet.cidr.split("/")[0], c) or nets_overlap(src_subnet.cidr, c)
                for c in target_att.cidr_blocks
            ):
                res.note(
                    f"source subnet CIDR {src_subnet.cidr} is outside the attachment CIDR "
                    f"{', '.join(target_att.cidr_blocks)}"
                )
        target_rtb: Optional[RouteTable] = None
        if dst_subnet:
            target_rtb = self.t.rtb_for_subnet(dst_subnet.id)
        if target_rtb:
            res.add("route-table", target_rtb.id, f"{target_rtb.label} (remote)", "")
            back = target_rtb.route_for(src_subnet.cidr.split("/")[0])
            if back is None:
                res.verdict = BLOCKED
                res.note(
                    f"remote route table {target_rtb.id} has no route back to "
                    f"{src_subnet.cidr} (missing VPC route to the transit gateway)"
                )
                return
            res.add("rtb-route", back.destination, f"{back.destination} -> {back.target_id}", "")
            if back.target_kind not in (M.T_TGW, M.T_PEERING):
                res.verdict = BLOCKED
                res.note(
                    f"remote route {back.destination} points at {back.target_kind} "
                    f"{back.target_id}, not the transit gateway"
                )
                return
            res.verdict = REACHABLE
        else:
            matching = [
                rt
                for rt in self.t.rtbs_by_vpc.get(target_vpc_id, [])
                if rt.route_for(src_subnet.cidr.split("/")[0]) is not None
            ]
            if not matching:
                res.verdict = BLOCKED
                res.note(
                    f"no route table in the destination VPC routes back to {src_subnet.cidr}; "
                    f"missing {src_subnet.vpc_id} -> {tgw.id} VPC route"
                )
            else:
                res.verdict = CONDITIONAL
                res.note(
                    "destination subnet unknown; reachability depends on the destination "
                    f"subnet's route table (destination VPC has {len(matching)} matching route "
                    "tables)"
                )

    def _walk_peering(
        self,
        res: PathResult,
        src_subnet: Subnet,
        route: Route,
        dst_ip: str,
        dst_vpc_id: str,
        dst_subnet: Optional[Subnet],
    ) -> None:
        pcx = self.t.peerings.get(route.target_id)
        res.add(
            "peering",
            route.target_id,
            pcx.name if pcx else route.target_id,
            route.destination,
        )
        if not pcx:
            res.verdict = BLOCKED
            res.note(f"peering connection {route.target_id} not found")
            return
        if pcx.status not in ("active",):
            res.verdict = BLOCKED
            res.note(f"peering connection status is '{pcx.status}'")
            return
        peer_vpc = self.t.vpcs.get(pcx.peer_vpc_id)
        if pcx.intra_region:
            res.add("vpc", pcx.peer_vpc_id, peer_vpc.label if peer_vpc else pcx.peer_vpc_id, "peer VPC")
        else:
            res.add("region", pcx.peer_region, pcx.peer_region or "unknown", "cross-region peering")
            if pcx.peer_region not in self.t.regions:
                res.verdict = CONDITIONAL
                res.note(
                    f"peer region {pcx.peer_region} was not scanned - verify return routing there"
                )
                return
            peer_vpc = self.t.vpcs.get(pcx.peer_vpc_id)
            if not peer_vpc:
                res.verdict = CONDITIONAL
                res.note(f"peer VPC {pcx.peer_vpc_id} not in inventory")
                return
        peer_cidrs = self.t.vpc_cidrs(pcx.peer_vpc_id)
        if peer_cidrs and dst_ip and not any(ip_in_net(dst_ip, c) for c in peer_cidrs):
            res.verdict = BLOCKED
            res.note(
                f"{dst_ip} is outside the peer VPC CIDRs ({', '.join(peer_cidrs)})"
            )
            return
        peer_rtb = self.t.rtb_for_subnet(dst_subnet.id) if dst_subnet else None
        if peer_rtb:
            back = peer_rtb.route_for(src_subnet.cidr.split("/")[0])
            res.add("route-table", peer_rtb.id, f"{peer_rtb.label} (peer)", "")
            if back is None:
                res.verdict = BLOCKED
                res.note(f"peer route table {peer_rtb.id} has no route back to {src_subnet.cidr}")
                return
            res.add("rtb-route", back.destination, f"{back.destination} -> {back.target_id}", "")
            res.verdict = REACHABLE
        elif peer_vpc:
            if any(
                rt.route_for(src_subnet.cidr.split("/")[0]) is not None
                for rt in self.t.rtbs_by_vpc.get(pcx.peer_vpc_id, [])
            ):
                res.verdict = CONDITIONAL
                res.note("destination subnet unknown; depends on the peer subnet's route table")
            else:
                res.verdict = BLOCKED
                res.note(
                    f"peer VPC {pcx.peer_vpc_id} has no route back to {src_subnet.cidr}"
                )
        else:
            res.verdict = CONDITIONAL
            res.note("peer VPC route table not evaluated")

    def _walk_vgw(self, res: PathResult, src_subnet: Subnet, route: Route) -> None:
        vgw = self.t.vpn_gateways.get(route.target_id)
        res.add("vgw", route.target_id, vgw.name if vgw else route.target_id, route.destination)
        conns = [c for c in self.t.vpn_connections.values() if c.vgw_id == route.target_id]
        for conn in conns:
            res.add("vpn", conn.id, conn.id, conn.state)
        if not conns:
            res.verdict = BLOCKED
            res.note(f"no VPN connection attached to {route.target_id}")
            return
        active = [c for c in conns if c.state == "available"]
        if not active:
            res.verdict = BLOCKED
            res.note("all VPN connections are down: " + ", ".join(sorted({c.state for c in conns})))
            return
        res.add("onprem", "on-prem", "On-premises / DX", "via VPN")
        res.verdict = REACHABLE
        if route.origin == "EnableVgwPropagation":
            res.note("route came from VGW propagation")

    def _walk_eni(self, res: PathResult, route: Route, dst_ip: str) -> None:
        eni = self.t.enis.get(route.target_id)
        res.add("eni", route.target_id, eni.label if eni else route.target_id, route.destination)
        if eni is None:
            res.verdict = UNKNOWN
            res.note(f"network interface {route.target_id} not in inventory")
            return
        if dst_ip and eni.private_ip and dst_ip != eni.private_ip:
            res.verdict = BLOCKED
            res.note(f"route targets ENI private IP {eni.private_ip}, not {dst_ip}")
            return
        if eni.workload_kind:
            res.add(eni.workload_kind, eni.workload_id, eni.workload_name, "")
        res.verdict = REACHABLE

    def _walk_endpoint(self, res: PathResult, route: Route, dst_ip: str) -> None:
        ep = self.t.endpoints.get(route.target_id)
        res.add(
            "vpc-endpoint",
            route.target_id,
            ep.short_service if ep else route.target_id,
            route.destination,
        )
        if not ep:
            res.verdict = UNKNOWN
            res.note(f"vpc endpoint {route.target_id} not in inventory")
            return
        if ep.state not in ("available",):
            res.verdict = BLOCKED
            res.note(f"vpc endpoint state is '{ep.state}'")
            return
        if ep.vpc_endpoint_type in ("Gateway",):
            res.add("service", ep.service_name, ep.short_service, "prefix list")
            res.verdict = REACHABLE
            res.note("gateway endpoint routes via prefix list, service IPs are not in the inventory")
            return
        res.verdict = CONDITIONAL
        res.note(
            f"interface endpoint: only traffic to the endpoint's own ENIs "
            f"({len(ep.subnet_ids)} subnets) is deliverable through it"
        )
        if ep.policy == "allow-all":
            res.note("endpoint policy allows all resources/principals")

    # -- TGW helpers ------------------------------------------------------
    def _attachment(self, tgw: M.Tgw, vpc_id: str) -> Optional[M.TgwAttachment]:
        for a in tgw.attachments:
            if a.resource_type == "vpc" and a.resource_id == vpc_id:
                return a
        return None

    @staticmethod
    def _attachment_by_id(tgw: M.Tgw, attachment_id: str) -> Optional[M.TgwAttachment]:
        for a in tgw.attachments:
            if a.id == attachment_id or a.resource_id == attachment_id:
                return a
        return None

    @staticmethod
    def _tgw_route_for(rtb: M.TgwRouteTable, ip: str) -> Optional[M.TgwRoute]:
        dest = longest_prefix_match((r.destination for r in rtb.routes), ip)
        if dest is None:
            return None
        for r in rtb.routes:
            if r.destination == dest:
                return r
        return None

    # ------------------------------------------------------------------
    # security groups
    # ------------------------------------------------------------------
    def _apply_sg(
        self,
        res: PathResult,
        src_ip: str,
        src_subnet: Subnet,
        dst_ip: str,
        dst_subnet: Optional[Subnet],
        dst_sg_ids: Sequence[str],
        port: int,
    ) -> None:
        src_sg_ids: List[str] = []
        for eni in self.t.enis_by_subnet.get(src_subnet.id, []):
            if eni.private_ip == src_ip or not src_ip:
                src_sg_ids.extend(eni.sg_ids)
        src_sg_ids = sorted(set(src_sg_ids))
        if not src_sg_ids:
            # fall back to every ENI in the subnet
            for eni in self.t.enis_by_subnet.get(src_subnet.id, []):
                src_sg_ids.extend(eni.sg_ids)
            src_sg_ids = sorted(set(src_sg_ids))
        if not dst_sg_ids:
            eni = self.t.eni_for_ip(dst_ip)
            if eni:
                dst_sg_ids = eni.sg_ids
        egress_ok, egress_why = self._sg_side(
            src_sg_ids, src_ip, dst_ip, port, egress=True
        )
        ingress_ok, ingress_why = self._sg_side(
            list(dst_sg_ids), dst_ip, src_ip, port, egress=False
        )
        parts = []
        if egress_ok is False:
            parts.append(f"blocked by egress: {egress_why}")
        if ingress_ok is False:
            parts.append(f"blocked by ingress: {ingress_why}")
        if parts:
            res.sg_verdict = BLOCKED
            for p in parts:
                res.note(p)
            if res.verdict == REACHABLE:
                res.verdict = REACHABLE
                res.note("route exists; security groups still block this flow")
        elif egress_ok is None or ingress_ok is None:
            res.sg_verdict = CONDITIONAL
            res.note(
                "security groups could not be fully evaluated "
                f"({egress_why or ingress_why})"
            )
        else:
            res.sg_verdict = REACHABLE

    def _sg_side(
        self,
        sg_ids: Sequence[str],
        self_ip: str,
        peer_ip: str,
        port: int,
        egress: bool,
    ) -> Tuple[Optional[bool], str]:
        if not sg_ids:
            return None, "no security group found on the interface"
        peer_sg_ids: List[str] = []
        peer_eni = self.t.eni_for_ip(peer_ip)
        if peer_eni:
            peer_sg_ids = peer_eni.sg_ids
        for sg_id in sg_ids:
            sg = self.t.security_groups.get(sg_id)
            if sg is None:
                continue
            rules = sg.egress if egress else sg.ingress
            for rule in rules:
                if self._rule_matches(rule, peer_ip, peer_sg_ids, port):
                    return True, ""
        return False, f"no matching rule in {'egress' if egress else 'ingress'} of {', '.join(sg_ids)}"

    def _rule_matches(
        self, rule: M.SgRule, peer_ip: str, peer_sg_ids: Sequence[str], port: int
    ) -> bool:
        proto = (rule.protocol or "-1").lower()
        if proto not in ("-1", "all"):
            if proto in ("tcp", "6"):
                if port is None or port < 0:
                    return False
            elif proto in ("icmp", "58"):
                pass
        if rule.cidr:
            if ip_in_net(peer_ip, rule.cidr):
                return self._port_ok(rule, port)
        if rule.sg_id and rule.sg_id in peer_sg_ids:
            return self._port_ok(rule, port)
        return False

    @staticmethod
    def _port_ok(rule: M.SgRule, port: Optional[int]) -> bool:
        if port is None:
            return True
        lo, hi = rule.from_port, rule.to_port
        if lo == -1 and hi == -1:
            return True
        return lo <= port <= hi
