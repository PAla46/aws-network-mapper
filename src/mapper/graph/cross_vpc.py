"""Derived analyses: cross-VPC reachability, load-balancer flows, exposure."""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .. import model as M
from ..model import Eni, Subnet, Vpc, Workload
from ..util.cidr import parse_net
from . import Topology
from .routing import PathEngine, PathResult


def link_key(a: str, b: str) -> Tuple[str, str]:
    return tuple(sorted((a, b)))  # type: ignore[return-value]


@dataclass
class VpcLink:
    a: str
    b: str
    kind: str
    detail: str = ""


def vpc_links(topo: Topology) -> List[VpcLink]:
    links: Dict[Tuple[str, str], VpcLink] = {}
    for tgw in topo.tgws.values():
        vpc_attachments = [a for a in tgw.attachments if a.resource_type == "vpc" and a.state == "available"]
        for a, c in itertools.combinations(vpc_attachments, 2):
            links.setdefault(
                link_key(a.resource_id, c.resource_id),
                VpcLink(a.resource_id, c.resource_id, "transit-gateway", tgw.id),
            )
    for pcx in topo.peerings.values():
        if pcx.status != "active" or pcx.peer_vpc_id not in topo.vpcs:
            continue
        links.setdefault(
            link_key(pcx.vpc_id, pcx.peer_vpc_id),
            VpcLink(pcx.vpc_id, pcx.peer_vpc_id, "vpc-peering", pcx.id),
        )
    for vgw in topo.vpn_gateways.values():
        if vgw.vpc_id in topo.vpcs:
            links.setdefault(
                (vgw.vpc_id, "on-premises"),
                VpcLink(vgw.vpc_id, "on-premises", "vpn-gateway", vgw.id),
            )
    return sorted(links.values(), key=lambda l: (l.a, l.b))


def representative_ip(topo: Topology, vpc_id: str) -> Tuple[str, Optional[Subnet]]:
    """Pick a source IP inside a VPC for reachability probes.

    Subnets whose route table only sends 0.0.0.0/0 to an internet gateway are
    tried last: probing from them would report "reachable via IGW" for every
    private destination and hide the interesting paths.
    """
    subnets = list(topo.subnets_by_vpc.get(vpc_id, []))
    if not subnets:
        return "", None

    def rank(subnet: Subnet) -> Tuple[int, str]:
        rtb = topo.rtb_for_subnet(subnet.id)
        if not rtb:
            return (2, subnet.id)
        kinds = {r.target_kind for r in rtb.routes if r.state == "active"}
        if M.T_INTERNET in kinds and len(kinds) == 1:
            return (1, subnet.id)
        if M.T_INTERNET not in kinds and M.T_LOCAL in kinds:
            return (0, subnet.id)
        return (1, subnet.id)

    subnets.sort(key=rank)
    for subnet in subnets:
        enis = [e for e in topo.enis_by_subnet.get(subnet.id, []) if e.private_ip]
        if enis:
            return enis[0].private_ip, subnet
    subnet = subnets[0]
    net = parse_net(subnet.cidr)
    if net is None:
        return "", subnet
    if net.version == 4:
        return str(list(net.hosts())[0] if net.num_addresses > 2 else net.network_address + 1), subnet
    return str(net.network_address + 1), subnet


@dataclass
class CrossVpcRow:
    src_vpc: str
    dst_vpc: str
    link_kind: str
    link_detail: str
    src_ip: str
    src_subnet: str
    dst_ip: str
    dst_subnet: str
    forward: str
    reverse: str
    asymmetric: bool
    reasons: str
    hops: str


def evaluate_cross_vpc(
    topo: Topology, engine: PathEngine, max_pairs: int = 500
) -> List[CrossVpcRow]:
    rows: List[CrossVpcRow] = []
    links = vpc_links(topo)
    for link in links[:max_pairs]:
        if link.b == "on-premises":
            src_ip, src_subnet = representative_ip(topo, link.a)
            if not src_ip or not src_subnet:
                continue
            continue
        a_ip, a_subnet = representative_ip(topo, link.a)
        b_ip, b_subnet = representative_ip(topo, link.b)
        if not (a_ip and b_ip and a_subnet and b_subnet):
            continue
        forward = engine.resolve(
            a_ip,
            a_subnet.id,
            b_ip,
            dst_vpc_id=link.b,
            dst_subnet_id=b_subnet.id,
            with_sg=False,
        )
        rows.append(
            CrossVpcRow(
                src_vpc=link.a,
                dst_vpc=link.b,
                link_kind=link.kind,
                link_detail=link.detail,
                src_ip=a_ip,
                src_subnet=a_subnet.id,
                dst_ip=b_ip,
                dst_subnet=b_subnet.id,
                forward=forward.verdict,
                reverse=forward.reverse.verdict if forward.reverse else "n/a",
                asymmetric=forward.asymmetric,
                reasons="; ".join(forward.reasons) or "-",
                hops=" -> ".join(f"{h.kind}:{h.id}" for h in forward.hops),
            )
        )
    return rows


@dataclass
class LbFlowRow:
    lb: str
    lb_kind: str
    lb_subnet: str
    target: str
    target_ip: str
    target_subnet: str
    verdict: str
    reasons: str
    hops: str


def evaluate_lb_flows(topo: Topology, engine: PathEngine) -> List[LbFlowRow]:
    rows: List[LbFlowRow] = []
    for wl in topo.workloads.values():
        if wl.kind not in ("alb", "nlb", "gwlb"):
            continue
        targets = wl.extra.get("targets") or []
        source_enis = topo.enis_for_workload(wl)
        if not source_enis or not targets:
            continue
        src_eni = source_enis[0]
        for tgt in targets[:20]:
            target_id = tgt.get("id", "")
            target_ip = target_id
            target_subnet = None
            target_sg: Sequence[str] = ()
            if target_id.startswith("i-"):
                twl = topo.workloads.get(target_id)
                if twl:
                    teni = topo.primary_ip_for_workload(twl)
                    target_ip = teni.private_ip if teni else ""
                    target_subnet = teni.subnet_id if teni else ""
                    target_sg = teni.sg_ids if teni else ()
            if not target_ip:
                continue
            if target_subnet:
                result = engine.resolve(
                    src_eni.private_ip,
                    src_eni.subnet_id,
                    target_ip,
                    dst_subnet_id=target_subnet,
                    dst_sg_ids=target_sg,
                    port=int(tgt.get("port") or 0) or None,
                    with_sg=True,
                )
            else:
                result = engine.resolve(
                    src_eni.private_ip,
                    src_eni.subnet_id,
                    target_ip,
                    with_sg=False,
                )
            rows.append(
                LbFlowRow(
                    lb=wl.id,
                    lb_kind=wl.kind,
                    lb_subnet=src_eni.subnet_id,
                    target=target_id,
                    target_ip=target_ip,
                    target_subnet=target_subnet or "-",
                    verdict=result.verdict,
                    reasons="; ".join(result.reasons) or "-",
                    hops=" -> ".join(f"{h.kind}:{h.id}" for h in result.hops),
                )
            )
    return rows


@dataclass
class ExposureRow:
    ip: str
    resource: str
    resource_type: str
    subnet: str
    vpc: str
    region: str
    route_target: str
    reason: str


def internet_exposure(topo: Topology) -> List[ExposureRow]:
    rows: List[ExposureRow] = []
    for eni in topo.enis.values():
        if not eni.public_ip:
            continue
        subnet = topo.subnets.get(eni.subnet_id)
        if not subnet:
            continue
        rtb = topo.rtb_for_subnet(subnet.id)
        target = "-"
        if rtb:
            for route in rtb.routes:
                if route.destination == "0.0.0.0/0" and route.state == "active":
                    target = f"{route.target_id} ({route.target_kind})"
                    break
        rows.append(
            ExposureRow(
                ip=eni.public_ip,
                resource=eni.workload_id or eni.id,
                resource_type=eni.workload_kind or eni.interface_type,
                subnet=subnet.id,
                vpc=subnet.vpc_id,
                region=eni.region,
                route_target=target,
                reason="ENI has a public IPv4 address",
            )
        )
    for wl in topo.workloads.values():
        if not wl.extra.get("public_ips") and wl.extra.get("public") is not True:
            continue
        rows.append(
            ExposureRow(
                ip=", ".join(wl.public_ips) or wl.extra.get("endpoint", ""),
                resource=wl.label,
                resource_type=wl.kind,
                subnet=", ".join(wl.subnet_ids) or "-",
                vpc=wl.vpc_id,
                region=wl.region,
                route_target="see route tables",
                reason="workload is flagged publicly reachable",
            )
        )
    return rows


@dataclass
class CidrMapRow:
    cidr: str
    vpc: str
    vpc_name: str
    subnet: str
    subnet_name: str
    az: str
    route_table: str
    conflicts_with: str
    reachable_from: str


def cidr_map(topo: Topology) -> List[CidrMapRow]:
    subnets = sorted(topo.subnets.values(), key=lambda s: (s.vpc_id, s.cidr))
    rows: List[CidrMapRow] = []
    for subnet in subnets:
        vpc = topo.vpcs.get(subnet.vpc_id)
        conflicts = []
        reachable = []
        for other in subnets:
            if other.id == subnet.id:
                continue
            from ..util.cidr import nets_overlap

            if nets_overlap(subnet.cidr, other.cidr):
                conflicts.append(f"{other.id}:{other.cidr}")
        for wl in topo.workloads_by_vpc.get(subnet.vpc_id, []):
            if subnet.id in wl.subnet_ids and wl.kind in ("rds",):
                reachable.append(f"{wl.kind}:{wl.label}")
        rows.append(
            CidrMapRow(
                cidr=subnet.cidr,
                vpc=subnet.vpc_id,
                vpc_name=vpc.label if vpc else "",
                subnet=subnet.id,
                subnet_name=subnet.name,
                az=subnet.az,
                route_table=subnet.rtb_id,
                conflicts_with="; ".join(conflicts) or "-",
                reachable_from="; ".join(reachable) or "-",
            )
        )
    return rows
