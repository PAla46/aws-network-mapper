"""Audit findings derived from the collected configuration.

Rules are deliberately conservative: they only fire on facts visible in the
AWS APIs, and every finding carries evidence so a reviewer can reproduce it.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

from .. import model as M
from ..util.cidr import (
    cidr_contains,
    is_default_route,
    nets_overlap,
)
from ..graph import Topology
from ..model import Route, RouteTable, Subnet, Vpc

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

SENSITIVE_PORTS = {
    22: "ssh",
    23: "telnet",
    445: "smb",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    2375: "docker-api",
    2379: "etcd",
}

PRIVATE_NAME_HINTS = ("private", "data", "db", "database", "internal", "app", "backend", "secure")


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    resource: str
    resource_type: str
    region: str = ""
    vpc_id: str = ""
    evidence: str = ""
    recommendation: str = ""
    tags: List[str] = field(default_factory=list)

    def as_row(self) -> Dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "resource": self.resource,
            "resource_type": self.resource_type,
            "region": self.region,
            "vpc_id": self.vpc_id,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "tags": ";".join(self.tags),
        }


@dataclass
class RuleContext:
    topo: Topology

    def subnet(self, sid: str) -> Optional[Subnet]:
        return self.topo.subnets.get(sid)

    def rtb(self, rid: str) -> Optional[RouteTable]:
        return self.topo.route_tables.get(rid)

    def default_routes(self, rtb: RouteTable) -> List[Route]:
        """Active default routes (0.0.0.0/0 and ::/0) in a route table."""
        return [
            r
            for r in rtb.routes
            if (r.destination == "0.0.0.0/0" or r.destination == "::/0")
            and r.state == "active"
        ]


RuleFn = Callable[[RuleContext], Iterable[Finding]]
RULES: Dict[str, RuleFn] = {}


def rule(rule_id: str, severity: str, title: str, recommendation: str, *tags: str):
    def wrap(fn: RuleFn) -> RuleFn:
        fn._meta = (rule_id, severity, title, recommendation, list(tags))  # type: ignore[attr-defined]
        RULES[rule_id] = fn
        return fn

    return wrap


# --------------------------------------------------------------------------- #
# routing rules
# --------------------------------------------------------------------------- #


@rule(
    "NET001",
    HIGH,
    "Subnet is directly internet-routable",
    "Move the workload to a private subnet behind a NAT gateway, or keep it public only "
    "if it is an intentional internet-facing tier with tightly scoped security groups.",
    "route-table",
    "internet-exposure",
)
def net001_public_subnet(ctx: RuleContext) -> Iterable[Finding]:
    for subnet in ctx.topo.subnets.values():
        rtb = ctx.topo.rtb_for_subnet(subnet.id)
        if not rtb:
            continue
        igw_routes = [
            r for r in ctx.default_routes(rtb) if r.target_kind == M.T_INTERNET and r.state == "active"
        ]
        if not igw_routes:
            continue
        public_ip_enis = [e for e in ctx.topo.enis_by_subnet.get(subnet.id, []) if e.public_ip]
        if subnet.map_public_ip_on_launch:
            sev = HIGH
            ev = (
                f"subnet {subnet.id} ({subnet.cidr}) has MapPublicIpOnLaunch=true and route "
                f"{igw_routes[0].destination} -> {igw_routes[0].target_id} via {rtb.id}"
            )
        elif public_ip_enis:
            sev = HIGH
            ev = (
                f"{len(public_ip_enis)} ENI(s) with public IPs in {subnet.id} and default route "
                f"to {igw_routes[0].target_id} via {rtb.id}"
            )
        else:
            continue
        yield Finding(
            "NET001",
            sev,
            "Subnet is directly internet-routable",
            subnet.id,
            "AWS::EC2::Subnet",
            subnet.region,
            subnet.vpc_id,
            ev,
            wrap_reco("NET001"),
            ["route-table", "internet-exposure"],
        )


@rule(
    "NET002",
    MEDIUM,
    "Dual default routes (IGW and NAT) in the same route table",
    "Remove one default route. Traffic matching 0.0.0.0/0 can follow either target depending "
    "on evaluation order, which makes egress paths unpredictable.",
    "route-table",
    "bug",
)
def net002_dual_default(ctx: RuleContext) -> Iterable[Finding]:
    for rtb in ctx.topo.route_tables.values():
        defaults = [r for r in ctx.default_routes(rtb) if r.state == "active"]
        kinds = {r.target_kind for r in defaults}
        if M.T_INTERNET in kinds and M.T_NAT in kinds:
            used = []
            for subnet in ctx.topo.subnets_by_vpc.get(rtb.vpc_id, []):
                if subnet.rtb_id == rtb.id:
                    used.append(subnet.id)
            yield Finding(
                "NET002",
                MEDIUM,
                "Dual default routes (IGW and NAT) in the same route table",
                rtb.id,
                "AWS::EC2::RouteTable",
                rtb.region,
                rtb.vpc_id,
                f"{rtb.id} has default routes to "
                + ", ".join(sorted(r.target_id for r in defaults))
                + f"; subnets using it: {', '.join(used) or 'none'}",
                wrap_reco("NET002"),
                ["route-table", "bug"],
            )


@rule(
    "NET003",
    HIGH,
    "NAT gateway cannot reach the internet",
    "Add a 0.0.0.0/0 route to an attached internet gateway in the NAT gateway's subnet route table.",
    "nat-gateway",
    "bug",
)
def net003_broken_nat(ctx: RuleContext) -> Iterable[Finding]:
    for nat in ctx.topo.nat_gateways.values():
        if nat.state not in ("available", "pending"):
            continue
        subnet = ctx.subnet(nat.subnet_id)
        if not subnet:
            continue
        rtb = ctx.topo.rtb_for_subnet(subnet.id)
        if not rtb:
            yield Finding(
                "NET003",
                HIGH,
                "NAT gateway cannot reach the internet",
                nat.id,
                "AWS::EC2::NatGateway",
                nat.region,
                nat.vpc_id,
                f"NAT {nat.id} sits in subnet {subnet.id} which has no effective route table",
                wrap_reco("NET003"),
                ["nat-gateway", "bug"],
            )
            continue
        defaults = [r for r in ctx.default_routes(rtb) if r.state == "active"]
        igw_defaults = [r for r in defaults if r.target_kind == M.T_INTERNET]
        if not igw_defaults:
            yield Finding(
                "NET003",
                HIGH,
                "NAT gateway cannot reach the internet",
                nat.id,
                "AWS::EC2::NatGateway",
                nat.region,
                nat.vpc_id,
                f"no 0.0.0.0/0 -> IGW route in {rtb.id} (subnet {subnet.id}); "
                f"defaults present: {', '.join(f'{r.target_id} ({r.target_kind})' for r in defaults) or 'none'}",
                wrap_reco("NET003"),
                ["nat-gateway", "bug"],
            )


@rule(
    "NET004",
    MEDIUM,
    "NAT gateway subnet default route points at another NAT gateway",
    "A NAT gateway's own subnet must reach an internet gateway, not another NAT gateway.",
    "nat-gateway",
    "bug",
)
def net004_nat_chase(ctx: RuleContext) -> Iterable[Finding]:
    for nat in ctx.topo.nat_gateways.values():
        subnet = ctx.subnet(nat.subnet_id)
        if not subnet:
            continue
        rtb = ctx.topo.rtb_for_subnet(subnet.id)
        if not rtb:
            continue
        for route in ctx.default_routes(rtb):
            if route.target_kind == M.T_NAT:
                yield Finding(
                    "NET004",
                    MEDIUM,
                    "NAT gateway subnet default route points at another NAT gateway",
                    rtb.id,
                    "AWS::EC2::RouteTable",
                    rtb.region,
                    rtb.vpc_id,
                    f"subnet {subnet.id} holds NAT {nat.id}; its default route points at "
                    f"{route.target_id}",
                    wrap_reco("NET004"),
                    ["nat-gateway", "bug"],
                )


@rule(
    "NET005",
    HIGH,
    "Route table points at an internet gateway that is not attached",
    "Attach the internet gateway to the VPC or replace the route with the correct gateway.",
    "route-table",
    "bug",
)
def net005_detached_igw(ctx: RuleContext) -> Iterable[Finding]:
    for rtb in ctx.topo.route_tables.values():
        for route in rtb.routes:
            if route.target_kind != M.T_INTERNET:
                continue
            igw = ctx.topo.igws.get(route.target_id)
            if igw and not igw.attached:
                yield Finding(
                    "NET005",
                    HIGH,
                    "Route table points at an internet gateway that is not attached",
                    rtb.id,
                    "AWS::EC2::RouteTable",
                    rtb.region,
                    rtb.vpc_id,
                    f"{rtb.id}: {route.destination} -> {route.target_id} but the IGW has no "
                    "available attachment",
                    wrap_reco("NET005"),
                    ["route-table", "bug"],
                )


@rule(
    "NET006",
    LOW,
    "Internet gateway attached to no VPC",
    "Remove the unused internet gateway to keep the inventory clean.",
    "internet-gateway",
    "hygiene",
)
def net006_orphan_igw(ctx: RuleContext) -> Iterable[Finding]:
    for igw in ctx.topo.igws.values():
        if not igw.attached:
            yield Finding(
                "NET006",
                LOW,
                "Internet gateway attached to no VPC",
                igw.id,
                "AWS::EC2::InternetGateway",
                igw.region,
                igw.vpc_id,
                f"{igw.id} ({igw.name}) has no available VPC attachment",
                wrap_reco("NET006"),
                ["internet-gateway", "hygiene"],
            )


@rule(
    "NET007",
    INFO,
    "Route table is not associated with any subnet",
    "Delete unused route tables or associate them, so reviewers can tell intent from drift.",
    "route-table",
    "hygiene",
)
def net007_unused_rtb(ctx: RuleContext) -> Iterable[Finding]:
    for rtb in ctx.topo.route_tables.values():
        if rtb.is_main or rtb.subnet_ids:
            continue
        yield Finding(
            "NET007",
            INFO,
            "Route table is not associated with any subnet",
            rtb.id,
            "AWS::EC2::RouteTable",
            rtb.region,
            rtb.vpc_id,
            f"{rtb.id} ({rtb.label}) has no subnet associations and is not the main table",
            wrap_reco("NET007"),
            ["route-table", "hygiene"],
        )


@rule(
    "NET008",
    HIGH,
    "Overlapping CIDR blocks between connected VPCs",
    "Overlapping CIDRs make return traffic unroutable. Re-plan the CIDR space (or add NAT / "
    "static routes on the TGW).",
    "cidr",
    "bug",
)
def net008_overlapping_vpcs(ctx: RuleContext) -> Iterable[Finding]:
    seen = set()
    for vpc in ctx.topo.vpcs.values():
        for other in ctx.topo.vpcs_overlapping(vpc.id):
            key = tuple(sorted((vpc.id, other.id)))
            if key in seen:
                continue
            seen.add(key)
            overlap = [
                f"{a} <-> {b}"
                for a in vpc.cidrs
                for b in other.cidrs
                if nets_overlap(a, b)
            ]
            paths = describe_vpc_paths(ctx, vpc.id, other.id)
            if not paths:
                continue
            yield Finding(
                "NET008",
                HIGH,
                "Overlapping CIDR blocks between connected VPCs",
                f"{vpc.id}|{other.id}",
                "AWS::EC2::Vpc",
                vpc.region,
                vpc.id,
                f"{vpc.id} ({', '.join(vpc.cidrs)}) and {other.id} "
                f"({', '.join(other.cidrs)}) overlap ({'; '.join(overlap)}) and are connected via "
                f"{paths}",
                wrap_reco("NET008"),
                ["cidr", "tgw" if "tgw" in paths else "peering"],
            )


@rule(
    "NET009",
    HIGH,
    "One-way transit gateway routing",
    "Add the mirrored route in the other direction. A transit gateway drops return traffic "
    "when one VPC has a route to the hub and the other does not.",
    "transit-gateway",
    "bug",
)
def net009_one_way_tgw(ctx: RuleContext) -> Iterable[Finding]:
    topo = ctx.topo
    for tgw in topo.tgws.values():
        vpc_atts = sorted(
            {a.resource_id for a in tgw.attachments if a.resource_type == "vpc" and a.state == "available"}
        )
        for vpc_a, vpc_b in itertools.combinations(vpc_atts, 2):
            forward = _vpc_routes_via_tgw_to(topo, vpc_a, vpc_b, tgw.id)
            backward = _vpc_routes_via_tgw_to(topo, vpc_b, vpc_a, tgw.id)
            if forward == backward:
                continue
            src, dst = (vpc_a, vpc_b) if forward else (vpc_b, vpc_a)
            yield Finding(
                "NET009",
                HIGH,
                "One-way transit gateway routing",
                f"{tgw.id}:{src}|{dst}",
                "AWS::EC2::TransitGateway",
                tgw.region,
                src,
                f"{src} has a route to {tgw.id} covering {dst}, but {dst} has no route table "
                f"that sends {src} traffic to {tgw.id}; the return path is broken",
                wrap_reco("NET009"),
                ["transit-gateway", "bug"],
            )


@rule(
    "NET010",
    MEDIUM,
    "Transit gateway route table has a catch-all route",
    "Replace 0.0.0.0/0 with explicit destination CIDRs so the hub does not become a "
    "transit path for unintended traffic.",
    "transit-gateway",
    "least-privilege",
)
def net010_broad_tgw_route(ctx: RuleContext) -> Iterable[Finding]:
    for tgw in ctx.topo.tgws.values():
        for rtb in tgw.route_tables:
            for route in rtb.routes:
                if is_default_route(route.destination) or route.destination == "::/0":
                    yield Finding(
                        "NET010",
                        MEDIUM,
                        "Transit gateway route table has a catch-all route",
                        rtb.id,
                        "AWS::EC2::TransitGatewayRouteTable",
                        tgw.region,
                        "",
                        f"{rtb.id} routes {route.destination} -> {route.target_id} "
                        f"({route.target_kind}, state={route.state})",
                        wrap_reco("NET010"),
                        ["transit-gateway", "least-privilege"],
                    )


@rule(
    "NET011",
    HIGH,
    "One-way VPC peering routing",
    "Add the mirrored route in the peer VPC. Peering connections are never transitive and "
    "must be configured on both sides.",
    "vpc-peering",
    "bug",
)
def net011_one_way_peering(ctx: RuleContext) -> Iterable[Finding]:
    topo = ctx.topo
    for pcx in topo.peerings.values():
        if pcx.status != "active" or not pcx.peer_vpc_id:
            continue
        if pcx.peer_region and pcx.peer_region not in topo.regions:
            continue
        local_vpcs = pcx.local_vpc_ids or ([pcx.vpc_id] if pcx.vpc_id else [])
        for local_id in local_vpcs:
            local = topo.vpcs.get(local_id)
            peer = topo.vpcs.get(pcx.peer_vpc_id)
            if not local or not peer:
                continue
            forward = _vpc_routes_via_peering(topo, local, peer.cidrs, pcx.id)
            backward = _vpc_routes_via_peering(topo, peer, local.cidrs, pcx.id)
            if forward == backward:
                continue
            src, dst = (local, peer) if forward else (peer, local)
            yield Finding(
                "NET011",
                HIGH,
                "One-way VPC peering routing",
                pcx.id,
                "AWS::EC2::VPCPeeringConnection",
                pcx.region,
                src.id,
                f"{src.id} routes toward {dst.id} via {pcx.id} but {dst.id} has no route back "
                f"via {pcx.id}; peering is never transitive",
                wrap_reco("NET011"),
                ["vpc-peering", "bug"],
            )


@rule(
    "NET012",
    MEDIUM,
    "VPC peering connection is not active",
    "Accept the pending peering request or delete the connection.",
    "vpc-peering",
    "hygiene",
)
def net012_inactive_peering(ctx: RuleContext) -> Iterable[Finding]:
    for pcx in ctx.topo.peerings.values():
        if pcx.status and pcx.status != "active":
            yield Finding(
                "NET012",
                MEDIUM,
                "VPC peering connection is not active",
                pcx.id,
                "AWS::EC2::VPCPeeringConnection",
                pcx.region,
                pcx.vpc_id,
                f"status={pcx.status} between {pcx.vpc_id} and {pcx.peer_vpc_id}",
                wrap_reco("NET012"),
                ["vpc-peering", "hygiene"],
            )


@rule(
    "NET013",
    MEDIUM,
    "Transit gateway attachment CIDR does not cover the whole VPC",
    "A partial attachment CIDR means the remaining VPC prefixes have no transit route, "
    "which usually causes asymmetric traffic.",
    "transit-gateway",
    "bug",
)
def net013_partial_attachment(ctx: RuleContext) -> Iterable[Finding]:
    topo = ctx.topo
    for att in [a for t in topo.tgws.values() for a in t.attachments]:
        vpc = topo.vpcs.get(att.resource_id)
        if not vpc or not att.cidr_blocks:
            continue
        uncovered = [
            c for c in vpc.cidrs if not any(cidr_contains(attc, c) for attc in att.cidr_blocks)
        ]
        if uncovered:
            yield Finding(
                "NET013",
                MEDIUM,
                "Transit gateway attachment CIDR does not cover the whole VPC",
                att.id,
                "AWS::EC2::TransitGatewayAttachment",
                att.region,
                vpc.id,
                f"attachment {att.id} advertises {', '.join(att.cidr_blocks)} but VPC CIDR(s) "
                f"{', '.join(uncovered)} are not covered",
                wrap_reco("NET013"),
                ["transit-gateway", "bug"],
            )


@rule(
    "NET014",
    MEDIUM,
    "Public IP assigned in a subnet without an internet route",
    "Either add a default route to an attached IGW or remove the public IP; otherwise the "
    "address is unreachable inbound.",
    "network-interface",
    "hygiene",
)
def net014_orphan_public_ip(ctx: RuleContext) -> Iterable[Finding]:
    topo = ctx.topo
    for eni in topo.enis.values():
        if not eni.public_ip:
            continue
        subnet = topo.subnets.get(eni.subnet_id)
        if not subnet:
            continue
        rtb = topo.rtb_for_subnet(subnet.id)
        if not rtb:
            continue
        has_igw = any(
            r.target_kind == M.T_INTERNET and r.state == "active" for r in rtb.routes
        )
        if not has_igw:
            yield Finding(
                "NET014",
                MEDIUM,
                "Public IP assigned in a subnet without an internet route",
                eni.id,
                "AWS::EC2::NetworkInterface",
                eni.region,
                subnet.vpc_id,
                f"ENI {eni.id} ({eni.workload_name}) has public IP {eni.public_ip} but route "
                f"table {rtb.id} has no route to an internet gateway",
                wrap_reco("NET014"),
                ["network-interface", "hygiene"],
            )


@rule(
    "NET015",
    HIGH,
    "Security group exposes a sensitive management port to the internet",
    "Restrict the source to a bastion, VPN or a known CIDR, and remove the 0.0.0.0/0 rule.",
    "security-group",
    "internet-exposure",
)
def net015_sensitive_ingress(ctx: RuleContext) -> Iterable[Finding]:
    for sg in ctx.topo.security_groups.values():
        for rule in sg.ingress:
            if rule.cidr not in ("0.0.0.0/0", "::/0"):
                continue
            ports = set(range(rule.from_port, rule.to_port + 1)) if rule.from_port >= 0 else set(SENSITIVE_PORTS)
            hits = sorted(p for p in ports if p in SENSITIVE_PORTS)
            if not hits and rule.protocol in ("-1", "all") and rule.from_port < 0:
                hits = sorted(SENSITIVE_PORTS)
            if not hits:
                continue
            names = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in hits)
            yield Finding(
                "NET015",
                HIGH,
                "Security group exposes a sensitive management port to the internet",
                sg.id,
                "AWS::EC2::SecurityGroup",
                sg.region,
                sg.vpc_id,
                f"sg {sg.id} ({sg.name or 'unnamed'}) ingress {rule.cidr} protocol="
                f"{rule.protocol} ports={rule.port_range} -> {names}",
                wrap_reco("NET015"),
                ["security-group", "internet-exposure"],
            )


@rule(
    "NET016",
    CRITICAL,
    "Security group allows all traffic from everywhere",
    "Replace the allow-all rule with the specific protocols and sources the workload needs.",
    "security-group",
    "internet-exposure",
)
def net016_allow_all(ctx: RuleContext) -> Iterable[Finding]:
    for sg in ctx.topo.security_groups.values():
        if sg.name == "default":
            continue
        for direction, rules in (("ingress", sg.ingress), ("egress", sg.egress)):
            for rule in rules:
                if (
                    rule.protocol in ("-1", "all")
                    and rule.cidr == "0.0.0.0/0"
                    and rule.from_port < 0
                    and not rule.sg_id
                ):
                    yield Finding(
                        "NET016",
                        CRITICAL if direction == "ingress" else LOW,
                        "Security group allows all traffic from everywhere",
                        sg.id,
                        "AWS::EC2::SecurityGroup",
                        sg.region,
                        sg.vpc_id,
                        f"sg {sg.id} ({sg.name or 'unnamed'}) {direction} allows "
                        f"{rule.cidr} on all protocols and ports",
                        wrap_reco("NET016"),
                        ["security-group", "internet-exposure" if direction == "ingress" else "hygiene"],
                    )


@rule(
    "NET017",
    INFO,
    "Security group is not attached to any network interface",
    "Delete unused security groups to reduce the chance of an accidental re-use.",
    "security-group",
    "hygiene",
)
def net017_unused_sg(ctx: RuleContext) -> Iterable[Finding]:
    used = set()
    for eni in ctx.topo.enis.values():
        used.update(eni.sg_ids)
    for wl in ctx.topo.workloads.values():
        used.update(wl.sg_ids)
    for ep in ctx.topo.endpoints.values():
        used.update(ep.sg_ids)
    for sg in ctx.topo.security_groups.values():
        if sg.id in used:
            continue
        yield Finding(
            "NET017",
            INFO,
            "Security group is not attached to any network interface",
            sg.id,
            "AWS::EC2::SecurityGroup",
            sg.region,
            sg.vpc_id,
            f"sg {sg.id} ({sg.name or 'unnamed'}) is not referenced by any ENI, workload or endpoint",
            wrap_reco("NET017"),
            ["security-group", "hygiene"],
        )


@rule(
    "NET018",
    MEDIUM,
    "VPC has no flow logs",
    "Enable VPC flow logs to a destination that is retained per the audit evidence policy; "
    "flow logs are required to prove actual (rather than permitted) connectivity.",
    "vpc",
    "monitoring",
)
def net018_no_flow_logs(ctx: RuleContext) -> Iterable[Finding]:
    for vpc in ctx.topo.vpcs.values():
        if not vpc.flow_logs:
            yield Finding(
                "NET018",
                MEDIUM,
                "VPC has no flow logs",
                vpc.id,
                "AWS::EC2::VPC",
                vpc.region,
                vpc.id,
                f"VPC {vpc.id} ({vpc.label}) has no flow logs configured",
                wrap_reco("NET018"),
                ["vpc", "monitoring"],
            )


@rule(
    "NET019",
    HIGH,
    "Database instance is publicly accessible",
    "Move the instance into private subnets and reach it through a VPN, TGW or VPC endpoint.",
    "rds",
    "internet-exposure",
)
def net019_public_rds(ctx: RuleContext) -> Iterable[Finding]:
    for wl in ctx.topo.workloads.values():
        if wl.kind != "rds" or not wl.extra.get("public"):
            continue
        yield Finding(
            "NET019",
            HIGH,
            "Database instance is publicly accessible",
            wl.id,
            "AWS::RDS::DBInstance",
            wl.region,
            wl.vpc_id,
            f"RDS {wl.label} ({wl.engine}) PubliclyAccessible=true in subnets "
            f"{', '.join(wl.subnet_ids) or 'unknown'}",
            wrap_reco("NET019"),
            ["rds", "internet-exposure"],
        )


@rule(
    "NET020",
    MEDIUM,
    "Network ACL allows a sensitive port from any source",
    "Scope the NACL rule to the security-group or CIDR range that needs it; NACLs are a "
    "defence-in-depth control, not the primary filter.",
    "network-acl",
    "least-privilege",
)
def net020_nacl_sensitive(ctx: RuleContext) -> Iterable[Finding]:
    for nacl in ctx.topo.nacls.values():
        for entry in nacl.entries:
            if entry.rule_action != "allow":
                continue
            if entry.cidr not in ("0.0.0.0/0", "::/0"):
                continue
            if not entry.port:
                continue
            try:
                lo, hi = entry.port.split("-")
                lo_i, hi_i = int(lo or 0), int(hi or 65535)
            except ValueError:
                continue
            hits = sorted(p for p in SENSITIVE_PORTS if lo_i <= p <= hi_i)
            if not hits:
                continue
            yield Finding(
                "NET020",
                MEDIUM,
                "Network ACL allows a sensitive port from any source",
                nacl.id,
                "AWS::EC2::NetworkAcl",
                nacl.region,
                nacl.vpc_id,
                f"nacl {nacl.id} rule {entry.rule_number} allows {entry.cidr} {entry.protocol} "
                f"{entry.port} -> {', '.join(str(p) for p in hits)}",
                wrap_reco("NET020"),
                ["network-acl", "least-privilege"],
            )


@rule(
    "NET021",
    LOW,
    "VPC endpoint policy allows every resource and principal",
    "Restrict the endpoint policy to the resources and principals that actually need it.",
    "vpc-endpoint",
    "least-privilege",
)
def net021_endpoint_allow_all(ctx: RuleContext) -> Iterable[Finding]:
    for ep in ctx.topo.endpoints.values():
        if ep.policy == "allow-all":
            yield Finding(
                "NET021",
                LOW,
                "VPC endpoint policy allows every resource and principal",
                ep.id,
                "AWS::EC2::VPCEndpoint",
                ep.region,
                ep.vpc_id,
                f"endpoint {ep.id} ({ep.short_service}) policy allows all actions/resources",
                wrap_reco("NET021"),
                ["vpc-endpoint", "least-privilege"],
            )


@rule(
    "NET022",
    LOW,
    "Transit gateway attachment has no association with a route table",
    "Associate the attachment with an explicit route table instead of relying on the "
    "transit gateway default, so routing is reviewable.",
    "transit-gateway",
    "hygiene",
)
def net022_tgw_default_rtb(ctx: RuleContext) -> Iterable[Finding]:
    for tgw in ctx.topo.tgws.values():
        if not tgw.route_tables:
            continue
        for att in tgw.attachments:
            associated = any(att.id in rtb.associations for rtb in tgw.route_tables)
            if not associated:
                yield Finding(
                    "NET022",
                    LOW,
                    "Transit gateway attachment has no association with a route table",
                    att.id,
                    "AWS::EC2::TransitGatewayAttachment",
                    tgw.region,
                    att.resource_id,
                    f"attachment {att.id} uses the default association route table of {tgw.id}",
                    wrap_reco("NET022"),
                    ["transit-gateway", "hygiene"],
                )


@rule(
    "NET023",
    INFO,
    "Subnet has no route to the internet and no gateway route",
    "Confirm the subnet is intentionally isolated (e.g. isolated network namespace); "
    "otherwise outbound calls will fail.",
    "subnet",
    "hygiene",
)
def net023_isolated_subnet(ctx: RuleContext) -> Iterable[Finding]:
    for subnet in ctx.topo.subnets.values():
        rtb = ctx.topo.rtb_for_subnet(subnet.id)
        if not rtb:
            continue
        defaults = [r for r in ctx.default_routes(rtb) if r.state == "active"]
        if defaults:
            continue
        if not any(r.target_kind == M.T_LOCAL for r in rtb.routes):
            continue
        yield Finding(
            "NET023",
            INFO,
            "Subnet has no route to the internet and no gateway route",
            subnet.id,
            "AWS::EC2::Subnet",
            subnet.region,
            subnet.vpc_id,
            f"route table {rtb.id} (used by {subnet.id}) has no 0.0.0.0/0 or ::/0 route",
            wrap_reco("NET023"),
            ["subnet", "hygiene"],
        )


@rule(
    "NET024",
    MEDIUM,
    "Subnets still use the main route table",
    "Give each tier (public / app / data) an explicit route table so a change cannot silently "
    "affect every subnet in the VPC.",
    "subnet",
    "hygiene",
)
def net024_main_rtb(ctx: RuleContext) -> Iterable[Finding]:
    for subnet in ctx.topo.subnets.values():
        if subnet.rtb_association != "main":
            continue
        rtb = ctx.topo.rtb_for_subnet(subnet.id)
        if not rtb or not rtb.is_main:
            continue
        has_igw = any(r.target_kind == M.T_INTERNET for r in rtb.routes)
        looks_private = any(h in (subnet.name or "").lower() for h in PRIVATE_NAME_HINTS)
        if has_igw and looks_private:
            yield Finding(
                "NET024",
                MEDIUM,
                "Subnets still use the main route table",
                subnet.id,
                "AWS::EC2::Subnet",
                subnet.region,
                subnet.vpc_id,
                f"subnet '{subnet.name}' ({subnet.cidr}) inherits main route table {rtb.id}, "
                "which has a default route to an internet gateway",
                wrap_reco("NET024"),
                ["subnet", "hygiene", "internet-exposure"],
            )


@rule(
    "NET025",
    LOW,
    "Internet-facing load balancer",
    "Confirm the balancer is meant to be internet-facing and that its listener is HTTPS with "
    "an ACM certificate.",
    "load-balancer",
    "internet-exposure",
)
def net025_public_alb(ctx: RuleContext) -> Iterable[Finding]:
    for wl in ctx.topo.workloads.values():
        if wl.kind not in ("alb", "nlb", "gwlb"):
            continue
        if wl.extra.get("scheme") != "internet-facing":
            continue
        yield Finding(
            "NET025",
            LOW,
            "Internet-facing load balancer",
            wl.id,
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            wl.region,
            wl.vpc_id,
            f"{wl.kind.upper()} {wl.label} is internet-facing (DNS {wl.extra.get('dns', '')}) in "
            f"subnets {', '.join(wl.subnet_ids)}",
            wrap_reco("NET025"),
            ["load-balancer", "internet-exposure"],
        )


@rule(
    "NET026",
    MEDIUM,
    "Overlapping CIDR blocks between subnets in the same VPC",
    "Re-plan the subnet space; overlapping subnets make the local route ambiguous.",
    "cidr",
    "bug",
)
def net026_overlapping_subnets(ctx: RuleContext) -> Iterable[Finding]:
    for vpc in ctx.topo.vpcs.values():
        subnets = ctx.topo.subnets_by_vpc.get(vpc.id, [])
        for i, a in enumerate(subnets):
            for b in subnets[i + 1 :]:
                if nets_overlap(a.cidr, b.cidr):
                    yield Finding(
                        "NET026",
                        MEDIUM,
                        "Overlapping CIDR blocks between subnets in the same VPC",
                        f"{a.id}|{b.id}",
                        "AWS::EC2::Subnet",
                        vpc.region,
                        vpc.id,
                        f"subnets {a.id} ({a.cidr}) and {b.id} ({b.cidr}) overlap",
                        wrap_reco("NET026"),
                        ["cidr", "bug"],
                    )


@rule(
    "NET027",
    HIGH,
    "VPC route table points at a transit gateway with no attachment",
    "Create the VPC attachment, or remove the route. Traffic to the destination CIDR is dropped.",
    "route-table",
    "bug",
)
def net027_tgw_no_attachment(ctx: RuleContext) -> Iterable[Finding]:
    for rtb in ctx.topo.route_tables.values():
        for route in rtb.routes:
            if route.target_kind != M.T_TGW:
                continue
            tgw = ctx.topo.tgws.get(route.target_id)
            if tgw is None:
                continue
            atts = ctx.topo.tgw_attachments_for_vpc(rtb.vpc_id)
            if not any(a.tgw_id == route.target_id for a in atts):
                yield Finding(
                    "NET027",
                    HIGH,
                    "VPC route table points at a transit gateway with no attachment",
                    rtb.id,
                    "AWS::EC2::RouteTable",
                    rtb.region,
                    rtb.vpc_id,
                    f"{rtb.id} routes {route.destination} -> {route.target_id} but VPC "
                    f"{rtb.vpc_id} has no attachment to that transit gateway",
                    wrap_reco("NET027"),
                    ["route-table", "bug"],
                )


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

_RECO_CACHE: Dict[str, str] = {}


def wrap_reco(rule_id: str) -> str:
    return _RECO_CACHE.get(rule_id, "")


def _vpc_routes_via_tgw_to(
    topo: Topology, from_vpc: str, to_vpc: str, tgw_id: str
) -> bool:
    """Does any route table in *from_vpc* send *to_vpc*'s CIDRs to this TGW?"""
    targets = topo.vpc_cidrs(to_vpc)
    if not targets:
        return False
    for rtb in topo.rtbs_by_vpc.get(from_vpc, []):
        for route in rtb.routes:
            if route.target_kind != M.T_TGW or route.target_id != tgw_id or route.state != "active":
                continue
            if any(cidr_contains(route.destination, t) or nets_overlap(route.destination, t) for t in targets):
                return True
    return False


def _vpc_routes_via_peering(topo: Topology, from_vpc: Vpc, peer_cidrs, pcx_id: str) -> bool:
    for rtb in topo.rtbs_by_vpc.get(from_vpc.id, []):
        for route in rtb.routes:
            if route.target_kind != M.T_PEERING or route.target_id != pcx_id:
                continue
            if route.state != "active":
                continue
            if any(cidr_contains(route.destination, c) or nets_overlap(route.destination, c) for c in peer_cidrs):
                return True
    return False


def describe_vpc_paths(ctx: RuleContext, vpc_a: str, vpc_b: str) -> str:
    paths = []
    for att in ctx.topo.tgw_attachments_for_vpc(vpc_a):
        tgw = ctx.topo.tgws.get(att.tgw_id)
        if not tgw:
            continue
        if any(a.resource_type == "vpc" and a.resource_id == vpc_b for a in tgw.attachments):
            paths.append(f"transit gateway {tgw.id}")
    for pcx in ctx.topo.peers_of_vpc(vpc_a):
        if pcx.peer_vpc_id == vpc_b and pcx.status == "active":
            paths.append(f"vpc peering {pcx.id}")
    return ", ".join(sorted(set(paths)))


for _rid, _fn in RULES.items():
    _meta = getattr(_fn, "_meta", None)
    if _meta:
        _RECO_CACHE[_rid] = _meta[3]


def run_rules(topo: Topology) -> List[Finding]:
    ctx = RuleContext(topo)
    findings: List[Finding] = []
    for rule_id, fn in RULES.items():
        try:
            findings.extend(fn(ctx))
        except Exception as exc:  # noqa: BLE001 - a broken rule must not kill the run
            findings.append(
                Finding(
                    "INTERNAL",
                    INFO,
                    f"Rule {rule_id} failed to evaluate",
                    rule_id,
                    "internal",
                    evidence=f"{type(exc).__name__}: {exc}",
                    recommendation="Report as a tool bug.",
                    tags=["tool-bug"],
                )
            )
    deduped: Dict[tuple, Finding] = {}
    for f in findings:
        deduped.setdefault((f.rule_id, f.resource), f)
    out = list(deduped.values())
    out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule_id, f.resource))
    return out
