"""Normalised data model for the AWS network map.

The collector turns raw ``describe_*`` responses into these dataclasses so the
rest of the tool never touches raw AWS payloads.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# --- route target kinds -----------------------------------------------------

T_LOCAL = "local"
T_INTERNET = "internet-gateway"
T_NAT = "nat-gateway"
T_TGW = "transit-gateway"
T_TGW_ATTACH = "transit-gateway-attachment"
T_PEERING = "vpc-peering"
T_VGW = "vpn-gateway"
T_EIGW = "egress-only-internet-gateway"
T_ENDPOINT = "vpc-endpoint"
T_CARRIER_GW = "carrier-gateway"
T_LOCAL_GW = "local-gateway"
T_CORE_NETWORK = "core-network"
T_ENI = "network-interface"
T_INSTANCE = "instance"
T_UNKNOWN = "unknown"

TARGET_FIELD_MAP = (
    ("GatewayId", None),
    ("NatGatewayId", T_NAT),
    ("NetworkInterfaceId", T_ENI),
    ("TransitGatewayId", T_TGW),
    ("VpcPeeringConnectionId", T_PEERING),
    ("EgressOnlyInternetGatewayId", T_EIGW),
    ("VpcEndpointId", T_ENDPOINT),
    ("TransitGatewayAttachmentId", T_TGW_ATTACH),
    ("LocalGatewayId", T_LOCAL_GW),
    ("CoreNetworkArn", T_CORE_NETWORK),
    ("InstanceId", T_INSTANCE),
)

GATEWAY_ID_KINDS = {
    "local": T_LOCAL,
    "igw-": T_INTERNET,
    "vgw-": T_VGW,
    "eigw-": T_EIGW,
    "cgw-": T_CARRIER_GW,
    "lgw-": T_LOCAL_GW,
}


def gateway_id_kind(gateway_id: str) -> str:
    for prefix, kind in GATEWAY_ID_KINDS.items():
        if gateway_id.startswith(prefix):
            return kind
    return T_UNKNOWN


def _tags_dict(tags: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    return {t.get("Key", ""): t.get("Value", "") for t in tags or []}


@dataclass
class Vpc:
    id: str
    region: str
    name: str = ""
    cidr: str = ""
    cidrs: List[str] = field(default_factory=list)
    is_default: bool = False
    flow_logs: List[str] = field(default_factory=list)
    flow_log_status: str = "unknown"
    dhcp_options_id: str = ""
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.name or self.id


@dataclass
class Subnet:
    id: str
    region: str
    vpc_id: str
    cidr: str = ""
    az: str = ""
    az_id: str = ""
    rtb_id: str = ""
    rtb_association: str = ""  # explicit | main | none
    map_public_ip_on_launch: bool = False
    available_ips: int = 0
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name") or self.id

    @property
    def label(self) -> str:
        return f"{self.name} ({self.cidr})"


@dataclass
class Route:
    destination: str
    target_kind: str
    target_id: str
    state: str = "active"
    origin: str = "CreateRouteTable"
    propagated: bool = False
    region: str = ""

    @property
    def key(self) -> str:
        return f"{self.destination}->{self.target_id}"


@dataclass
class RouteTable:
    id: str
    region: str
    vpc_id: str
    name: str = ""
    is_main: bool = False
    subnet_ids: List[str] = field(default_factory=list)
    routes: List[Route] = field(default_factory=list)
    association_count: int = 0
    propagated: bool = False
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.name or self.id

    def route_for(self, ip: str) -> Optional[Route]:
        """Longest-prefix-match route for *ip* (pure table lookup)."""
        from ..util.cidr import longest_prefix_match

        dest = longest_prefix_match((r.destination for r in self.routes), ip)
        if dest is None:
            return None
        for r in self.routes:
            if r.destination == dest and r.state == "active":
                return r
        return None


@dataclass
class Igw:
    id: str
    region: str
    vpc_id: str = ""
    attached: bool = False
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name") or self.id


@dataclass
class NatGw:
    id: str
    region: str
    subnet_id: str = ""
    vpc_id: str = ""
    state: str = ""
    connect_type: str = "public"
    address: str = ""
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name") or self.id


@dataclass
class TgwAttachment:
    id: str
    tgw_id: str
    region: str
    resource_type: str = ""
    resource_id: str = ""
    vpc_id: str = ""
    subnet_ids: List[str] = field(default_factory=list)
    cidr_blocks: List[str] = field(default_factory=list)
    state: str = ""
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class TgwRoute:
    destination: str
    target_kind: str
    target_id: str
    state: str = "active"
    origin: str = ""
    attachment_id: str = ""


@dataclass
class TgwRouteTable:
    id: str
    tgw_id: str
    region: str
    name: str = ""
    default_association: bool = False
    default_propagation: bool = False
    routes: List[TgwRoute] = field(default_factory=list)
    associations: List[str] = field(default_factory=list)
    propagations: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class Tgw:
    id: str
    region: str
    owner_id: str = ""
    state: str = ""
    name: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    attachments: List[TgwAttachment] = field(default_factory=list)
    route_tables: List[TgwRouteTable] = field(default_factory=list)

    @property
    def label(self) -> str:
        return self.name or self.id


@dataclass
class Peering:
    id: str
    region: str
    vpc_id: str
    peer_vpc_id: str = ""
    peer_owner_id: str = ""
    peer_region: str = ""
    status: str = ""
    dns_enabled: bool = False
    expiry_time: str = ""
    local_vpc_ids: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name") or self.id

    @property
    def intra_region(self) -> bool:
        return not self.peer_region or self.peer_region == self.region


@dataclass
class VpnConnection:
    id: str
    region: str
    vgw_id: str = ""
    vpc_id: str = ""
    state: str = ""
    vpn_type: str = ""
    customer_gw_id: str = ""
    routes: List[str] = field(default_factory=list)


@dataclass
class VpnGateway:
    id: str
    region: str
    vpc_id: str = ""
    state: str = ""
    vpn_type: str = "ipsec.1"
    amazon_side_asn: str = ""
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name") or self.id


@dataclass
class VpcEndpoint:
    id: str
    region: str
    vpc_id: str
    service_name: str = ""
    vpc_endpoint_type: str = ""
    state: str = ""
    subnet_ids: List[str] = field(default_factory=list)
    sg_ids: List[str] = field(default_factory=list)
    policy: str = ""
    private_dns: str = ""
    route_table_ids: List[str] = field(default_factory=list)
    network_interface_ids: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name") or self.id

    @property
    def short_service(self) -> str:
        """com.amazonaws.<region>.<service> -> <service>"""
        if not self.service_name:
            return "endpoint"
        parts = self.service_name.split(".")
        if len(parts) >= 4:
            return ".".join(parts[3:])
        return parts[-1]


@dataclass
class Eni:
    id: str
    region: str
    vpc_id: str
    subnet_id: str = ""
    private_ip: str = ""
    public_ip: str = ""
    primary: bool = True
    interface_type: str = "interface"
    description: str = ""
    sg_ids: List[str] = field(default_factory=list)
    attachment_id: str = ""
    instance_id: str = ""
    requester_managed: bool = False
    owner_id: str = ""
    status: str = ""
    eni_type: str = ""
    # inferred owning workload
    workload_kind: str = ""
    workload_id: str = ""
    workload_name: str = ""

    @property
    def label(self) -> str:
        return self.workload_name or self.id


@dataclass
class NaclEntry:
    rule_number: int
    protocol: str
    rule_action: str
    cidr: str
    port: str = ""
    icmp: str = ""
    egress: bool = False


@dataclass
class Nacl:
    id: str
    region: str
    vpc_id: str
    is_default: bool = False
    entries: List[NaclEntry] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.tags.get("Name") or self.id


@dataclass
class SgRule:
    protocol: str
    from_port: int
    to_port: int
    cidr: str = ""  # may be ""
    sg_id: str = ""
    prefix_list_id: str = ""
    description: str = ""

    @property
    def port_range(self) -> str:
        if self.protocol in ("-1", "all", "tcp", "udp"):
            if self.from_port == -1 or (self.from_port == 0 and self.to_port == 65535):
                return "all"
            return f"{self.from_port}-{self.to_port}" if self.from_port != self.to_port else str(self.from_port)
        return self.protocol


@dataclass
class SecurityGroup:
    id: str
    region: str
    name: str = ""
    description: str = ""
    vpc_id: str = ""
    ingress: List[SgRule] = field(default_factory=list)
    egress: List[SgRule] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class Workload:
    """A non-ENI resource we want on the diagram (ALB, RDS, EKS, Lambda...)."""

    id: str
    kind: str
    region: str
    vpc_id: str = ""
    name: str = ""
    subnet_ids: List[str] = field(default_factory=list)
    sg_ids: List[str] = field(default_factory=list)
    eni_ids: List[str] = field(default_factory=list)
    state: str = ""
    detail: str = ""
    engine: str = ""
    private_ips: List[str] = field(default_factory=list)
    public_ips: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return self.name or self.id


@dataclass
class AccountSnapshot:
    """Everything collected for a single region."""

    region: str
    vpcs: List[Vpc] = field(default_factory=list)
    subnets: List[Subnet] = field(default_factory=list)
    route_tables: List[RouteTable] = field(default_factory=list)
    igws: List[Igw] = field(default_factory=list)
    nat_gateways: List[NatGw] = field(default_factory=list)
    tgws: List[Tgw] = field(default_factory=list)
    peerings: List[Peering] = field(default_factory=list)
    vpn_gateways: List[VpnGateway] = field(default_factory=list)
    vpn_connections: List[VpnConnection] = field(default_factory=list)
    endpoints: List[VpcEndpoint] = field(default_factory=list)
    enis: List[Eni] = field(default_factory=list)
    nacls: List[Nacl] = field(default_factory=list)
    security_groups: List[SecurityGroup] = field(default_factory=list)
    workloads: List[Workload] = field(default_factory=list)
    account_id: str = ""
    partition: str = "aws"
    errors: List[str] = field(default_factory=list)


# --- normalisers ------------------------------------------------------------


def parse_route(raw: Dict[str, Any], region: str) -> Route:
    dest = (
        raw.get("DestinationCidrBlock")
        or raw.get("DestinationIpv6CidrBlock")
        or raw.get("DestinationPrefixListId")
        or ""
    )
    target_kind = T_UNKNOWN
    target_id = ""
    for fname, kind in TARGET_FIELD_MAP:
        val = raw.get(fname)
        if not val:
            continue
        target_id = val
        if fname == "GatewayId":
            target_kind = gateway_id_kind(val)
        else:
            target_kind = kind or T_UNKNOWN
        break
    return Route(
        destination=dest,
        target_kind=target_kind,
        target_id=target_id,
        state=raw.get("State", "active"),
        origin=raw.get("Origin", ""),
        propagated=bool(raw.get("PropagatingVgw", False)),
        region=region,
    )


def vpc_from(v: Dict[str, Any], region: str) -> Vpc:
    tags = _tags_dict(v.get("Tags"))
    cidrs = []
    for assoc in v.get("CidrBlockAssociationSet", []) or []:
        raw_blk = assoc.get("CidrBlock")
        blk = raw_blk.get("CidrBlock") if isinstance(raw_blk, dict) else raw_blk
        state = (assoc.get("CidrBlockState") or {}).get("State")
        if blk and state in ("associated", "associating"):
            cidrs.append(blk)
    primary = v.get("CidrBlock") or (cidrs[0] if cidrs else "")
    if primary and primary not in cidrs:
        cidrs.insert(0, primary)
    fls = v.get("FlowLogs") or []
    return Vpc(
        id=v["VpcId"],
        region=region,
        name=tags.get("Name", ""),
        cidr=primary,
        cidrs=cidrs,
        is_default=bool(v.get("IsDefault")),
        flow_logs=[f.get("FlowLogId", "") for f in fls if isinstance(f, dict)],
        flow_log_status="enabled" if fls else "not-configured",
        dhcp_options_id=(v.get("DhcpOptionsId") or ""),
            tags=tags,
    )


def subnet_from(s: Dict[str, Any], region: str) -> Subnet:
    return Subnet(
        id=s["SubnetId"],
        region=region,
        vpc_id=s.get("VpcId", ""),
        cidr=s.get("CidrBlock", "") or s.get("Ipv6CidrBlock", ""),
        az=s.get("AvailabilityZone", ""),
        az_id=s.get("AvailabilityZoneId", ""),
        map_public_ip_on_launch=bool(s.get("MapPublicIpOnLaunch")),
        available_ips=int(s.get("AvailableIpAddressCount") or 0),
        tags=_tags_dict(s.get("Tags")),
    )


def route_table_from(rt: Dict[str, Any], region: str) -> RouteTable:
    subnet_ids: List[str] = []
    is_main = False
    assoc_count = 0
    for a in rt.get("Associations", []) or []:
        assoc_count += 1
        if a.get("Main"):
            is_main = True
        sid = a.get("SubnetId")
        if sid:
            subnet_ids.append(sid)
    return RouteTable(
        id=rt["RouteTableId"],
        region=region,
        vpc_id=rt.get("VpcId", ""),
        name=_tags_dict(rt.get("Tags")).get("Name", ""),
        is_main=is_main,
        subnet_ids=subnet_ids,
        routes=[parse_route(r, region) for r in rt.get("Routes", []) or []],
        association_count=assoc_count,
        propagated=bool(rt.get("PropagatingVgw")),
        tags=_tags_dict(rt.get("Tags")),
    )


def eni_from(e: Dict[str, Any], region: str) -> Eni:
    assoc = e.get("Association") or {}
    private = e.get("PrivateIpAddress") or ""
    addrs = e.get("PrivateIpAddresses") or []
    primary = not addrs or bool(addrs[0].get("Primary")) or private == addrs[0].get(
        "PrivateIpAddress", ""
    )
    attachment = (e.get("Attachment") or {}).get("AttachmentId", "")
    return Eni(
        id=e["NetworkInterfaceId"],
        region=region,
        vpc_id=e.get("VpcId", ""),
        subnet_id=e.get("SubnetId", ""),
        private_ip=private,
        public_ip=assoc.get("PublicIp", "") or "",
        primary=primary,
        interface_type=e.get("InterfaceType") or "interface",
        description=(e.get("Description") or "").strip(),
        sg_ids=[g["GroupId"] for g in e.get("Groups", []) or [] if g.get("GroupId")],
        # describe_network_interfaces has no Attachment.InstanceId. The field is
        # Attachment.AttachmentId, and for an EC2 instance ENI that value *is*
        # the instance id. Reading a non-existent key made instance_id always
        # empty against real AWS, which silently broke every ALB -> target path
        # (the target could never be resolved back to its ENI).
        attachment_id=attachment,
        # Only an EC2 instance attachment carries an i- id. For other attachment
        # types (natgw-, elasticmapreduce-, eipassoc-) it is not an instance.
        instance_id=attachment if attachment.startswith("i-") else "",
        requester_managed=bool(e.get("RequesterManaged")),
        owner_id=e.get("OwnerId") or "",
        status=e.get("Status", ""),
        eni_type=e.get("InterfaceType") or "",
    )


def _int_port(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _sg_rules(raw: List[Dict[str, Any]]) -> List[SgRule]:
    """Flatten describe_security_groups IpPermissions into one rule per source."""
    rules: List[SgRule] = []
    for perm in raw or []:
        proto = perm.get("IpProtocol") or "-1"
        lo = _int_port(perm.get("FromPort"))
        hi = _int_port(perm.get("ToPort"))
        desc = perm.get("Description") or ""
        sources: List[Dict[str, str]] = []
        for entry in perm.get("IpRanges", []) or []:
            sources.append({"kind": "cidr", "value": entry.get("CidrIp", "") or ""})
        for entry in perm.get("Ipv6Ranges", []) or []:
            sources.append({"kind": "cidr", "value": entry.get("CidrIpv6", "") or ""})
        for entry in perm.get("UserIdGroupPairs", []) or []:
            sources.append({"kind": "sg", "value": entry.get("GroupId", "") or ""})
        for entry in perm.get("PrefixListIds", []) or []:
            sources.append({"kind": "prefix", "value": entry.get("PrefixListId", "") or ""})
        if not sources:
            sources.append({"kind": "cidr", "value": ""})
        for source in sources:
            rules.append(
                SgRule(
                    protocol=proto,
                    from_port=lo,
                    to_port=hi,
                    cidr=source["value"] if source["kind"] == "cidr" else "",
                    sg_id=source["value"] if source["kind"] == "sg" else "",
                    prefix_list_id=source["value"] if source["kind"] == "prefix" else "",
                    description=desc,
                )
            )
    return rules


def sg_from(sg: Dict[str, Any], region: str) -> SecurityGroup:
    return SecurityGroup(
        id=sg["GroupId"],
        region=region,
        name=sg.get("GroupName", ""),
        description=sg.get("Description", ""),
        vpc_id=sg.get("VpcId", ""),
        ingress=_sg_rules(sg.get("IpPermissions", [])),
        egress=_sg_rules(sg.get("IpPermissionsEgress", [])),
        tags=_tags_dict(sg.get("Tags")),
    )


def nacl_from(n: Dict[str, Any], region: str) -> Nacl:
    entries = []
    for e in n.get("Entries", []) or []:
        entries.append(
            NaclEntry(
                rule_number=int(e.get("RuleNumber", 0)),
                protocol=str(e.get("Protocol", "")),
                rule_action=str(e.get("RuleAction", "")),
                cidr=e.get("CidrBlock", "") or e.get("Ipv6CidrBlock", "") or "",
                port=f"{e.get('PortRange', {}).get('From', '')}-{e.get('PortRange', {}).get('To', '')}"
                if e.get("PortRange")
                else "",
                icmp=e.get("IcmpTypeCode", {}).get("Type", "") if e.get("IcmpTypeCode") else "",
                egress=bool(e.get("Egress")),
            )
        )
    return Nacl(
        id=n["NetworkAclId"],
        region=region,
        vpc_id=n.get("VpcId", ""),
        is_default=bool(n.get("IsDefault")),
        entries=entries,
        tags=_tags_dict(n.get("Tags")),
    )
