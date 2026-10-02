"""Read-only AWS inventory collection.

Design notes
------------
* Every API call is optional. A failed/unavailable call is recorded in
  ``AccountSnapshot.errors`` and never aborts the run.
* Responses are cached on disk (``--cache-dir``) so a run can be re-rendered
  offline with ``--offline`` without touching the API again.
* One thread-local client per region; calls are dispatched through a small
  thread pool.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import os
import threading
from dataclasses import asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from . import model as M
from .model import AccountSnapshot

DEFAULT_CACHE_VERSION = 1


class CollectorError(Exception):
    pass


# --------------------------------------------------------------------------- #
# low level AWS helpers
# --------------------------------------------------------------------------- #


def _paged(
    client,
    op: str,
    result_key: str,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Return every item of *result_key*, following NextToken when needed."""
    items: List[Dict[str, Any]] = []
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        resp = client.__getattribute__(op)(**params)
        page = resp.get(result_key) or []
        items.extend(page)
        if not resp.get("NextToken"):
            break
        token = resp["NextToken"]
    return items


class OfflineClient:
    """Stand-in handed out in offline mode; every real call is a bug."""

    def __init__(self, service: str, region: str):
        self._service = service
        self._region = region

    def __getattr__(self, op: str):
        def call(**_kwargs):
            raise CollectorError(
                f"offline mode cannot call {self._service}.{op} in {self._region}; "
                "run without --offline to refresh the cache"
            )

        return call


class RegionClientPool:
    """Thread-local boto3 clients (clients are cheap-ish but not shareable)."""

    def __init__(self, session, region: str):
        self._session = session
        self._region = region
        self._local = threading.local()

    def get(self, service: str):
        if self._session is None:  # offline: cache-only, never build a client
            return OfflineClient(service, self._region)
        key = f"_{service}"
        client = getattr(self._local, key, None)
        if client is None:
            client = self._session.client(
                service,
                region_name=self._region,
                config=_client_config(),
            )
            setattr(self._local, key, client)
        return client


def _client_config():
    from botocore.config import Config

    return Config(
        retries={"max_attempts": 4, "mode": "standard"},
        connect_timeout=10,
        read_timeout=60,
        max_pool_connections=32,
        user_agent_extra="aws-network-mapper",
    )


class Cache:
    def __init__(self, root: Optional[str], enabled: bool = True):
        self.root = root
        self.enabled = enabled and bool(root)
        self.hits = 0
        self.writes = 0

    def path(self, region: str, key: str) -> Optional[str]:
        if not self.enabled:
            return None
        safe = key.replace("/", "_").replace(" ", "_")
        return os.path.join(self.root or "", region, f"{safe}.json")

    def load(self, region: str, key: str) -> Optional[Any]:
        p = self.path(region, key)
        if not p or not os.path.exists(p):
            return None
        try:
            with open(p, "r", encoding="utf-8") as fh:
                self.hits += 1
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def save(self, region: str, key: str, value: Any) -> None:
        p = self.path(region, key)
        if not p:
            return
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            tmp = p + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(value, fh, default=str)
            os.replace(tmp, p)
            self.writes += 1
        except (OSError, TypeError):
            pass


# --------------------------------------------------------------------------- #
# collector
# --------------------------------------------------------------------------- #


class Collector:
    OPTIONAL_SERVICES = ("ec2-workloads", "elbv2", "rds", "ecs", "eks", "lambda")

    def __init__(
        self,
        regions: List[str],
        *,
        cache_dir: Optional[str] = None,
        offline: bool = False,
        services: Iterable[str] = OPTIONAL_SERVICES,
        max_workers: int = 8,
        log: Optional[Callable[[str], None]] = None,
        pool_factory: Optional[Callable[[str], Any]] = None,
    ):
        self.regions = regions
        self.offline = offline
        self._started = False
        self.services = set(services)
        self.max_workers = max_workers
        self.cache = Cache(cache_dir)
        self.log = log or (lambda _m: None)
        self.session = None
        self.pool_factory = pool_factory
        self.account_id = ""
        self.partition = "aws"
        self.errors: List[str] = []

    # -- session ---------------------------------------------------------
    def start(self) -> None:
        if self.offline:
            # nothing but the cache is read, so boto3 is not needed
            self._started = True
            return None
        try:
            import boto3  # noqa: WPS433 (runtime import is intentional)
        except ImportError as exc:  # pragma: no cover
            raise CollectorError(
                "boto3 is required. In AWS CloudShell it is pre-installed; "
                "else run: pip install boto3"
            ) from exc
        self.session = boto3.Session()
        self._started = True
        if not self.offline:
            try:
                ident = self.session.client("sts", config=_client_config()).get_caller_identity()
                self.account_id = ident.get("Account", "")
                self.partition = ident.get("Arn", "").split(":")[1] or "aws"
            except Exception as exc:  # noqa: BLE001
                self.errors.append(f"sts.get-caller-identity failed: {exc}")
                self.log("! could not read caller identity")

    def resolve_regions(self, requested: Optional[List[str]] = None) -> List[str]:
        if requested:
            return requested
        env = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        if env and not self.regions:
            return [env]
        if self.regions:
            return self.regions
        if self.offline:
            if self.cache.enabled and os.path.isdir(self.cache.root or ""):
                return sorted(os.listdir(self.cache.root or ""))
            return []
        client = self.session.client("ec2", config=_client_config())
        regions = []
        for r in _paged(client, "describe_regions", "Regions", AllRegions=False):
            if r.get("OptInStatus") in ("not-opted-in",):
                continue
            regions.append(r["RegionName"])
        return sorted(regions)

    # -- per region ------------------------------------------------------
    def collect_region(self, region: str) -> AccountSnapshot:
        snap = AccountSnapshot(
            region=region, account_id=self.account_id, partition=self.partition
        )
        if not self._started:
            raise CollectorError("collector not started; call start() first")
        pool = self.pool_factory(region) if self.pool_factory else RegionClientPool(self.session, region)
        jobs: List[Tuple[str, Callable[[], None]]] = []

        def job(name: str, fn: Callable[[], None]):
            jobs.append((name, fn))

        ec2 = lambda: pool.get("ec2")  # noqa: E731

        # --- core network (always) ---
        job("vpcs", lambda: setattr(snap, "vpcs", self._ec2(ec2, region, "describe_vpcs", "Vpcs", vpc_from=M.vpc_from)))
        job("subnets", lambda: setattr(snap, "subnets", self._ec2(ec2, region, "describe_subnets", "Subnets", vpc_from=M.subnet_from)))
        job("route_tables", lambda: setattr(snap, "route_tables", self._ec2(ec2, region, "describe_route_tables", "RouteTables", vpc_from=M.route_table_from)))
        job("igws", lambda: setattr(snap, "igws", self._collect_igws(ec2, region)))
        job("nat_gateways", lambda: setattr(snap, "nat_gateways", self._collect_nat(ec2, region)))
        job("tgws", lambda: setattr(snap, "tgws", self._collect_tgws(ec2, region)))
        job("peerings", lambda: setattr(snap, "peerings", self._collect_peerings(ec2, region)))
        job("vpn", lambda: self._collect_vpn(ec2, region, snap))
        job("endpoints", lambda: setattr(snap, "endpoints", self._collect_endpoints(ec2, region)))
        job("enis", lambda: setattr(snap, "enis", self._collect_enis(ec2, region)))
        job("security_groups", lambda: setattr(snap, "security_groups", self._ec2(ec2, region, "describe_security_groups", "SecurityGroups", vpc_from=M.sg_from)))
        job("nacls", lambda: setattr(snap, "nacls", self._collect_nacls(ec2, region)))

        # --- workloads / service integrations (optional) ---
        if "ec2-workloads" in self.services:
            job("instances", lambda: self._collect_instances(ec2, region, snap))
        if "elbv2" in self.services:
            job("elbv2", lambda: self._collect_elbv2(pool, region, snap))
        if "rds" in self.services:
            job("rds", lambda: self._collect_rds(pool, region, snap))
        if "ecs" in self.services:
            job("ecs", lambda: self._collect_ecs(pool, region, snap))
        if "eks" in self.services:
            job("eks", lambda: self._collect_eks(pool, region, snap))
        if "lambda" in self.services:
            job("lambda", lambda: self._collect_lambda(pool, region, snap))

        with cf.ThreadPoolExecutor(max_workers=self.max_workers) as pool_ex:
            futures = {pool_ex.submit(fn): name for name, fn in jobs}
            for fut in cf.as_completed(futures):
                name = futures[fut]
                try:
                    fut.result()
                except Exception as exc:  # noqa: BLE001
                    msg = f"{region}:{name}: {type(exc).__name__}: {exc}"
                    snap.errors.append(msg)
                    self.errors.append(msg)
                    self.log(f"! {msg[:160]}")

        self._resolve_subnet_routes(snap)
        self._resolve_workload_vpcs(snap)
        self._attribute_enis(snap)
        return snap

    # -- generic cached call --------------------------------------------
    def _call(
        self,
        region: str,
        key: str,
        fn: Callable[[], Any],
    ) -> Any:
        cached = self.cache.load(region, key)
        if cached is not None:
            return cached
        if self.offline:
            raise CollectorError(f"offline and no cache for {region}/{key}")
        value = fn()
        self.cache.save(region, key, value)
        return value

    def _ec2(self, ec2_client, region: str, op: str, key: str, vpc_from: Callable) -> List[Any]:
        raw = self._call(region, op, lambda: _paged(ec2_client(), op, key))
        return [vpc_from(item, region) for item in raw]

    # -- individual collectors -----------------------------------------
    def _collect_igws(self, ec2_client, region: str) -> List[M.Igw]:
        raw = self._call(region, "describe_internet_gateways", lambda: _paged(ec2_client(), "describe_internet_gateways", "InternetGateways"))
        out = []
        for i in raw:
            attachments = [
                a.get("VpcId", "")
                for a in i.get("Attachments", []) or []
                if a.get("State") == "available"
            ]
            out.append(
                M.Igw(
                    id=i["InternetGatewayId"],
                    region=region,
                    vpc_id=attachments[0] if attachments else "",
                    attached=bool(attachments),
                    tags=M._tags_dict(i.get("Tags")),
                )
            )
        return out

    def _collect_nat(self, ec2_client, region: str) -> List[M.NatGw]:
        raw = self._call(region, "describe_nat_gateways", lambda: _paged(ec2_client(), "describe_nat_gateways", "NatGateways"))
        return [
            M.NatGw(
                id=n["NatGatewayId"],
                region=region,
                subnet_id=(n.get("SubnetId") or ""),
                vpc_id=(n.get("VpcId") or ""),
                state=n.get("State", ""),
                connect_type=n.get("ConnectivityType", "public"),
                address=((n.get("NatGatewayAddresses") or [{}])[0] or {}).get("AllocationId", ""),
                tags=M._tags_dict(n.get("Tags")),
            )
            for n in raw
        ]

    def _collect_tgws(self, ec2_client, region: str) -> List[M.Tgw]:
        raw = self._call(region, "describe_transit_gateways", lambda: _paged(ec2_client(), "describe_transit_gateways", "TransitGateways"))
        tgws = [
            M.Tgw(
                id=t["TransitGatewayId"],
                region=region,
                owner_id=t.get("OwnerId", ""),
                state=t.get("State", ""),
                name=M._tags_dict(t.get("Tags")).get("Name", ""),
                tags=M._tags_dict(t.get("Tags")),
            )
            for t in raw
        ]
        if not tgws:
            return []
        tgw_ids = [t.id for t in tgws]

        atts = self._call(
            region,
            "describe_transit_gateway_attachments",
            lambda: _paged(
                ec2_client(),
                "describe_transit_gateway_attachments",
                "TransitGatewayAttachments",
            ),
        )
        for a in atts:
            owner = next((t for t in tgws if t.id == a.get("TransitGatewayId")), None)
            if owner is None:
                continue
            cidr = a.get("CidrBlock") or ""
            cidr_blocks = [cidr] if cidr else []
            owner.attachments.append(
                M.TgwAttachment(
                    id=a["TransitGatewayAttachmentId"],
                    tgw_id=owner.id,
                    region=region,
                    resource_type=a.get("ResourceType", ""),
                    resource_id=a.get("ResourceId", ""),
                    vpc_id=a.get("ResourceId", "") if a.get("ResourceType") == "vpc" else "",
                    subnet_ids=list(a.get("SubnetIds", []) or []),
                    cidr_blocks=cidr_blocks,
                    state=a.get("State", ""),
                    tags=M._tags_dict(a.get("Tags")),
                )
            )

        rtbs = self._call(
            region,
            "describe_transit_gateway_route_tables",
            lambda: _paged(
                ec2_client(),
                "describe_transit_gateway_route_tables",
                "TransitGatewayRouteTables",
            ),
        )
        for r in rtbs:
            owner = next((t for t in tgws if t.id == r.get("TransitGatewayId")), None)
            if owner is None:
                continue
            trt = M.TgwRouteTable(
                id=r["TransitGatewayRouteTableId"],
                tgw_id=owner.id,
                region=region,
                name=M._tags_dict(r.get("Tags")).get("Name", ""),
                default_association=bool(r.get("DefaultAssociationRouteTable")),
                default_propagation=bool(r.get("DefaultPropagationRouteTable")),
                associations=[a.get("TransitGatewayAttachmentId", "") for a in r.get("Associations", []) or []],
                propagations=[p.get("TransitGatewayAttachmentId", "") for p in r.get("Propagation", []) or []],
                tags=M._tags_dict(r.get("Tags")),
            )
            routes = self._call(
                region,
                f"search_transit_gateway_routes:{trt.id}",
                lambda tid=trt.id: _paged(
                    ec2_client(),
                    "search_transit_gateway_routes",
                    "Routes",
                    TransitGatewayRouteTableId=tid,
                    Filters=[{"Name": "state", "Values": ["active"]}],
                ),
            )
            for rt in routes:
                target_kind, target_id = M.T_UNKNOWN, ""
                for field_name, kind in (
                    ("TransitGatewayAttachmentId", M.T_TGW_ATTACH),
                    ("GatewayId", None),
                    ("TransitGatewayId", M.T_TGW),
                    ("VpcId", ""),
                    ("CoreNetworkArn", M.T_CORE_NETWORK),
                    ("Blackhole", M.T_UNKNOWN),
                ):
                    val = rt.get(field_name)
                    if val:
                        target_id = str(val)
                        target_kind = (
                            M.gateway_id_kind(val)
                            if field_name == "GatewayId"
                            else (kind or "vpc")
                        )
                        break
                trt.routes.append(
                    M.TgwRoute(
                        destination=rt.get("DestinationCidrBlock", ""),
                        target_kind=target_kind,
                        target_id=target_id,
                        state=rt.get("State", "active"),
                        origin=rt.get("Origin", ""),
                        attachment_id=rt.get("TransitGatewayAttachmentId", ""),
                    )
                )
            owner.route_tables.append(trt)
        return tgws

    def _collect_peerings(self, ec2_client, region: str) -> List[M.Peering]:
        raw = self._call(
            region,
            "describe_vpc_peering_connections",
            lambda: _paged(ec2_client(), "describe_vpc_peering_connections", "VpcPeeringConnections"),
        )
        out = []
        for p in raw:
            req = p.get("VpcPeeringConnection") or {}
            status = (p.get("Status") or {}).get("Code", "")
            out.append(
                M.Peering(
                    id=p["VpcPeeringConnectionId"],
                    region=region,
                    vpc_id=req.get("VpcId", ""),
                    peer_vpc_id=req.get("PeeredVpcId", ""),
                    peer_owner_id=req.get("PeerOwnerId", "") or p.get("AccepterVpcInfo", {}).get("OwnerId", ""),
                    peer_region=req.get("PeerRegion", ""),
                    status=status,
                    dns_enabled=bool(
                        (p.get("Options") or {}).get("AllowDnsResolutionFromRemoteVpc", False)
                    ),
                    expiry_time=req.get("ExpirationTime", "") or "",
                    local_vpc_ids=[req.get("VpcId", "")],
                    tags=M._tags_dict(req.get("Tags")) or M._tags_dict(p.get("Tags")),
                )
            )
        return out

    def _collect_vpn(self, ec2_client, region: str, snap: AccountSnapshot) -> None:
        gateways = self._call(
            region,
            "describe_vpn_gateways",
            lambda: _paged(ec2_client(), "describe_vpn_gateways", "VpnGateways"),
        )
        snap.vpn_gateways = [
            M.VpnGateway(
                id=g["VpnGatewayId"],
                region=region,
                vpc_id=(g.get("VpcAttachments") or [{}])[0].get("VpcId", "")
                if g.get("VpcAttachments")
                else "",
                state=g.get("State", ""),
                vpn_type=g.get("Type", ""),
                amazon_side_asn=str(g.get("AmazonSideAsn", "")),
                tags=M._tags_dict(g.get("Tags")),
            )
            for g in gateways
        ]
        conns = self._call(
            region,
            "describe_vpn_connections",
            lambda: _paged(ec2_client(), "describe_vpn_connections", "VpnConnections"),
        )
        snap.vpn_connections = [
            M.VpnConnection(
                id=c["VpnConnectionId"],
                region=region,
                vgw_id=(c.get("VpnGatewayId") or ""),
                vpc_id=(c.get("VgwTelemetry") or [{}])[0].get("VpcId", "")
                if c.get("VgwTelemetry")
                else "",
                state=c.get("State", ""),
                vpn_type=c.get("Type", ""),
                customer_gw_id=c.get("CustomerGatewayId", ""),
                routes=[
                    r.get("DestinationCidrBlock", "")
                    for r in c.get("VgwTelemetry", []) or []
                    if r.get("DestinationCidrBlock")
                ],
            )
            for c in conns
        ]

    def _collect_endpoints(self, ec2_client, region: str) -> List[M.VpcEndpoint]:
        raw = self._call(
            region,
            "describe_vpc_endpoints",
            lambda: _paged(ec2_client(), "describe_vpc_endpoints", "VpcEndpoints"),
        )
        out = []
        for e in raw:
            groups = [
                g.get("GroupId", "")
                for g in ((e.get("GroupsList") or []) + (e.get("SecurityGroupIdList") or []))
                if g.get("GroupId")
            ]
            policy = ""
            if e.get("PolicyDocument"):
                try:
                    parsed = json.loads(e["PolicyDocument"])
                    statements = parsed.get("Statement", [])
                    allow_all = any(
                        s.get("Effect") == "Allow"
                        and s.get("Action") in ("*", "s3:*")
                        and "*" in (s.get("Resource") or "*")
                        and s.get("Principal") in ("*", {"AWS": "*"}, None)
                        for s in statements
                    )
                    policy = "allow-all" if allow_all else f"{len(statements)}-stmt"
                except ValueError:
                    policy = "unparsable"
            out.append(
                M.VpcEndpoint(
                    id=e["VpcEndpointId"],
                    region=region,
                    vpc_id=e.get("VpcId", ""),
                    service_name=e.get("ServiceName", ""),
                    vpc_endpoint_type=e.get("VpcEndpointType", ""),
                    state=e.get("State", ""),
                    subnet_ids=list((e.get("SubnetIdList") or []) + ([e["SubnetId"]] if e.get("SubnetId") else [])),
                    sg_ids=groups,
                    policy=policy,
                    private_dns=e.get("PrivateDnsName", "") or "",
                    route_table_ids=list(e.get("RouteTableIdList") or []),
                    network_interface_ids=list(e.get("NetworkInterfaceIdList") or []),
                    tags=M._tags_dict(e.get("Tags")),
                )
            )
        return out

    def _collect_enis(self, ec2_client, region: str) -> List[M.Eni]:
        raw = self._call(
            region,
            "describe_network_interfaces",
            lambda: _paged(ec2_client(), "describe_network_interfaces", "NetworkInterfaces"),
        )
        return [M.eni_from(e, region) for e in raw]

    def _collect_nacls(self, ec2_client, region: str) -> List[M.Nacl]:
        raw = self._call(
            region,
            "describe_network_acls",
            lambda: _paged(ec2_client(), "describe_network_acls", "NetworkAcls"),
        )
        return [M.nacl_from(n, region) for n in raw]

    def _collect_instances(self, ec2_client, region: str, snap: AccountSnapshot) -> None:
        raw = self._call(
            region,
            "describe_instances",
            lambda: _paged(
                ec2_client(),
                "describe_instances",
                "Reservations",
            ),
        )
        workloads = snap.workloads
        instances: List[Dict[str, Any]] = []
        for res in raw:
            if "Instances" in res:
                instances.extend(res.get("Instances") or [])
            else:
                instances.append(res)
        for inst in instances:
                sg_ids = sorted(
                    {g["GroupId"] for g in inst.get("SecurityGroups", []) or [] if g.get("GroupId")}
                )
                eni_ids = [e["NetworkInterfaceId"] for e in inst.get("NetworkInterfaces", []) or []]
                private_ips = [e.get("PrivateIpAddress", "") for e in inst.get("NetworkInterfaces", []) or []]
                public_ips = [
                    e["Association"].get("PublicIp", "")
                    for e in inst.get("NetworkInterfaces", []) or []
                    if e.get("Association")
                ]
                tags = M._tags_dict(inst.get("Tags"))
                workloads.append(
                    M.Workload(
                        id=inst["InstanceId"],
                        kind="ec2",
                        region=region,
                        vpc_id=inst.get("VpcId", ""),
                        name=tags.get("Name", ""),
                        subnet_ids=sorted({e["SubnetId"] for e in inst.get("NetworkInterfaces", []) or [] if e.get("SubnetId")}),
                        sg_ids=sg_ids,
                        eni_ids=eni_ids,
                        state=(inst.get("State") or {}).get("Name", ""),
                        engine=inst.get("InstanceType", ""),
                        private_ips=[ip for ip in private_ips if ip],
                        public_ips=[ip for ip in public_ips if ip],
                        detail=tags.get("Name", ""),
                        extra={"ami": (inst.get("ImageId") or ""), "az": inst.get("Placement", {}).get("AvailabilityZone", "")},
                    )
                )

    def _collect_elbv2(self, pool, region: str, snap: AccountSnapshot) -> None:
        client = pool.get("elbv2")

        def lbs():
            return _paged(client, "describe_load_balancers", "LoadBalancers")

        raw = self._call(region, "elbv2.describe_load_balancers", lbs)

        def tgs():
            groups = _paged(client, "describe_target_groups", "TargetGroups")
            return groups

        target_groups = self._call(region, "elbv2.describe_target_groups", tgs)
        tg_targets: Dict[str, List[Dict[str, Any]]] = {}
        for tg in target_groups:
            def fetch(tid=tg["TargetGroupArn"]):
                try:
                    return _paged(client, "describe_target_health", "TargetHealthDescriptions", TargetGroupArn=tid)
                except Exception:  # noqa: BLE001
                    return []

            tg_slug = "/".join(tg.get("TargetGroupArn", "unknown").split("/")[-2:])
            health = self._call(region, f"elbv2.target_health:{tg_slug}", fetch)
            tg_targets[tg["TargetGroupArn"]] = health

        for lb in raw:
            lb_arn = lb["LoadBalancerArn"]
            lb_id = lb_arn.rsplit("/", 1)[-1]
            name = lb.get("LoadBalancerName", "")
            azs = lb.get("AvailabilityZones", []) or []
            subnet_ids = [a.get("SubnetId") for a in azs if a.get("SubnetId")]
            eni_ids = [a.get("NetworkInterfaceId") for a in azs if a.get("NetworkInterfaceId")]
            sg_ids = list(lb.get("SecurityGroups", []) or [])
            scheme = lb.get("Scheme", "internal")
            dns = lb.get("DNSName", "")
            kind = {"application": "alb", "network": "nlb", "gateway": "gwlb"}.get(
                lb.get("Type", "application"), "lb"
            )
            targets: List[Dict[str, Any]] = []
            for tg in target_groups:
                if lb_arn in (tg.get("LoadBalancerArns") or []):
                    for th in tg_targets.get(tg["TargetGroupArn"], []):
                        target = th.get("Target", {}) or {}
                        targets.append(
                            {
                                "id": target.get("Id", ""),
                                "port": target.get("Port", ""),
                                "zone": target.get("AvailabilityZone", ""),
                                "health": th.get("TargetHealth", {}).get("State", ""),
                                "target_group": tg.get("TargetGroupName", ""),
                                "type": tg.get("TargetType", "instance"),
                            }
                        )
            snap.workloads.append(
                M.Workload(
                    id=lb_id,
                    kind=kind,
                    region=region,
                    vpc_id="",
                    name=name,
                    subnet_ids=[s for s in subnet_ids if s],
                    sg_ids=sg_ids,
                    eni_ids=[e for e in eni_ids if e],
                    state="active" if lb.get("State", {}).get("Code") == "active" else lb.get("State", {}).get("Code", ""),
                    detail=f"{scheme} {kind.upper()}",
                    engine=lb.get("Type", ""),
                    private_ips=[a.get("IpAddress", "") for a in azs if a.get("IpAddress")],
                    public_ips=[a.get("IpAddress", "") for a in azs if a.get("IpAddress") and scheme == "internet-facing"],
                    extra={"scheme": scheme, "dns": dns, "type": lb.get("Type", ""), "targets": targets},
                )
            )

    def _collect_rds(self, pool, region: str, snap: AccountSnapshot) -> None:
        client = pool.get("rds")

        def instances():
            return _paged(client, "describe_db_instances", "DBInstances")

        def subnet_groups():
            return _paged(client, "describe_db_subnet_groups", "DBSubnetGroups")

        dbs = self._call(region, "rds.describe_db_instances", instances)
        sgs = self._call(region, "rds.describe_db_subnet_groups", subnet_groups)
        group_map = {g["DBSubnetGroupName"]: g for g in sgs}
        sg_vpc = {}
        for g in sgs:
            vpc_desc = g.get("VpcId")
            if vpc_desc:
                sg_vpc[g["DBSubnetGroupName"]] = vpc_desc

        for db in dbs:
            group_name = db.get("DBSubnetGroup", {}).get("DBSubnetGroupName", "")
            group = group_map.get(group_name, {})
            subnet_ids = [s.get("SubnetIdentifier") for s in group.get("Subnets", []) or [] if s.get("SubnetIdentifier")]
            sg_ids = [
                s["VpcSecurityGroupId"]
                for s in (group.get("Subnets") or [])
                if s.get("VpcSecurityGroupId")
            ]
            vpc_id = group.get("VpcId", "")
            if not vpc_id:
                vpc_id = self._guess_vpc_from_subnets(snap, subnet_ids)
            endpoint = db.get("Endpoint", {}) or {}
            public = db.get("PubliclyAccessible", False)
            snap.workloads.append(
                M.Workload(
                    id=db.get("DbiResourceId", db.get("DBInstanceIdentifier", "")),
                    kind="rds",
                    region=region,
                    vpc_id=vpc_id,
                    name=db.get("DBInstanceIdentifier", ""),
                    subnet_ids=subnet_ids,
                    sg_ids=sorted(set(sg_ids)),
                    state=db.get("DBInstanceStatus", ""),
                    detail=f"{db.get('Engine', '')} {db.get('DBInstanceClass', '')}".strip(),
                    engine=db.get("Engine", ""),
                    private_ips=[endpoint.get("Address", "")] if endpoint.get("Address") else [],
                    public_ips=[endpoint.get("Address", "")] if public and endpoint.get("Address") else [],
                    extra={
                        "multi_az": db.get("MultiAZ", False),
                        "public": public,
                        "engine": db.get("Engine", ""),
                        "encrypted": db.get("StorageEncrypted", False),
                        "subnet_group": group_name,
                        "endpoint": endpoint.get("Address", ""),
                        "port": endpoint.get("Port", ""),
                    },
                )
            )

    def _collect_ecs(self, pool, region: str, snap: AccountSnapshot) -> None:
        client = pool.get("ecs")

        def clusters():
            return [c["clusterArn"] for c in _paged(client, "list_clusters", "clusterArns")]

        cluster_arns = self._call(region, "ecs.list_clusters", clusters)
        if not cluster_arns:
            return
        described = self._call(
            region,
            "ecs.describe_clusters",
            lambda: client.describe_clusters(clusters=cluster_arns).get("clusters", []),
        )
        for cluster in described:
            vpc_cfg = cluster.get("resourcesVpcConfig") or {}
            subnets = list(vpc_cfg.get("subnetIds") or [])
            snap.workloads.append(
                M.Workload(
                    id=cluster.get("clusterName", ""),
                    kind="ecs-cluster",
                    region=region,
                    vpc_id=vpc_cfg.get("vpcId", "") or self._guess_vpc_from_subnets(snap, subnets),
                    name=cluster.get("clusterName", ""),
                    subnet_ids=subnets,
                    sg_ids=list(vpc_cfg.get("securityGroups") or []),
                    state=cluster.get("status", ""),
                    detail=f"{cluster.get('registeredContainerInstancesCount', 0)} instances",
                    extra={"cluster_arn": cluster.get("clusterArn", "")},
                )
            )
            try:
                services = self._call(
                    region,
                    f"ecs.services:{cluster.get('clusterName')}",
                    lambda arn=cluster.get("clusterArn", ""): [
                        s["serviceArn"]
                        for s in _paged(client, "list_services", "serviceArns", cluster=arn)
                    ],
                )
                if not services:
                    continue
                svc_desc = self._call(
                    region,
                    f"ecs.describe_services:{cluster.get('clusterName')}",
                    lambda arn=cluster.get("clusterArn", ""), svcs=list(services): client.describe_services(
                        cluster=arn, services=svcs
                    ).get("services", []),
                )
            except Exception:  # noqa: BLE001
                continue
            for svc in svc_desc:
                awsvpc = (svc.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
                svc_subnets = list(awsvpc.get("subnets") or [])
                if not svc_subnets:
                    continue
                snap.workloads.append(
                    M.Workload(
                        id=svc.get("serviceArn", "").rsplit("/", 2)[-2:][0] if svc.get("serviceArn") else "",
                        kind="ecs-service",
                        region=region,
                        vpc_id=self._guess_vpc_from_subnets(snap, svc_subnets),
                        name=svc.get("serviceName", ""),
                        subnet_ids=svc_subnets,
                        sg_ids=list(awsvpc.get("securityGroups") or []),
                        state=svc.get("status", ""),
                        detail=f"{svc.get('desiredCount', 0)} tasks",
                        extra={"cluster": cluster.get("clusterName", ""), "launch_type": svc.get("launchType", "FARGATE")},
                    )
                )

    def _collect_eks(self, pool, region: str, snap: AccountSnapshot) -> None:
        client = pool.get("eks")

        def clusters():
            return _paged(client, "list_clusters", "clusters")

        names = self._call(region, "eks.list_clusters", clusters)
        if not names:
            return
        described = self._call(
            region,
            "eks.describe_cluster",
            lambda: [client.describe_cluster(name=n)["cluster"] for n in names],
        )
        for cluster in described:
            vpc_cfg = cluster.get("resourcesVpcConfig") or {}
            subnets = list(vpc_cfg.get("subnetIds") or [])
            if not subnets:
                continue
            snap.workloads.append(
                M.Workload(
                    id=cluster.get("name", ""),
                    kind="eks",
                    region=region,
                    vpc_id=vpc_cfg.get("vpcId", "") or self._guess_vpc_from_subnets(snap, subnets),
                    name=cluster.get("name", ""),
                    subnet_ids=subnets,
                    sg_ids=list(vpc_cfg.get("securityGroupIds") or []),
                    state=cluster.get("status", ""),
                    detail=f"v{cluster.get('version', '?')}",
                    extra={"endpoint": cluster.get("endpoint", "")},
                )
            )

    def _collect_lambda(self, pool, region: str, snap: AccountSnapshot) -> None:
        client = pool.get("lambda")

        def functions():
            return _paged(client, "list_functions", "Functions")

        fns = self._call(region, "lambda.list_functions", functions)
        for fn in fns:
            vpc_cfg = fn.get("VpcConfig") or {}
            if vpc_cfg.get("VpcId"):
                snap.workloads.append(
                    M.Workload(
                        id=fn.get("FunctionName", ""),
                        kind="lambda",
                        region=region,
                        vpc_id=vpc_cfg.get("VpcId", ""),
                        name=fn.get("FunctionName", ""),
                        subnet_ids=list(vpc_cfg.get("SubnetIds") or []),
                        sg_ids=list(vpc_cfg.get("SecurityGroupIds") or []),
                        state=fn.get("State", "") or "Active",
                        detail=fn.get("Runtime", ""),
                        engine=fn.get("Runtime", ""),
                    )
                )

    # -- post processing -------------------------------------------------
    @staticmethod
    def _guess_vpc_from_subnets(snap: AccountSnapshot, subnet_ids: List[str]) -> str:
        ids = {s for s in subnet_ids if s}
        for subnet in snap.subnets:
            if subnet.id in ids:
                return subnet.vpc_id
        return ""

    @staticmethod
    def _resolve_subnet_routes(snap: AccountSnapshot) -> None:
        """Bind each subnet to its effective route table."""
        explicit: Dict[str, str] = {}
        main_by_vpc: Dict[str, str] = {}
        for rt in snap.route_tables:
            if rt.is_main and rt.vpc_id:
                main_by_vpc.setdefault(rt.vpc_id, rt.id)
            for sid in rt.subnet_ids:
                explicit[sid] = rt.id
        for subnet in snap.subnets:
            if subnet.id in explicit:
                subnet.rtb_id = explicit[subnet.id]
                subnet.rtb_association = "explicit"
            elif subnet.vpc_id in main_by_vpc:
                subnet.rtb_id = main_by_vpc[subnet.vpc_id]
                subnet.rtb_association = "main"
            else:
                subnet.rtb_id = ""
                subnet.rtb_association = "none"
        # VPC cidrs seen on the local route

    @staticmethod
    def _resolve_workload_vpcs(snap: AccountSnapshot) -> None:
        """Fill workload.vpc_id from subnet membership (jobs run in parallel)."""
        subnet_vpc = {s.id: s.vpc_id for s in snap.subnets}
        for wl in snap.workloads:
            if wl.vpc_id:
                continue
            for sid in wl.subnet_ids:
                if sid in subnet_vpc:
                    wl.vpc_id = subnet_vpc[sid]
                    break
            if wl.vpc_id:
                continue
            for eni in snap.enis:
                if eni.id in wl.eni_ids:
                    wl.vpc_id = eni.vpc_id
                    break

    @staticmethod
    def _attribute_enis(snap: AccountSnapshot) -> None:
        """Attach ENIs to the workload that owns them (best effort)."""
        by_eni: Dict[str, M.Workload] = {}
        for wl in snap.workloads:
            for eid in wl.eni_ids:
                by_eni[eid] = wl
        instance_ids = {wl.id: wl for wl in snap.workloads if wl.kind == "ec2"}
        for eni in snap.enis:
            if eni.workload_kind:
                continue
            wl = by_eni.get(eni.id)
            if wl is not None:
                eni.workload_kind = wl.kind
                eni.workload_id = wl.id
                eni.workload_name = wl.label
                continue
            if eni.instance_id and eni.instance_id in instance_ids:
                wl = instance_ids[eni.instance_id]
                eni.workload_kind = wl.kind
                eni.workload_id = wl.id
                eni.workload_name = wl.label
                continue
            eni.workload_kind, eni.workload_id, eni.workload_name = infer_eni_owner(eni, snap)


def infer_eni_owner(eni: M.Eni, snap: AccountSnapshot) -> Tuple[str, str, str]:
    """Guess which service owns an unattached-looking ENI from its metadata."""
    desc = (eni.description or "").lower()
    iface = (eni.interface_type or "").lower()

    if iface == "natgateway" or "nat gateway" in desc or "elastic nat gateway" in desc:
        nat = next((n for n in snap.nat_gateways if n.subnet_id == eni.subnet_id and not n.tags), None)
        nat = nat or next((n for n in snap.nat_gateways if n.subnet_id == eni.subnet_id), None)
        if nat:
            return "nat-gateway-eni", nat.id, nat.name
    if "elb" in desc or "elb app/" in desc or "elb net/" in desc or "elb gw/" in desc:
        lb = next(
            (w for w in snap.workloads if w.kind in ("alb", "nlb", "gwlb") and eni.id in w.eni_ids),
            None,
        )
        if lb:
            return lb.kind, lb.id, lb.label
        for kind in ("alb", "gwlb", "nlb"):
            desc_kind = {
                "alb": "elb app/",
                "nlb": "elb net/",
                "gwlb": "elb gw/",
            }[kind]
            if desc_kind in desc:
                return kind, eni.id, eni.id
    if "lambda" in desc:
        return "lambda-eni", eni.id, eni.id
    if "vpce" in desc or iface in ("vpce", "endpoint"):
        ep = next(
            (e for e in snap.endpoints if eni.id in e.network_interface_ids),
            None,
        )
        if ep:
            return "vpc-endpoint-eni", ep.id, ep.name
        return "vpc-endpoint-eni", eni.id, eni.id
    if "dms" in desc or "directory" in desc or "storagegateway" in desc:
        return "managed-eni", eni.id, eni.id
    if eni.requester_managed:
        return "aws-managed-eni", eni.id, eni.id
    return "unknown", eni.id, eni.id


def merge_snapshots(snaps: List[AccountSnapshot]) -> List[AccountSnapshot]:
    """Collapse per-region snapshots that share a VPC set is not valid, so we
    keep them separate and let callers index by (region, vpc)."""
    return [s for s in snaps if s.region]
