"""Derived indexes and path evaluation -- everything computed from the model.

Three sibling modules, used in this order:

``connectivity``  the node/edge model the diagram is drawn from: subnet
                  classification and the arrows between resources.
``routing``       "does a packet from A reach B" -- longest-prefix match,
                  gateway/peering/transit resolution, security groups.
``cross_vpc``     the pairwise analyses that only ``--reports`` needs.

This module holds ``Topology``, the index that sits underneath all three: it
indexes the raw snapshots once and resolves each subnet to its *effective* route
table. Nothing here calls AWS -- it is all pure functions of a ``Topology``.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from .. import model as M
from ..model import AccountSnapshot, Eni, RouteTable, SecurityGroup, Subnet, Vpc, Workload
from ..util.cidr import ip_in_net, nets_overlap


class Topology:
    def __init__(self, snapshots: Iterable[AccountSnapshot]):
        self.snapshots = [s for s in snapshots if s is not None]
        self.regions = sorted({s.region for s in self.snapshots})
        self.account_id = next((s.account_id for s in self.snapshots if s.account_id), "")
        self.partition = next((s.partition for s in self.snapshots), "aws")

        self.vpcs: Dict[str, Vpc] = {}
        self.subnets: Dict[str, Subnet] = {}
        self.route_tables: Dict[str, RouteTable] = {}
        self.igws: Dict[str, M.Igw] = {}
        self.nat_gateways: Dict[str, M.NatGw] = {}
        self.tgws: Dict[str, M.Tgw] = {}
        self.peerings: Dict[str, M.Peering] = {}
        self.vpn_gateways: Dict[str, M.VpnGateway] = {}
        self.vpn_connections: Dict[str, M.VpnConnection] = {}
        self.endpoints: Dict[str, M.VpcEndpoint] = {}
        self.enis: Dict[str, Eni] = {}
        self.security_groups: Dict[str, SecurityGroup] = {}
        self.nacls: Dict[str, M.Nacl] = {}
        self.workloads: Dict[str, Workload] = {}

        self.subnets_by_vpc: Dict[str, List[Subnet]] = {}
        self.rtbs_by_vpc: Dict[str, List[RouteTable]] = {}
        self.workloads_by_vpc: Dict[str, List[Workload]] = {}
        self.workloads_by_subnet: Dict[str, List[Workload]] = {}
        self.enis_by_subnet: Dict[str, List[Eni]] = {}
        self.enis_by_ip: Dict[str, Eni] = {}
        self.sgs_by_vpc: Dict[str, List[SecurityGroup]] = {}
        self.nat_by_vpc: Dict[str, List[M.NatGw]] = {}
        self.igw_by_vpc: Dict[str, List[M.Igw]] = {}
        self.endpoints_by_vpc: Dict[str, List[M.VpcEndpoint]] = {}
        self.tgw_attach_by_vpc: Dict[str, List[M.TgwAttachment]] = {}
        self.peerings_by_vpc: Dict[str, List[M.Peering]] = {}
        self.nacl_by_subnet: Dict[str, M.Nacl] = {}
        self.error_count = 0

        for snap in self.snapshots:
            self.error_count += len(snap.errors)
            self._index(snap)
        self._link()

    # -- indexing --------------------------------------------------------
    def _index(self, snap: AccountSnapshot) -> None:
        for v in snap.vpcs:
            self.vpcs[v.id] = v
            self.subnets_by_vpc.setdefault(v.id, [])
            self.workloads_by_vpc.setdefault(v.id, [])
            self.rtbs_by_vpc.setdefault(v.id, [])
            self.sgs_by_vpc.setdefault(v.id, [])
        for s in snap.subnets:
            self.subnets[s.id] = s
            self.subnets_by_vpc.setdefault(s.vpc_id, []).append(s)
        for rt in snap.route_tables:
            self.route_tables[rt.id] = rt
            self.rtbs_by_vpc.setdefault(rt.vpc_id, []).append(rt)
        for ig in snap.igws:
            self.igws[ig.id] = ig
            if ig.vpc_id:
                self.igw_by_vpc.setdefault(ig.vpc_id, []).append(ig)
        for n in snap.nat_gateways:
            self.nat_gateways[n.id] = n
            if n.vpc_id:
                self.nat_by_vpc.setdefault(n.vpc_id, []).append(n)
        for t in snap.tgws:
            self.tgws[t.id] = t
            for a in t.attachments:
                if a.vpc_id:
                    self.tgw_attach_by_vpc.setdefault(a.vpc_id, []).append(a)
        for p in snap.peerings:
            existing = self.peerings.get(p.id)
            if existing is not None:
                # the same peering is described from both sides; keep both views
                for vpc_id in p.local_vpc_ids or [p.vpc_id]:
                    if vpc_id and vpc_id not in existing.local_vpc_ids:
                        existing.local_vpc_ids.append(vpc_id)
                p = existing
            else:
                self.peerings[p.id] = p
            for vpc_id in list(p.local_vpc_ids or []) + ([p.vpc_id] if p.vpc_id else []):
                self.peerings_by_vpc.setdefault(vpc_id, []).append(p)
            if p.peer_vpc_id:
                self.peerings_by_vpc.setdefault(p.peer_vpc_id, []).append(p)
        for v in snap.vpn_gateways:
            self.vpn_gateways[v.id] = v
        for v in snap.vpn_connections:
            self.vpn_connections[v.id] = v
        for e in snap.endpoints:
            self.endpoints[e.id] = e
            self.endpoints_by_vpc.setdefault(e.vpc_id, []).append(e)
        for e in snap.enis:
            self.enis[e.id] = e
            if e.subnet_id:
                self.enis_by_subnet.setdefault(e.subnet_id, []).append(e)
            if e.private_ip:
                self.enis_by_ip.setdefault(e.private_ip, e)
        for sg in snap.security_groups:
            self.security_groups[sg.id] = sg
            self.sgs_by_vpc.setdefault(sg.vpc_id, []).append(sg)
        for n in snap.nacls:
            self.nacls[n.id] = n
        for w in snap.workloads:
            self.workloads[w.id] = w
            self.workloads_by_vpc.setdefault(w.vpc_id, []).append(w)
            for sid in w.subnet_ids:
                self.workloads_by_subnet.setdefault(sid, []).append(w)

    def _link(self) -> None:
        for subnet in self.subnets.values():
            self.nacl_by_subnet[subnet.id] = self.default_nacl_for(subnet)
        self._link_database_enis()

    def _link_database_enis(self) -> None:
        """Attach RDS ENIs to their instance.

        ``describe_db_instances`` never returns the interface, and the endpoint
        address is a DNS name rather than an address you can route to. AWS does
        expose the ENI through ``describe_network_interfaces``, named
        ``RDSNetworkInterface`` / ``RDSNetworkInterface:<name>``, and the subnet
        group tells us which VPC it lives in. Without this the diagram cannot
        show an EC2 -> RDS path at all, because there is no IP to trace.
        """
        for wl in self.workloads.values():
            if wl.kind != "rds" or wl.eni_ids:
                continue
            candidates = [
                eni
                for eni in self.enis.values()
                if eni.subnet_id in (wl.subnet_ids or [])
                and "rds" in (eni.description or "").lower()
                and not eni.instance_id
            ]
            if not candidates:
                continue
            # Prefer an interface whose description names this instance.
            named = [e for e in candidates if wl.name and wl.name in (e.description or "")]
            chosen = (named or candidates)[0]
            wl.eni_ids = [chosen.id]
            if not wl.private_ips or "." not in (wl.private_ips[0] or ""):
                if chosen.private_ip:
                    wl.private_ips = [chosen.private_ip]
            if not wl.sg_ids:
                wl.sg_ids = list(chosen.sg_ids)
            chosen.requester_managed = True

    # -- lookups ---------------------------------------------------------
    def rtb_for_subnet(self, subnet_id: str) -> Optional[RouteTable]:
        subnet = self.subnets.get(subnet_id)
        if not subnet or not subnet.rtb_id:
            return None
        return self.route_tables.get(subnet.rtb_id)

    def default_nacl_for(self, subnet: Subnet) -> Optional[M.Nacl]:
        candidates = [n for n in self.nacls.values() if n.is_default and n.vpc_id == subnet.vpc_id]
        if not candidates:
            return None
        for nacl in candidates:
            for entry in nacl.entries:
                if entry.rule_number == 100:
                    return nacl
        return candidates[0]

    def vpc_cidrs(self, vpc_id: str) -> List[str]:
        vpc = self.vpcs.get(vpc_id)
        return list(vpc.cidrs) if vpc else []

    def subnet_for_ip(self, ip: str, vpc_id: Optional[str] = None) -> Optional[Subnet]:
        for subnet in self.subnets.values():
            if vpc_id and subnet.vpc_id != vpc_id:
                continue
            if ip_in_net(ip, subnet.cidr):
                return subnet
        return None

    def eni_for_ip(self, ip: str) -> Optional[Eni]:
        return self.enis_by_ip.get(ip)

    def nat_in_subnet(self, subnet_id: str) -> Optional[M.NatGw]:
        for n in self.nat_gateways.values():
            if n.subnet_id == subnet_id and n.state in ("available", "pending"):
                return n
        return None

    def igw_for_vpc(self, vpc_id: str) -> Optional[M.Igw]:
        for igw in self.igw_by_vpc.get(vpc_id, []):
            if igw.attached:
                return igw
        return None

    def peers_of_vpc(self, vpc_id: str) -> List[M.Peering]:
        seen = set()
        out = []
        for p in self.peerings_by_vpc.get(vpc_id, []):
            if p.id in seen:
                continue
            seen.add(p.id)
            out.append(p)
        return out

    def tgw_attachments_for_vpc(self, vpc_id: str) -> List[M.TgwAttachment]:
        return self.tgw_attach_by_vpc.get(vpc_id, [])

    def tgw_route_table_for_attachment(
        self, attachment: M.TgwAttachment
    ) -> Optional[M.TgwRouteTable]:
        for tgw in self.tgws.values():
            for rtb in tgw.route_tables:
                if attachment.id in rtb.associations:
                    return rtb
            for rtb in tgw.route_tables:
                if rtb.default_association:
                    return rtb
        return None

    def enis_for_workload(self, workload: Workload) -> List[Eni]:
        return [self.enis[e] for e in workload.eni_ids if e in self.enis]

    def primary_ip_for_workload(self, workload: Workload) -> Optional[Eni]:
        enis = self.enis_for_workload(workload)
        for eni in enis:
            if eni.primary:
                return eni
        return enis[0] if enis else None

    # -- helpers ---------------------------------------------------------
    def vpcs_overlapping(self, vpc_id: str) -> List[Vpc]:
        """Other VPCs whose CIDRs overlap this VPC's CIDRs."""
        out = []
        mine = self.vpc_cidrs(vpc_id)
        for other in self.vpcs.values():
            if other.id == vpc_id:
                continue
            for a in mine:
                for b in other.cidrs:
                    if nets_overlap(a, b):
                        out.append(other)
                        break
                else:
                    continue
                break
        return out

    def summary(self) -> Dict[str, int]:
        return {
            "regions": len(self.regions),
            "vpcs": len(self.vpcs),
            "subnets": len(self.subnets),
            "route_tables": len(self.route_tables),
            "internet_gateways": len(self.igws),
            "nat_gateways": len(self.nat_gateways),
            "transit_gateways": len(self.tgws),
            "tgw_attachments": sum(len(t.attachments) for t in self.tgws.values()),
            "peerings": len(self.peerings),
            "vpn_gateways": len(self.vpn_gateways),
            "vpn_connections": len(self.vpn_connections),
            "vpc_endpoints": len(self.endpoints),
            "network_interfaces": len(self.enis),
            "security_groups": len(self.security_groups),
            "network_acls": len(self.nacls),
            "workloads": len(self.workloads),
            "collection_errors": self.error_count,
        }
