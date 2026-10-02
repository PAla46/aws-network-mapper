"""CSV / JSON / Markdown output."""

from __future__ import annotations

import csv
import dataclasses
import json
import os
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import model as M
from .analysis import (
    CidrMapRow,
    CrossVpcRow,
    ExposureRow,
    LbFlowRow,
)
from .findings import RULES, Finding
from .topology import Topology


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def write_csv(path: str, rows: Sequence[Dict[str, Any]], fieldnames: Optional[Sequence[str]] = None) -> int:
    ensure_dir(os.path.dirname(path) or ".")
    if not rows:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            fh.write((",".join(fieldnames) if fieldnames else "empty") + "\n")
        return 0
    if not fieldnames:
        fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def write_text(path: str, content: str) -> str:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _dc(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _dc(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _dc(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_dc(v) for v in obj]
    return obj


def write_inventory_json(path: str, topo: Topology, meta: Dict[str, Any]) -> str:
    payload = {
        "meta": meta,
        "summary": topo.summary(),
        "vpcs": [_dc(v) for v in topo.vpcs.values()],
        "subnets": [_dc(s) for s in topo.subnets.values()],
        "route_tables": [_dc(r) for r in topo.route_tables.values()],
        "internet_gateways": [_dc(i) for i in topo.igws.values()],
        "nat_gateways": [_dc(n) for n in topo.nat_gateways.values()],
        "transit_gateways": [_dc(t) for t in topo.tgws.values()],
        "vpc_peerings": [_dc(p) for p in topo.peerings.values()],
        "vpn_gateways": [_dc(v) for v in topo.vpn_gateways.values()],
        "vpc_endpoints": [_dc(e) for e in topo.endpoints.values()],
        "network_interfaces": [_dc(e) for e in topo.enis.values()],
        "security_groups": [_dc(s) for s in topo.security_groups.values()],
        "network_acls": [_dc(n) for n in topo.nacls.values()],
        "workloads": [_dc(w) for w in topo.workloads.values()],
    }
    return write_text(path, json.dumps(payload, indent=2, default=str))


# --------------------------------------------------------------------------- #
# report rows
# --------------------------------------------------------------------------- #


def route_rows(topo: Topology) -> List[Dict[str, Any]]:
    rows = []
    for rt in sorted(topo.route_tables.values(), key=lambda r: (r.region, r.vpc_id, r.id)):
        vpc = topo.vpcs.get(rt.vpc_id)
        subnets = sorted(
            [topo.subnets[s] for s in rt.subnet_ids if s in topo.subnets],
            key=lambda s: s.id,
        )
        targets = subnets or [None]
        for subnet in targets:
            for route in rt.routes:
                target_name = _target_name(topo, route)
                rows.append(
                    {
                        "region": rt.region,
                        "account": topo.account_id,
                        "vpc_id": rt.vpc_id,
                        "vpc_name": vpc.label if vpc else "",
                        "route_table_id": rt.id,
                        "route_table_name": rt.label,
                        "is_main": rt.is_main,
                        "subnet_id": subnet.id if subnet else "",
                        "subnet_name": subnet.name if subnet else "",
                        "subnet_cidr": subnet.cidr if subnet else "",
                        "availability_zone": subnet.az if subnet else "",
                        "association": subnet.rtb_association if subnet else "",
                        "destination": route.destination,
                        "target": route.target_id,
                        "target_type": route.target_kind,
                        "target_name": target_name,
                        "state": route.state,
                        "origin": route.origin,
                    }
                )
    return rows


def _target_name(topo: Topology, route: M.Route) -> str:
    kind = route.target_kind
    if kind == M.T_NAT and route.target_id in topo.nat_gateways:
        return topo.nat_gateways[route.target_id].name
    if kind == M.T_INTERNET and route.target_id in topo.igws:
        return topo.igws[route.target_id].name
    if kind == M.T_TGW and route.target_id in topo.tgws:
        return topo.tgws[route.target_id].label
    if kind == M.T_VGW and route.target_id in topo.vpn_gateways:
        return topo.vpn_gateways[route.target_id].name
    if kind == M.T_PEERING and route.target_id in topo.peerings:
        return topo.peerings[route.target_id].name
    if kind == M.T_ENDPOINT and route.target_id in topo.endpoints:
        return topo.endpoints[route.target_id].short_service
    if kind == M.T_ENI and route.target_id in topo.enis:
        return topo.enis[route.target_id].label
    return ""


def subnet_rows(topo: Topology) -> List[Dict[str, Any]]:
    rows = []
    for subnet in sorted(topo.subnets.values(), key=lambda s: (s.region, s.vpc_id, s.cidr)):
        vpc = topo.vpcs.get(subnet.vpc_id)
        rtb = topo.rtb_for_subnet(subnet.id)
        rows.append(
            {
                "region": subnet.region,
                "vpc_id": subnet.vpc_id,
                "vpc_name": vpc.label if vpc else "",
                "vpc_cidr": vpc.cidr if vpc else "",
                "subnet_id": subnet.id,
                "subnet_name": subnet.name,
                "cidr": subnet.cidr,
                "availability_zone": subnet.az,
                "route_table_id": rtb.id if rtb else "",
                "route_table_name": rtb.label if rtb else "",
                "association": subnet.rtb_association,
                "map_public_ip_on_launch": subnet.map_public_ip_on_launch,
                "available_ip_addresses": subnet.available_ips,
                "internet_routable": _is_public(topo, subnet),
                "eni_count": len(topo.enis_by_subnet.get(subnet.id, [])),
                "workloads": ", ".join(w.label for w in topo.workloads_by_subnet.get(subnet.id, [])),
                "network_acl_id": (topo.nacl_by_subnet.get(subnet.id).id if topo.nacl_by_subnet.get(subnet.id) else ""),
            }
        )
    return rows


def _is_public(topo: Topology, subnet) -> bool:
    rtb = topo.rtb_for_subnet(subnet.id)
    if not rtb:
        return False
    return any(
        r.target_kind in (M.T_INTERNET, M.T_EIGW) and r.state == "active" for r in rtb.routes
    )


def resource_rows(topo: Topology) -> List[Dict[str, Any]]:
    rows = []
    for wl in sorted(topo.workloads.values(), key=lambda w: (w.region, w.kind, w.id)):
        eni = topo.primary_ip_for_workload(wl)
        rows.append(
            {
                "region": wl.region,
                "vpc_id": wl.vpc_id,
                "kind": wl.kind,
                "id": wl.id,
                "name": wl.label,
                "state": wl.state,
                "subnets": ", ".join(wl.subnet_ids),
                "subnet_names": ", ".join(
                    topo.subnets[s].name for s in wl.subnet_ids if s in topo.subnets
                ),
                "security_groups": ", ".join(wl.sg_ids),
                "private_ip": eni.private_ip if eni else "",
                "public_ip": eni.public_ip if eni else "",
                "engine": wl.engine,
                "detail": wl.detail,
                "internet_facing": bool(wl.public_ips or wl.extra.get("public") or wl.extra.get("scheme") == "internet-facing"),
            }
        )
    return rows


def eni_rows(topo: Topology) -> List[Dict[str, Any]]:
    rows = []
    for eni in sorted(topo.enis.values(), key=lambda e: (e.region, e.subnet_id, e.private_ip)):
        subnet = topo.subnets.get(eni.subnet_id)
        rows.append(
            {
                "region": eni.region,
                "vpc_id": eni.vpc_id,
                "subnet_id": eni.subnet_id,
                "subnet_name": subnet.name if subnet else "",
                "eni_id": eni.id,
                "workload_kind": eni.workload_kind,
                "workload_id": eni.workload_id,
                "workload_name": eni.workload_name,
                "private_ip": eni.private_ip,
                "public_ip": eni.public_ip,
                "interface_type": eni.interface_type,
                "primary": eni.primary,
                "security_groups": ", ".join(eni.sg_ids),
                "description": eni.description,
                "status": eni.status,
            }
        )
    return rows


def sg_rows(topo: Topology) -> List[Dict[str, Any]]:
    used = set()
    for eni in topo.enis.values():
        used.update(eni.sg_ids)
    for wl in topo.workloads.values():
        used.update(wl.sg_ids)
    for ep in topo.endpoints.values():
        used.update(ep.sg_ids)
    rows = []
    for sg in sorted(topo.security_groups.values(), key=lambda s: (s.region, s.id)):
        open_in = [
            r
            for r in sg.ingress
            if r.cidr in ("0.0.0.0/0", "::/0") and r.from_port < 0 and not r.sg_id
        ]
        rows.append(
            {
                "region": sg.region,
                "vpc_id": sg.vpc_id,
                "sg_id": sg.id,
                "name": sg.name,
                "description": sg.description,
                "ingress_rules": len(sg.ingress),
                "egress_rules": len(sg.egress),
                "open_to_world_all": bool(open_in),
                "in_use": sg.id in used,
            }
        )
    return rows


def cross_vpc_rows(rows: Sequence[CrossVpcRow]) -> List[Dict[str, Any]]:
    return [
        {
            "src_vpc": r.src_vpc,
            "dst_vpc": r.dst_vpc,
            "link_type": r.link_kind,
            "link_id": r.link_detail,
            "src_ip": r.src_ip,
            "src_subnet": r.src_subnet,
            "dst_ip": r.dst_ip,
            "dst_subnet": r.dst_subnet,
            "forward_verdict": r.forward,
            "reverse_verdict": r.reverse,
            "asymmetric": r.asymmetric,
            "reasons": r.reasons,
            "hops": r.hops,
        }
        for r in rows
    ]


def lb_flow_rows(rows: Sequence[LbFlowRow]) -> List[Dict[str, Any]]:
    return [
        {
            "load_balancer": r.lb,
            "lb_kind": r.lb_kind,
            "lb_subnet": r.lb_subnet,
            "target_id": r.target,
            "target_ip": r.target_ip,
            "target_subnet": r.target_subnet,
            "verdict": r.verdict,
            "reasons": r.reasons,
            "hops": r.hops,
        }
        for r in rows
    ]


def exposure_rows(rows: Sequence[ExposureRow]) -> List[Dict[str, Any]]:
    return [
        {
            "public_ip": r.ip,
            "resource": r.resource,
            "resource_type": r.resource_type,
            "subnet": r.subnet,
            "vpc": r.vpc,
            "region": r.region,
            "default_route_target": r.route_target,
            "reason": r.reason,
        }
        for r in rows
    ]


def cidr_rows(rows: Sequence[CidrMapRow]) -> List[Dict[str, Any]]:
    return [
        {
            "cidr": r.cidr,
            "vpc_id": r.vpc,
            "vpc_name": r.vpc_name,
            "subnet_id": r.subnet,
            "subnet_name": r.subnet_name,
            "availability_zone": r.az,
            "route_table": r.route_table,
            "overlaps": r.conflicts_with,
            "hosts": r.reachable_from,
        }
        for r in rows
    ]


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #


def findings_markdown(findings: Sequence[Finding], topo: Topology) -> str:
    lines = ["# Network findings", ""]
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append(
        "Findings: "
        + ", ".join(f"**{sev}** {counts.get(sev, 0)}" for sev in ("critical", "high", "medium", "low", "info") if counts.get(sev))
        + f"  (total {len(findings)})"
    )
    lines.append("")
    for severity in ("critical", "high", "medium", "low", "info"):
        subset = [f for f in findings if f.severity == severity]
        if not subset:
            continue
        lines.append(f"## {severity.upper()} ({len(subset)})")
        lines.append("")
        for f in subset:
            lines.append(f"### {f.rule_id} - {f.title}")
            lines.append("")
            lines.append(f"- **Resource**: `{f.resource}` ({f.resource_type})")
            lines.append(f"- **Region / VPC**: {f.region} / {f.vpc_id or '-'}")
            lines.append(f"- **Evidence**: {f.evidence}")
            if f.recommendation:
                lines.append(f"- **Recommendation**: {f.recommendation}")
            lines.append("")
    if not findings:
        lines.append("_No findings matched the rule set._")
    return "\n".join(lines) + "\n"


def start_here_markdown(topo: Topology, findings: Sequence[Finding], diagrams: Sequence[str]) -> str:
    """The one page to open first: what the diagrams answer, and the findings."""
    lines = [
        "# Start here",
        "",
        f"- Account: {topo.account_id or 'unknown'} ({topo.partition})",
        f"- Regions: {', '.join(topo.regions) or '-'}",
        f"- VPCs {len(topo.vpcs)}, subnets {len(topo.subnets)}, "
        f"route tables {len(topo.route_tables)}, transit gateways {len(topo.tgws)}, "
        f"peerings {len(topo.peerings)}, internet gateways {len(topo.igws)}",
        "",
        "Each `.mmd` file is Mermaid text. Paste one into <https://mermaid.live>, or render:",
        "",
        "```",
        "npx -y @mermaid-js/mermaid-cli -i 00-overview.mmd -o overview.svg",
        "```",
        "",
        "## Diagrams",
        "",
        "| File | What it shows |",
        "| --- | --- |",
    ]
    described = {
        "00-overview.mmd": "every VPC, transit gateway attachment, peering, internet gateway and on-prem VPN",
        "01-transit-gateways.mmd": "transit gateway attachments, their route tables and associations",
        "02-internet-paths.mmd": "internet gateways, NAT gateways, public subnets and elastic IPs",
    }
    vpc_files = [d for d in diagrams if d.startswith("vpcs/")]
    sub_files = [d for d in diagrams if d.startswith("subnets/")]
    for name in diagrams:
        if not name.startswith(("vpcs/", "subnets/")):
            lines.append(f"| `{name}` | {described.get(name, 'topology')} |")
    if vpc_files:
        lines.append(f"| `vpcs/` ({len(vpc_files)}) | one file per VPC: subnets, route tables, gateways, workloads |")
    if sub_files:
        lines.append(f"| `subnets/` ({len(sub_files)}) | one file per subnet: route table, gateways, workloads |")
    if not vpc_files and not sub_files:
        lines.append("| _(none)_ | |")

    lines += ["", "## Findings", ""]
    if findings:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary = ", ".join(f"{counts[s]} {s}" for s in sorted(counts, key=lambda x: order.get(x, 9)))
        lines += [f"{len(findings)} total: {summary}.", ""]
        by_rule: Dict[str, List[str]] = {}
        for f in findings:
            by_rule.setdefault(f.rule_id, []).append(f.resource)
        lines += ["| Rule | Severity | Resources |", "| --- | --- | --- |"]
        sev = {f.rule_id: f.severity for f in findings}
        title = {f.rule_id: f.title for f in findings}
        for rule_id in sorted(by_rule):
            res = ", ".join(f"`{r}`" for r in sorted(set(by_rule[rule_id]))[:6])
            more = len(set(by_rule[rule_id])) - 6
            if more > 0:
                res += f" (+{more} more)"
            lines.append(f"| `{rule_id}` | {sev[rule_id]} | {res} |")
        lines += ["", "A warning icon on a node in a diagram marks a finding on it.", ""]
    else:
        lines.append("None.", "")
    return "\n".join(lines) + "\n"


def main_markdown(
    topo: Topology,
    findings: Sequence[Finding],
    meta: Dict[str, Any],
    cross_rows: Sequence[CrossVpcRow],
    lb_rows: Sequence[LbFlowRow],
    diagram_index: Sequence[str],
) -> str:
    summary = topo.summary()
    lines = [
        "# AWS network topology report",
        "",
        f"- Generated: {meta.get('generated_at')}",
        f"- Account: {meta.get('account_id') or 'unknown'} ({meta.get('partition')})",
        f"- Regions scanned: {', '.join(topo.regions) or 'none'}",
        f"- Rules executed: {len(RULES)} / rules with findings: {len({f.rule_id for f in findings})} / "
        f"findings: {len(findings)}",
        "",
        "## Inventory summary",
        "",
        "| Metric | Count |",
        "| --- | --- |",
    ]
    for key, value in summary.items():
        lines.append(f"| {key.replace('_', ' ')} | {value} |")
    lines += ["", "## VPCs", "", "| Region | VPC | Name | CIDR | Subnets | Route tables |", "| --- | --- | --- | --- | --- | --- |"]
    for vpc in sorted(topo.vpcs.values(), key=lambda v: (v.region, v.id)):
        lines.append(
            f"| {vpc.region} | {vpc.id} | {vpc.label} | {', '.join(vpc.cidrs)} | "
            f"{len(topo.subnets_by_vpc.get(vpc.id, []))} | {len(topo.rtbs_by_vpc.get(vpc.id, []))} |"
        )
    lines += ["", "## Cross-VPC connectivity (evaluated)", "", "| From | To | Link | Forward | Return | Asymmetric | Notes |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in cross_rows[:200]:
        lines.append(
            f"| {row.src_vpc} | {row.dst_vpc} | {row.link_kind} {row.link_detail} | "
            f"{row.forward} | {row.reverse} | {'YES' if row.asymmetric else 'no'} | {row.reasons[:160]} |"
        )
    if not cross_rows:
        lines.append("| - | - | - | - | - | - | no connected VPC pairs found |")
    lines += ["", "## Load balancer -> target flows (evaluated)", "", "| LB | Target | Target IP | Verdict | Notes |", "| --- | --- | --- | --- | --- |"]
    for row in lb_rows[:200]:
        lines.append(
            f"| {row.lb} ({row.lb_kind}) | {row.target} | {row.target_ip} | {row.verdict} | {row.reasons[:140]} |"
        )
    if not lb_rows:
        lines.append("| - | - | - | - | no load balancer targets evaluated |")
    if diagram_index:
        lines += ["", "## Diagrams", ""]
        lines += [f"- `{d}`" for d in diagram_index]
    lines += ["", "## Findings", "", f"See `findings/findings.md` ({len(findings)} findings).", ""]
    return "\n".join(lines) + "\n"
