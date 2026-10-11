"""D2 rendering of the single topology diagram.

A second view of the exact same model as ``mermaid.py``: same containers, same
nodes, same arrows, same labels. Only the syntax differs -- and the way D2 and
Mermaid each spell a line break. Everything either renderer *says* comes from
``scene.py``, so the two files cannot disagree about a subnet's classification
or a workload's title.

Why this exists next to Mermaid: D2 lets the *reader* choose a layout engine.
Mermaid has one, with no control, and it collapses on a deeply nested graph.
D2 ships dagre, ELK and TALA; the header below pins ELK as a sane default and
a reader who wants the architecture look can re-render with ``--layout=tala``.

Text only, deliberately. Rendering a ``.d2`` needs the ``d2`` binary or the
playground at https://play.d2lang.com, and neither is a dependency here: this
runs on AWS CloudShell, which has no Go toolchain and no renderer. Emitting the
source is pure stdlib, exactly like the ``.mmd`` it sits beside.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from . import kinds
from .scene import (
    CLASS_ORDER,
    MAX_TOPOLOGY_SUBNETS,
    PALETTE,
    Style,
    classification_reason,
    component_node_ids,
    known_node_ids,
    nacl_counts,
    service_short,
    short_id,
    short_sg_list,
    trunc,
    workload_title,
)
from ..graph import connectivity as flow
from ..graph import Topology
from ..model import Subnet, Workload


def d2_label(text: object) -> str:
    """Escape a label for a D2 double-quoted string.

    D2 wants a multi-line label as ``\\n`` escapes inside one physical line, so
    the backslash is doubled first and only then are real newlines turned into
    ``\\n`` -- otherwise data that already contained the two characters
    ``\\`` ``n`` would silently become a line break.
    """
    raw = str(text if text is not None else "").replace("\r", "")
    raw = raw.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return raw or " "


# Mermaid shape intent -> (D2 shape keyword, rounded box?). D2's default shape
# is a rectangle, so a plain box carries no ``shape`` line at all.
_SHAPES: Dict[str, tuple] = {
    "box": ("", False),
    "round": ("", True),
    "stadium": ("oval", False),
    "hex": ("hexagon", False),
    "diamond": ("diamond", False),
    "subroutine": ("", False),
}


def _class_props(style: Style) -> List[str]:
    """A shared palette row as D2 ``style`` properties."""
    props: List[str] = []
    if style.fill:
        props.append(f'fill: "{style.fill}"')
    if style.stroke:
        props.append(f'stroke: "{style.stroke}"')
    if style.text:
        props.append(f'font-color: "{style.text}"')
    if style.dashed:
        props.append("stroke-dash: 4")
    return props


class D2Builder:
    """Emits D2 source. Ids are the caller's keys, so an inventory renders the
    same way every time and a node keeps the identity the model gave it."""

    def __init__(self, title: str = ""):
        self.title = title
        self._lines: List[str] = []
        self._indent = 0
        self._defined: Set[str] = set()
        self._edges: Set[str] = set()
        self._used_classes: Set[str] = set()

    # -- primitives ------------------------------------------------------
    def _line(self, text: str) -> None:
        self._lines.append(("  " * self._indent + text) if text else "")

    def comment(self, text: str) -> None:
        self._line(f"# {text}")

    def blank(self) -> None:
        self._lines.append("")

    def container(self, key: str, label: str) -> "_Container":
        return _Container(self, key, d2_label(label))

    def node(
        self,
        key: str,
        label: str,
        shape: str = "box",
        cls: Optional[str] = None,
        label_limit: int = 60,
    ) -> None:
        if key in self._defined:
            return
        text = d2_label(trunc(label, label_limit))
        d2shape, rounded = _SHAPES.get(shape, ("", False))
        props: List[str] = []
        if d2shape:
            props.append(f"shape: {d2shape}")
        if cls:
            props.append(f"class: {cls}")
            self._used_classes.add(cls)
        if rounded:
            props.append("style: { border-radius: 8 }")
        if props:
            self._line(f'{key}: "{text}" {{')
            self._indent += 1
            for prop in props:
                self._line(prop)
            self._indent -= 1
            self._line("}")
        else:
            self._line(f'{key}: "{text}"')
        self._defined.add(key)

    def edge(self, src: str, dst: str, label: str = "", label_limit: int = 40) -> None:
        text = d2_label(trunc(label, label_limit))
        body = f'{src} -> {dst}: "{text}"' if label else f"{src} -> {dst}"
        if body in self._edges:
            return
        self._edges.add(body)
        self._line(body)

    # -- render ----------------------------------------------------------
    def render(self) -> str:
        out: List[str] = []
        if self.title:
            out.append(f"# {self.title}")
        out.append("")
        out.append("vars: {")
        out.append("  d2-config: {")
        out.append("    layout-engine: elk")
        out.append("  }")
        out.append("}")
        used = [name for name in PALETTE if name in self._used_classes]
        if used:
            out.append("")
            out.append("classes: {")
            for name in used:
                out.append(f"  {name}: {{")
                out.append("    style: {")
                for prop in _class_props(PALETTE[name]):
                    out.append(f"      {prop}")
                out.append("    }")
                out.append("  }")
            out.append("}")
        out.append("")
        out.extend(self._lines)
        return "\n".join(out).rstrip("\n") + "\n"


class _Container:
    """A D2 container: ``key: "label" { ... }``."""

    def __init__(self, builder: D2Builder, key: str, label: str):
        self.b = builder
        self.key = key
        self.label = label

    def __enter__(self) -> str:
        self.b._line(f'{self.key}: "{self.label}" {{')
        self.b._indent += 1
        return self.key

    def __exit__(self, *exc) -> bool:
        self.b._indent -= 1
        self.b._line("}")
        return False


# --------------------------------------------------------------------------- #
# THE single topology diagram (same shape as mermaid.render_topology)
# --------------------------------------------------------------------------- #


def render_topology(
    topo: Topology,
    model: Optional["flow.FlowModel"] = None,
    *,
    max_vpcs: int = 60,
    max_subnets: int = MAX_TOPOLOGY_SUBNETS,
) -> str:
    """Render the AWS network connectivity / traffic flow map as D2."""
    if model is None:
        model = flow.build_flow_model(topo)

    b = D2Builder(
        f"AWS network connectivity / traffic flow map ({topo.account_id or 'account'})"
    )
    b.comment("containers = where a resource lives; arrows = network traffic path")
    b.comment("NACL and security groups are metadata inside labels, never nodes")
    b.comment("arrow labels show the route that justifies the path (longest-prefix match)")
    b.blank()

    defined: Set[str] = set()

    b.node(flow.internet_node(), "INTERNET", "stadium", "internet", 60)
    defined.add(flow.internet_node())

    if topo.vpn_gateways or topo.vpn_connections or topo.tgws:
        b.node(
            flow.onprem_node(),
            "ON-PREMISES\nCORPORATE / DATA CENTRE",
            "box",
            "onprem",
            60,
        )
        defined.add(flow.onprem_node())

    for endpoint in list(topo.endpoints.values())[:12]:
        svc = endpoint.service_name or "aws service"
        node = flow.service_node(svc)
        if node in defined:
            continue
        b.node(node, f"AWS SERVICE\n{service_short(svc)}", "stadium", "endpoint", 120)
        defined.add(node)

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

    for tgw in list(topo.tgws.values())[:8]:
        node = flow.nid("tgw", tgw.id)
        label = [f"TRANSIT GATEWAY {tgw.label}", f"{tgw.id}"]
        if tgw.state:
            label.append(tgw.state)
        label.extend(model.notes.get(node, []))
        b.node(node, "\n".join(label), "hex", "tgw", 200)
        defined.add(node)

    vpcs = list(topo.vpcs.values())[:max_vpcs]
    for vpc in vpcs:
        _emit_vpc(b, model, topo, vpc, defined, max_subnets)

    referenced = {e.src for e in model.edges} | {e.dst for e in model.edges}
    known = known_node_ids(topo)
    components = component_node_ids(topo)
    missing_components = (referenced - defined) & components
    if missing_components:
        for node in sorted(missing_components):
            b.node(node, f"{node.replace('_', ' ').upper()}\n(recovered)", "round", "component", 200)
            defined.add(node)

    for node in sorted((referenced - defined) - components):
        if node in known:
            why = "exists, but over the diagram budget\nraise --max-diagram-vpcs / --max-diagram-subnets"
        else:
            why = "not present in the inventory\nits subnet or VPC may have failed collection"
        b.node(
            node,
            f"OMITTED\n{node.replace('_', ' ')}\nreferenced by a route\n{why}",
            "round",
            "blocked",
            220,
        )
        defined.add(node)

    for edge in model.edges:
        if edge.src in defined and edge.dst in defined:
            b.edge(edge.src, edge.dst, edge.label, 120)

    for edge in model.edges:
        for key in (edge.src, edge.dst):
            if key in defined:
                continue
            defined.add(key)
            b.node(key, f"unresolved {key}", "box", "warn", 80)

    b.blank()
    _legend(b, topo, model, len(vpcs))

    text = b.render()
    if len(topo.vpcs) > max_vpcs:
        text += f"# NOTE: showing {max_vpcs} of {len(topo.vpcs)} VPCs\n"
    return text


def _emit_vpc(b, model, topo, vpc, defined: Set[str], budget: int) -> None:
    cidrs = ", ".join(topo.vpc_cidrs(vpc.id)[:3]) or "no CIDR"
    title = f"AWS ACCOUNT {topo.account_id or ''}\nVPC {vpc.label}  \u2014  {vpc.id}\n{cidrs}"
    if vpc.flow_log_status and vpc.flow_log_status != "unknown":
        title += f"\nVPC Flow Logs: {vpc.flow_log_status}"

    with b.container(f"c_vpc_{flow._key(vpc.id)}", title):
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

        for nat in topo.nat_by_vpc.get(vpc.id, []):
            nat_node = flow.nid("nat", nat.id)
            lines = [f"NAT GATEWAY\n{nat.id}"]
            if nat.state:
                lines.append(nat.state)
            if nat.connect_type:
                lines.append(f"{nat.connect_type}")
            if nat.address:
                lines.append(nat.address)
            home = topo.subnets.get(nat.subnet_id or "")
            if home is not None:
                lines.append(f"in {home.id} · {home.cidr} · {home.az or '?'}")
            nat_sgs: List[str] = []
            for eni in topo.enis_by_subnet.get(nat.subnet_id or "", []):
                if eni.interface_type == "natGateway" or nat.id in (eni.description or ""):
                    nat_sgs = [x for x in eni.sg_ids]
                    break
            lines.append(f"SG: {', '.join(nat_sgs[:2])}" if nat_sgs else "SG: none")
            lines.extend(model.notes.get(nat_node, []))
            b.node(nat_node, "\n".join(lines), "round", "nat", 220)
            defined.add(nat_node)

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
            with b.container(
                f"c_az_{flow._key(vpc.id)}_{flow._key(az)}", f"AVAILABILITY ZONE {az}"
            ):
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
    with b.container(f"c_subnet_{flow._key(subnet.id)}", title):
        header = [
            f"{subnet.id}  \u00b7  {subnet.cidr or 'no cidr'}  \u00b7  AZ {subnet.az or 'unknown'}",
        ]
        if info.rtb_id:
            header.append(f"Route table: {info.rtb_name or info.rtb_id} ({info.rtb_id})")
        else:
            header.append("Route table: none associated (main table only)")
        nacl = topo.nacl_by_subnet.get(subnet.id)
        if nacl is not None:
            header.append(f"NACL: {nacl.id}  \u00b7  {nacl_counts(nacl)}")
        else:
            header.append("NACL: none found")
        header.append(classification_reason(info))
        for extra in info.extra_summary:
            header.append(extra)
        node = flow.sid(subnet.id)
        b.node(node, "\n".join(header), "box", cls if cls in PALETTE else "private", 220)
        defined.add(node)

        for wl in topo.workloads_by_subnet.get(subnet.id, []):
            _emit_workload(b, model, topo, wl, defined, cls)

        for eni in topo.enis_by_subnet.get(subnet.id, []):
            _emit_eni(b, topo, eni, defined, owned_eni_ids)


def _emit_workload(
    b,
    model,
    topo: Topology,
    wl: Workload,
    defined: Set[str],
    subnet_class: str,
    detail: str = "full",
) -> None:
    node = flow.wid(wl.id)
    if node in defined:
        return

    lines = [workload_title(wl)]
    eni = topo.primary_ip_for_workload(wl)
    style = kinds.style_for(wl.kind)

    lines.extend(style.detail(wl))

    if style.shows_ip and eni is not None and eni.private_ip:
        lines.append(eni.private_ip)

    sg_ids = list(wl.sg_ids)
    if not sg_ids and eni is not None:
        sg_ids = list(eni.sg_ids)
    if sg_ids:
        lines.append(f"SG: {short_sg_list(sg_ids)}")
    elif detail == "full":
        lines.append("SG: none")

    if detail == "full":
        lines.append(short_id(wl.id))

    for note in model.notes.get(node, [])[:2]:
        lines.append(note)

    b.node(
        node,
        "\n".join(lines),
        style.shape,
        subnet_class if subnet_class in PALETTE else "private",
        320,
    )
    defined.add(node)


def _emit_eni(b, topo, eni, defined: Set[str], owned_eni_ids: Set[str]) -> None:
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
    """Name security resources that exist but attach to nothing (audit-relevant,
    but with no place in the topology)."""
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
        b.comment("not associated with any subnet (no traffic path to draw): "
                  + ", ".join(sorted(orphan_rtb)))
    if orphan_nacl:
        b.comment("NACLs not associated with any subnet: " + ", ".join(sorted(orphan_nacl)))
    if orphan_sg:
        b.comment("security groups not attached to any ENI: " + ", ".join(sorted(orphan_sg)))


def _legend(b, topo, model, vpc_count: int) -> None:
    b.comment("---- how to read this ----")
    b.comment("containers: AWS ACCOUNT > VPC > AVAILABILITY ZONE > SUBNET (where things live)")
    b.comment("solid arrow = network traffic path; label = the route / port that creates it")
    b.comment("arrow labels name the route only, never the node they point at")
    b.comment("each journey is drawn once, in the direction traffic travels")
    b.comment("'security:' on a path edge is allowed / blocked / unknown")
    b.comment("'local' is shown in an edge label only, never as a gateway node")
    b.comment("NACL appears in the subnet header; security groups in the resource node")
    b.comment("routes show configured reachability potential, not observed traffic")
    b.comment(f"{vpc_count} VPC(s), {len(model.routing)} subnets, {len(model.edges)} "
              f"paths ({model.traced} allowed / {model.blocked} blocked / "
              f"{model.conditional} unknown) -- console output has the detail")
    _orphan_notes(b, topo)
