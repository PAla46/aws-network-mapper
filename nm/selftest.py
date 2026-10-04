"""Offline self-test: exercises the whole pipeline against synthetic data.

Run with ``python3 aws_network_mapper.py --self-test``. No AWS access, no
third-party packages.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import tempfile
from typing import Any, Dict, List

from . import analysis, flow, mermaid, report
from .collect import Collector
from .findings import run_rules
from .fixtures import build_fixtures
from .paths import PathEngine
from .testing import FakePool, FixtureCollector
from .topology import Topology


class CheckFailed(AssertionError):
    pass


class Checker:
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.passed = 0
        self.failed: List[str] = []

    def check(self, label: str, condition: bool, detail: str = "") -> bool:
        if condition:
            self.passed += 1
            if self.verbose:
                print(f"  PASS  {label}")
        else:
            self.failed.append(f"{label}{(' :: ' + detail) if detail else ''}")
            print(f"  FAIL  {label}" + (f"\n        {detail}" if detail else ""))
        return bool(condition)

    def eq(self, label: str, actual: Any, expected: Any) -> bool:
        return self.check(label, actual == expected, f"got {actual!r}, expected {expected!r}")


NODE_DEF_RE = re.compile(r'^\s*(n\d+)[\[({\{]')
# Only the tokens Mermaid actually accepts. A bare "->" or "-.-" lexes as MINUS and
# fails with "Expecting 'SEMI', 'NEWLINE', ... got 'MINUS'".
EDGE_RE = re.compile(
    r"^\s*(n\d+)\s*(<-\.->|<-\.\.->|-\.\.->|-\.->|-->|==>|<-->|===|<==>)\s*"
    r"(?:\|[^|]*\|\s*)?(n\d+)\s*$"
)
# Any dash run that is not one of the allowed link tokens.
BAD_LINK_RE = re.compile(r"(?<![\w\"\[({|])(-+>|-+\.|-+\.[-.]+)(?![\w\"\[({|])")
CLASS_RE = re.compile(r"^\s*class\s+(n\d+)\s")
SUBGRAPH_RE = re.compile(r"^\s*subgraph\s+(sg\d+)\[")
LABEL_RE = re.compile(r'(["\[])("(?:[^"\\]|\\.)*")\s*[\])]}')


def _line_matching(text: str, needle: str) -> str:
    for raw in text.splitlines():
        if needle in raw and any(t in raw for t in ("-->", "-.->", "==>", "<-.->")):
            return raw.strip()
    return ""


def _invalid_styles(diagrams: Dict[str, str]) -> List[str]:
    """Link tokens in every diagram that Mermaid would not accept."""
    bad: List[str] = []
    token = re.compile(
        r"<-\.->|<-\.\.->|<-->|-\.\.->|-\.->|-\.-|-->|==>|===|<==>|---|==|->"
    )
    for name, text in diagrams.items():
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("%%") or "classDef" in line or "direction" in line:
                continue
            # only look at the part between two node ids (greedy so "-> n2" stays put)
            m = re.match(r"^(\w+)\s+(.*)\s+(\w+)$", line)
            if not m:
                continue
            # strip an edge label so dashes inside it are ignored
            middle = re.sub(r"\|[^|]*\|", "", m.group(2)).strip()
            if not re.fullmatch(r"[\w\[\]\(\){\}<>=.|-]+", middle):
                continue
            for run in token.findall(middle):
                if run not in mermaid.VALID_LINK_STYLES:
                    bad.append(f"{name}: {run!r} in {line!r}")
    return bad


def validate_mermaid(text: str) -> List[str]:
    """Lightweight structural check for the Mermaid subset we emit."""
    problems: List[str] = []
    lines = text.splitlines()
    if not lines or not lines[0].startswith("flowchart "):
        problems.append("missing flowchart header")
    depth = 0
    defined: set[str] = set()
    for raw in lines[1:]:
        line = raw.rstrip()
        if not line or line.strip().startswith("%%"):
            continue
        if SUBGRAPH_RE.match(line):
            depth += 1
            continue
        if line.strip() == "end":
            depth -= 1
            if depth < 0:
                problems.append("unbalanced 'end'")
            continue
        m = NODE_DEF_RE.match(line)
        if m:
            defined.add(m.group(1))
            continue
        m = CLASS_RE.match(line)
        if m:
            if m.group(1) not in defined:
                problems.append(f"class for undefined node {m.group(1)}")
            continue
        if (
            line.strip().startswith("direction")
            or line.strip().startswith("classDef")
            or line.strip().startswith("%%")
        ):
            continue
        m = EDGE_RE.match(line)
        if m:
            for nid in (m.group(1), m.group(3)):
                if nid not in defined:
                    problems.append(f"edge references undefined node {nid}")
            continue
        bad = BAD_LINK_RE.search(line)
        if bad:
            problems.append(
                f"invalid link token {bad.group(1)!r} (not a mermaid link): {line!r}"
            )
            continue
        problems.append(f"unrecognised line: {line!r}")
    if depth != 0:
        problems.append(f"unbalanced subgraph/end (depth {depth})")
    if text.count('"') % 2 != 0:
        problems.append("odd number of quote characters")
    return problems


def run_self_test(verbose: bool = True) -> int:
    c = Checker(verbose=verbose)
    print("aws-network-mapper self-test\n")

    # ---------------------------------------------------------------- collect
    print("[1/8] collection from synthetic AWS payloads")
    fixtures = build_fixtures()
    collector = FixtureCollector(
        fixtures,
        cache_dir=None,
        services=("ec2-workloads", "elbv2", "rds", "ecs", "eks", "lambda"),
        pool_factory=lambda region: FakePool(region),
    )
    collector.start()
    snapshots = [collector.collect_region(region) for region in fixtures]
    eu = next(s for s in snapshots if s.region == "eu-west-1")
    us = next(s for s in snapshots if s.region == "us-east-1")
    c.eq("eu-west-1 collected without errors", eu.errors, [])
    c.eq("us-east-1 collected without errors", us.errors, [])
    c.eq("eu-west-1 VPCs", len(eu.vpcs), 4)
    c.eq("eu-west-1 subnets", len(eu.subnets), 10)
    c.eq("eu-west-1 route tables", len(eu.route_tables), 9)
    c.eq("eu-west-1 internet gateways", len(eu.igws), 2)
    c.eq("eu-west-1 NAT gateways", len(eu.nat_gateways), 2)
    c.eq("eu-west-1 transit gateways", len(eu.tgws), 1)
    c.eq("eu-west-1 TGW attachments", len(eu.tgws[0].attachments), 3)
    c.eq("eu-west-1 TGW route table routes", len(eu.tgws[0].route_tables[0].routes), 4)
    c.eq("eu-west-1 vpc peerings", len(eu.peerings), 1)
    c.eq("eu-west-1 vpc endpoints", len(eu.endpoints), 1)
    c.eq("eu-west-1 network interfaces", len(eu.enis), 10)
    c.eq("eu-west-1 security groups", len(eu.security_groups), 9)
    c.eq("eu-west-1 network acls", len(eu.nacls), 2)
    c.eq("eu-west-1 workloads", len(eu.workloads), 7)
    c.eq("us-east-1 RDS instances", len([w for w in us.workloads if w.kind == "rds"]), 1)
    c.eq("us-east-1 EKS clusters", len([w for w in us.workloads if w.kind == "eks"]), 1)
    c.eq("us-east-1 ECS services", len([w for w in us.workloads if w.kind == "ecs-service"]), 1)
    c.eq("us-east-1 Lambda functions", len([w for w in us.workloads if w.kind == "lambda"]), 1)

    # ---------------------------------------------------------------- topology
    # The fixtures must look like the real API. They previously invented
    # Attachment.InstanceId, a field describe_network_interfaces never returns,
    # which hid a bug that made every ALB -> target path untraceable on live AWS.
    def _walk_attachments(node, path=""):
        found = []
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "Attachment" and isinstance(v, dict):
                    found.append((path, sorted(v)))
                found.extend(_walk_attachments(v, f"{path}/{k}"))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                found.extend(_walk_attachments(v, f"{path}[{i}]"))
        return found

    att_fixtures = []
    for region, payload in fixtures.items():
        for key, value in payload.items():
            att_fixtures.extend(_walk_attachments(value, f"{region}/{key}"))
    c.check("fixtures never use the non-existent Attachment.InstanceId field",
            all("InstanceId" not in keys for _p, keys in att_fixtures),
            str([p for p, k in att_fixtures if "InstanceId" in k]))
    c.check("fixtures model the real Attachment.AttachmentId field",
            any("AttachmentId" in keys for _p, keys in att_fixtures),
            str(att_fixtures[:3]))

    # And the linkage the code actually depends on must be present.
    eni_by_inst = {e.attachment_id: e for e in eu.enis if e.attachment_id}
    ec2_ids = {w.id for w in eu.workloads if w.kind == "ec2"}
    c.check("every EC2 fixture instance has an ENI attached via AttachmentId",
            ec2_ids <= set(eni_by_inst),
            f"missing={sorted(ec2_ids - set(eni_by_inst))}")
    c.check("instance_id is derived only for i- attachments",
            all((e.instance_id == e.attachment_id) if e.attachment_id.startswith("i-")
                else (e.instance_id == "") for e in eu.enis))

    print("\n[2/8] topology indexes and subnet -> route table resolution")
    topo = Topology(snapshots)
    c.eq("regions", topo.regions, ["eu-west-1", "us-east-1"])
    c.eq("total VPCs", len(topo.vpcs), 6)
    c.check(
        "explicit association wins over the main table",
        topo.subnets["subnet-app-1"].rtb_id == "rtb-prod-app"
        and topo.subnets["subnet-app-1"].rtb_association == "explicit",
    )
    c.check(
        "unassociated subnet inherits the main table",
        topo.subnets["subnet-dev-1"].rtb_id == "rtb-dev-main"
        and topo.subnets["subnet-dev-1"].rtb_association == "main",
    )
    c.check("prod VPC cidrs include both associations",
            set(topo.vpc_cidrs("vpc-dev")) == {"10.40.0.0/16", "10.0.5.0/24"},
            str(topo.vpc_cidrs("vpc-dev")))
    c.check("NAT gateway indexed in its subnet", topo.nat_in_subnet("subnet-pub-1") is not None)
    c.check("internet gateway resolved for vpc-prod",
            (topo.igw_for_vpc("vpc-prod") or None) is not None
            and topo.igw_for_vpc("vpc-prod").id == "igw-prod")
    c.check("orphan IGW has no VPC attachment", topo.igws["igw-orphan"].attached is False)
    c.check("longest prefix match picks the /16 over the default",
            topo.rtb_for_subnet("subnet-app-1").route_for("10.30.1.20").target_id == "tgw-hub")
    c.check("default route chosen for 8.8.8.8",
            topo.rtb_for_subnet("subnet-app-1").route_for("8.8.8.8").target_kind == "nat-gateway")
    c.check("TGW route table resolved for the prod attachment",
            (topo.tgw_route_table_for_attachment(topo.tgw_attach_by_vpc["vpc-prod"][0]) or None)
            is not None)
    c.check("overlapping VPC detection sees vpc-dev",
            any(v.id == "vpc-dev" for v in topo.vpcs_overlapping("vpc-prod")))

    # ---------------------------------------------------------------- paths
    print("\n[3/8] route and security group path evaluation")
    engine = PathEngine(topo)

    r = engine.resolve("10.0.10.20", "subnet-app-1", "10.30.1.20", dst_subnet_id="subnet-data-1", with_sg=False)
    c.eq("app subnet reaches data VPC through the transit gateway", r.verdict, "reachable")
    c.check("path crosses the transit gateway",
            any(h.kind == "tgw" for h in r.hops), str([h.kind for h in r.hops]))
    c.check("return path is also reachable", (r.reverse.verdict if r.reverse else None) == "reachable")
    c.check("no asymmetry reported", r.asymmetric is False)

    r = engine.resolve("10.0.10.20", "subnet-app-1", "8.8.8.8", with_sg=False)
    c.eq("app subnet egresses via NAT gateway", r.verdict, "reachable")
    c.check("NAT hop present", any(h.kind == "nat" for h in r.hops))

    r = engine.resolve("10.0.20.30", "subnet-db-1", "8.8.8.8", with_sg=False)
    c.eq("db subnet has no internet egress", r.verdict, "blocked")
    c.check("db subnet block is explained", bool(r.reasons), str(r.reasons))

    r = engine.resolve("10.0.1.50", "subnet-pub-1", "8.8.8.8", with_sg=False)
    c.eq("public subnet egresses via the internet gateway", r.verdict, "reachable")
    c.check("internet gateway hop present", any(h.kind == "igw" for h in r.hops))

    r = engine.resolve("10.30.2.200", "subnet-data-nat", "8.8.8.8", with_sg=False)
    c.eq("data VPC NAT gateway is broken (no default route)", r.verdict, "blocked")
    c.check(
        "broken NAT is explained by the missing default route",
        any("no route in" in reason for reason in r.reasons),
        str(r.reasons),
    )

    r = engine.resolve("10.0.10.20", "subnet-app-1", "10.40.1.20", dst_subnet_id="subnet-dev-1", with_sg=False)
    c.eq("dev VPC is not reachable because it lacks a return route", r.verdict, "blocked")
    c.check(
        "dev block reason names the missing return route",
        any("not the transit gateway" in reason for reason in r.reasons),
        str(r.reasons),
    )

    r = engine.resolve(
        "10.0.1.10", "subnet-pub-1", "10.0.10.20", dst_subnet_id="subnet-app-1", port=8080
    )
    c.eq("ALB reaches app instance on 8080", r.verdict, "reachable")
    c.eq("security groups allow 8080", r.sg_verdict, "reachable")

    r = engine.resolve(
        "10.0.1.10", "subnet-pub-1", "10.0.20.30", dst_subnet_id="subnet-db-1", port=5432
    )
    c.eq("ALB can route to the db subnet", r.verdict, "reachable")
    c.eq("security groups allow 5432 from the ALB", r.sg_verdict, "reachable")

    r = engine.resolve(
        "10.0.1.10", "subnet-pub-1", "10.0.20.30", dst_subnet_id="subnet-db-1", port=22
    )
    c.eq("routing to the db subnet is fine but ssh is blocked", r.sg_verdict, "blocked")
    c.check("sg block names the ingress rules", any("ingress" in n for n in r.reasons), str(r.reasons))

    r = engine.resolve("10.0.10.20", "subnet-app-1", "172.16.1.20", dst_vpc_id="vpc-shared", with_sg=False)
    c.check(
        "cross-region peering path evaluated",
        r.verdict in ("reachable", "conditional", "blocked"),
        f"{r.verdict} {r.reasons}",
    )

    # ---------------------------------------------------------------- analysis
    print("\n[4/8] cross-VPC, load balancer and exposure analysis")
    links = analysis.vpc_links(topo)
    link_pairs = {tuple(sorted((l.a, l.b))) for l in links}
    c.check("transit gateway links discovered",
            ("vpc-data", "vpc-prod") in link_pairs, str(sorted(link_pairs)))
    c.check("dev VPC is linked through the transit gateway",
            ("vpc-dev", "vpc-prod") in link_pairs, str(sorted(link_pairs)))
    c.check("cross-region peering link discovered",
            ("vpc-prod", "vpc-shared") in link_pairs, str(sorted(link_pairs)))
    c.check("unconnected overlapping VPC is not linked",
            not any("vpc-legacy" in p for p in link_pairs), str(sorted(link_pairs)))

    cross = analysis.evaluate_cross_vpc(topo, engine)
    c.check("cross-VPC rows produced", len(cross) >= 3, f"{len(cross)} rows")
    row = next((r for r in cross if {r.src_vpc, r.dst_vpc} == {"vpc-prod", "vpc-data"}), None)
    c.check("prod <-> data evaluated as reachable", row is not None and row.forward == "reachable",
            row.reasons if row else "no row")
    row = next((r for r in cross if "vpc-dev" in (r.src_vpc, r.dst_vpc)), None)
    c.check("prod <-> dev evaluated as blocked", row is not None and row.forward == "blocked",
            f"{row.forward} {row.reasons}" if row else "no row")

    lb_rows = analysis.evaluate_lb_flows(topo, engine)
    c.eq("load balancer target flows evaluated", len(lb_rows), 2)
    c.check("both ALB targets are reachable",
            all(r.verdict == "reachable" for r in lb_rows),
            str([(r.target, r.verdict) for r in lb_rows]))

    exposure = analysis.internet_exposure(topo)
    c.check("bastion public IP is reported", any(r.ip == "203.0.113.50" for r in exposure))
    c.check("public RDS is reported", any("shared-mysql" in r.resource for r in exposure))

    cidr = analysis.cidr_map(topo)
    c.check("cidr map covers every subnet", len(cidr) == len(topo.subnets))

    # ---------------------------------------------------------------- rules
    print("\n[5/8] findings engine")
    findings = run_rules(topo)
    rule_ids = {f.rule_id for f in findings}
    expected = {
        "NET001",  # public subnet with a public IP
        "NET002",  # dual default routes
        "NET003",  # NAT gateway without a route to the internet
        "NET005",  # route table -> unattached IGW
        "NET006",  # orphan IGW
        "NET007",  # unused route table
        "NET008",  # overlapping CIDRs on a connected pair
        "NET009",  # one-way TGW routing
        "NET010",  # catch-all TGW route
        "NET011",  # one-way peering
        "NET013",  # partial TGW attachment
        "NET015",  # SSH open to the world
        "NET016",  # allow-all security group
        "NET017",  # unused security group
        "NET018",  # no flow logs
        "NET019",  # public RDS
        "NET020",  # NACL allows a sensitive port
        "NET021",  # endpoint allow-all policy
        "NET023",  # subnet with no default route
        "NET027",  # route to a TGW with no attachment
    }
    for rule_id in sorted(expected):
        c.check(f"{rule_id} fires", rule_id in rule_ids)
    c.check("no rule crashed", not any(f.rule_id == "INTERNAL" for f in findings),
            str([f.evidence for f in findings if f.rule_id == "INTERNAL"]))
    c.check("severities are ordered", [f.severity for f in findings] == sorted(
        [f.severity for f in findings],
        key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[s]))
    ssh = next((f for f in findings if f.rule_id == "NET015" and f.resource == "sg-ssh"), None)
    c.check("NET015 evidence names port 22",
            ssh is not None and "22/ssh" in ssh.evidence, ssh.evidence if ssh else "")
    c.check("NET011 targets the peering connection",
            any(f.rule_id == "NET011" and f.resource == "pcx-prod-shared" for f in findings))
    c.check("NET002 targets the duplicate route table",
            any(f.rule_id == "NET002" and f.resource == "rtb-prod-dup" for f in findings))
    c.check("NET027 does not fire for vpc-prod (attachment exists)",
            not any(f.rule_id == "NET027" and f.vpc_id == "vpc-prod" for f in findings))

    # ---------------------------------------------------------------- diagrams
    print("\n[6/8] mermaid rendering")
    fmodel = flow.build_flow_model(topo)
    topology_mmd = mermaid.render_topology(topo, fmodel)
    diagrams: Dict[str, str] = {"topology": topology_mmd}
    tricky = mermaid.MermaidBuilder("escaping", "TB")
    tricky.node("k1", 'quote " pipe | brace {} lt < gt > amp & hash #')
    tricky.node("k2", "second")
    tricky.edge("k1", "k2", 'label "with" quotes | and #hashes')
    diagrams["tricky-labels"] = tricky.render()
    for name, text in diagrams.items():
        problems = validate_mermaid(text)
        c.check(f"{name}.mmd is structurally valid", not problems, "; ".join(problems[:4]))
    # -- the one diagram answers the design brief ---------------------------
    t = diagrams["topology"]
    c.check("topology names every VPC",
            all(v in t for v in ("vpc-prod", "vpc-data", "vpc-dev", "vpc-shared", "vpc-legacy")))
    c.check("topology has the Account > VPC > AZ > Subnet nesting",
            "AWS ACCOUNT" in t and "AVAILABILITY ZONE" in t
            and t.count("AVAILABILITY ZONE") >= 4 and "SUBNET  \u00b7" in t)
    c.check("topology shows every subnet id and cidr",
            all(s.id in t for s in topo.subnets.values())
            and all(s.cidr in t for s in topo.subnets.values() if s.cidr))
    # Route tables / NACLs / SGs only appear where they are actually attached;
    # the unattached ones must still be accounted for rather than dropped.
    attached_rtb = {topo.rtb_for_subnet(x.id).id for x in topo.subnets.values()
                    if topo.rtb_for_subnet(x.id)}
    c.check("topology shows every attached route table",
            all(r.id in t for r in topo.route_tables.values() if r.id in attached_rtb))
    attached_nacl = {topo.nacl_by_subnet[x.id].id for x in topo.subnets.values()
                     if topo.nacl_by_subnet.get(x.id)}
    c.check("topology shows every attached NACL",
            all(a.id in t for a in topo.nacls.values() if a.id in attached_nacl))
    used_sg = set()
    for _w in topo.workloads.values():
        used_sg.update(_w.sg_ids or [])
    for _e in topo.enis.values():
        used_sg.update(_e.sg_ids or [])
    c.check("topology shows every security group that is attached somewhere",
            all(g.id in t for g in topo.security_groups.values() if g.id in used_sg))
    c.check("unattached route tables / NACLs / SGs are accounted for, not dropped",
            all(r.id in t for r in topo.route_tables.values() if r.id not in attached_rtb)
            and all(g.id in t for g in topo.security_groups.values() if g.id not in used_sg))
    c.check("topology classifies subnets public/private/isolated",
            "PUBLIC SUBNET" in t and "PRIVATE SUBNET" in t and "ISOLATED SUBNET" in t)
    c.check("classification comes from the route table, not the name",
            all(f"Type: {r.classification.upper()}" in t for r in fmodel.routing.values()))

    # Arrows must be traffic paths carrying the route that justifies them.
    c.check("every arrow label names a destination or a port",
            all(e.label for e in fmodel.edges))
    c.check("gateway arrows carry the route destination",
            any(e.dst == flow.nid("nat", "nat-prod") and e.label == "0.0.0.0/0"
                for e in fmodel.edges)
            and any(e.dst == flow.nid("igw", "igw-prod") and e.label == "0.0.0.0/0"
                    for e in fmodel.edges))
    c.check("no arrow label repeats the node it points at",
            not any(w in e.label for e in fmodel.edges
                    for w in ("NAT Gateway", "Internet Gateway", "Transit Gateway")),
            str([e.label for e in fmodel.edges
                 if "Gateway" in e.label][:3]))
    c.check("workload arrows carry a port and a route",
            any(e.label.startswith("TCP :") and "local" in e.label for e in fmodel.edges))
    c.check("internet ingress reaches the ALB's public subnet",
            any(e.src == flow.nid("igw", "igw-prod")
                and e.dst == flow.sid("subnet-pub-1") for e in fmodel.edges))
    c.check("private subnet egress reaches NAT then IGW",
            any(e.dst == flow.nid("nat", "nat-prod") for e in fmodel.edges)
            and any(e.src == flow.nid("nat", "nat-prod")
                    and e.dst == flow.nid("igw", "igw-prod") for e in fmodel.edges))
    c.check("ALB targets its registered targets on the listener port",
            any(e.src == flow.wid("def456") and e.dst == flow.wid("i-app-01")
                and "HTTPS:443" in e.label and "TG: tg-app" in e.label
                for e in fmodel.edges),
            str([e.label for e in fmodel.edges if e.src == flow.wid("def456")]))
    c.check("a target group is never a node of its own",
            not any("tg-app" in n for n in mermaid._known_node_ids(topo)))
    c.check("EC2 reaches RDS over the intra-VPC local route",
            any(e.src == flow.wid("i-app-01") and e.dst == flow.wid("db-prod-postgres")
                and "TCP :5432" in e.label and "local" in e.label for e in fmodel.edges))
    c.check("RDS ENI is linked so the EC2 -> RDS path can be traced",
            bool(topo.workloads["db-prod-postgres"].eni_ids))
    # Section 12: a TGW arrow must land on a subnet in an *attached* VPC. The
    # previous version of this check had `if False` in its generator plus a
    # trailing `or True`, so it asserted nothing and could not fail.
    attached_vpcs = {
        a.resource_id for a in (topo.tgws["tgw-hub"].attachments or [])
        if a.resource_type == "vpc"
    }
    tgw_targets = [
        topo.subnets[e.dst[len("s_"):].replace("_", "-")]
        for e in fmodel.edges
        if e.src == flow.nid("tgw", "tgw-hub")
        and e.dst.startswith("s_")
    ]
    c.check("the transit gateway actually reaches some subnets",
            len(tgw_targets) > 0, f"{len(tgw_targets)} subnet(s)")
    c.check("transit gateway only reaches subnets in attached VPCs",
            all(sub.vpc_id in attached_vpcs for sub in tgw_targets),
            str(sorted({sub.vpc_id for sub in tgw_targets}
                       - attached_vpcs)))
    c.check("peering is only drawn where a route uses it",
            any(e.src == flow.nid("pcx", "pcx-prod-shared") for e in fmodel.edges))

    # Identity: the workloads map is keyed by id, so two resources sharing an id
    # silently overwrite each other and vanish from the diagram. This is a real
    # bug that was present (ECS services were keyed by their *cluster* name).
    ids = [w.id for w in topo.workloads.values()]
    c.check("every workload has a unique id", len(ids) == len(set(ids)),
            str(sorted({i for i in ids if ids.count(i) > 1})))
    c.check("every ECS service keeps its own identity",
            len({w.id for w in topo.workloads.values() if w.kind == "ecs-service"})
            == len([w for w in topo.workloads.values() if w.kind == "ecs-service"]))

    # Section 16: an unevaluated rule must never look like a permitted one.
    # A "path" is an edge between two endpoints whose security groups can be
    # evaluated. Subnet -> NAT and NAT -> IGW are routing hops with no SG pair.
    path_edges = [e for e in fmodel.edges if e.kind == "target"]
    c.check("every path edge states a security status",
            all("security: " in e.label for e in path_edges),
            str([e.label for e in path_edges if "security: " not in e.label][:3]))
    c.check("security status is one of allowed/blocked/unknown",
            all(any(f"security: {x}" in e.label for x in
                    ("allowed", "blocked", "unknown")) for e in path_edges))
    c.check("a blocked path is labelled as blocked",
            all("security: blocked" in e.label
                for e in path_edges if "blocked" in e.label.lower()))

    # The two hard prohibitions from the brief.
    c.check("no 'filtered by' edge anywhere", "filtered by" not in t)
    c.check("no 'hosts'/'uses'/'associated with'/'routes here' edge labels",
            not any(w in e.label.lower() for e in fmodel.edges
                    for w in ("filtered by", "hosts", "uses", "associated with", "routes here")))
    c.check("'local' is never rendered as a node",
            "local gateway" not in t.lower() and "LOCAL GATEWAY" not in t)
    c.check("NACLs and SGs are never nodes",
            not re.search(r'\[(?:SUBNET )?acl-', t) and not re.search(r'\[SG ', t))
    c.check("no dangling node references",
            "unresolved" not in t, "a node was referenced but never defined")
    # Structural reference integrity: every node an arrow mentions must be
    # declared by a node statement, or Mermaid drops the arrow.
    declared = set(re.findall(r"^\s*(n\d+)[\[({]", t, re.M))
    mentioned = set(re.findall(r"\b(n\d+)\b", t))
    arrow_targets = set()
    for line in t.splitlines():
        mm = re.match(r"^\s*(n\d+)\s*-->\|?[^|]*\|?\s*(n\d+)", line)
        if mm:
            arrow_targets.update(mm.groups())
    c.check("every node used in an arrow is declared",
            arrow_targets <= declared,
            f"missing={sorted(arrow_targets - declared)}")
    c.check("the complete fixture needs no OFF DIAGRAM placeholders",
            "OFF DIAGRAM" not in t)
    az_containers = len(re.findall(r'^subgraph sg\d+\["AVAILABILITY ZONE ', t, re.M))
    subnet_containers = len(re.findall(r'^subgraph sg\d+\["\w+ SUBNET  \u00b7', t, re.M))
    c.check("exactly one AZ container per (vpc, az) and one subnet container per subnet",
            az_containers == len({(x.vpc_id, x.az or "unknown-az") for x in topo.subnets.values()})
            and subnet_containers == len(topo.subnets),
            f"az={az_containers} subnet={subnet_containers}")
    c.check("the diagram is a single flowchart",
            topology_mmd.count("flowchart") == 1)
    c.check("special characters are escaped in labels",
            "#quot;" in diagrams["tricky-labels"] and "#124;" in diagrams["tricky-labels"]
            and "#35;" in diagrams["tricky-labels"] and "#lt;" in diagrams["tricky-labels"],
            diagrams["tricky-labels"])

    # Regression: mermaid does not accept a bare "->" or "-.-" as a link. It lexes
    # them as MINUS and fails with "got 'MINUS'". These spell out the real report.
    c.check("every emitted link style is a real mermaid link token",
            not _invalid_styles(diagrams), "; ".join(_invalid_styles(diagrams)[:4]))
    try:
        mermaid.MermaidBuilder("bad", "TB").edge("a", "b", "", "->")
        c.check("edge() rejects an invalid link style", False, "no error raised for '->'")
    except ValueError as exc:
        c.check("edge() rejects an invalid link style", "->" in str(exc), str(exc))
    broken = {
        "internet": "flowchart TB\nn1([\"a\"])\nn2([\"b\"])\n  n1 -> n2\n  n1 -.- n2\n",
        "ok": "flowchart TB\nn1([\"a\"])\nn2([\"b\"])\n  n1 -.-> n2\n",
    }
    caught = _invalid_styles(broken)
    c.check("the link checker catches the reported bad styles",
            any("'->'" in x for x in caught) and any("'-.-'" in x for x in caught), str(caught))
    c.check("the link checker passes valid styles", not _invalid_styles({"ok": broken["ok"]}))

    # ---------------------------------------------------------------- reports
    # ---------------------------------------------------- live-shape regressions
    print("\n[6b/8] live AWS response shapes")

    # Regression: ECS list_clusters / list_services return ARNs as plain strings.
    # The collector used to subscript them as dicts, which raised
    # "TypeError: string indices must be integers" against a real account.
    from .collect import Collector
    from .model import AccountSnapshot as _Snap

    class _EcsClient:
        def list_clusters(self, **kw):
            return {"clusterArns": ["arn:aws:ecs:eu-west-1:111122223333:cluster/prod"]}

        def describe_clusters(self, clusters=None, **kw):
            return {
                "clusters": [
                    {
                        "clusterArn": clusters[0],
                        "clusterName": "prod",
                        "status": "ACTIVE",
                        "resourcesVpcConfig": {
                            "vpcId": "vpc-prod",
                            "subnetIds": ["subnet-app-1"],
                            "securityGroups": ["sg-app"],
                        },
                        "registeredContainerInstancesCount": 3,
                    }
                ]
            }

        def list_services(self, cluster=None, **kw):
            return {"serviceArns": [f"{cluster}/svc-web"]}

        def describe_services(self, cluster=None, services=None, **kw):
            return {
                "services": [
                    {
                        "serviceArn": services[0],
                        "serviceName": "svc-web",
                        "status": "ACTIVE",
                        "desiredCount": 2,
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "subnets": ["subnet-app-1"],
                                "securityGroups": ["sg-app"],
                            }
                        },
                    }
                ]
            }

    class _Pool:
        def get(self, service):
            return _EcsClient()

    class _OfflineCollector(Collector):
        """Real Collector logic, but no boto3 session (the self-test has none)."""

        def start(self) -> None:
            self._started = True

    from .model import Subnet as _Sub

    snap = _Snap(region="eu-west-1")
    # Subnets are collected before ECS, so the service's VPC can be inferred.
    snap.subnets = [
        _Sub(id="subnet-app-1", region="eu-west-1", vpc_id="vpc-prod", cidr="10.0.10.0/24", az="eu-west-1a")
    ]
    col = _OfflineCollector(regions=["eu-west-1"])
    col.start()
    try:
        col._collect_ecs(_Pool(), "eu-west-1", snap)
        names = {w.name for w in snap.workloads}
        c.check("ECS cluster ARNs are handled as strings, not dicts",
                "prod" in names, str(sorted(names)))
        c.check("ECS service ARNs are handled as strings, not dicts",
                "svc-web" in names, str(sorted(names)))
        svc = next((w for w in snap.workloads if w.name == "svc-web"), None)
        c.check("ECS service is placed in the VPC implied by its subnets",
                svc is not None and svc.vpc_id == "vpc-prod",
                svc.vpc_id if svc else "missing")
    except Exception as exc:  # noqa: BLE001
        c.check("ECS collection does not raise on string ARN lists", False, repr(exc))

    # Regression: a NAT gateway can reference a subnet that never made it into the
    # inventory. Rendering used to dereference the missing subnet and crash the run
    # with "'NoneType' object has no attribute 'az'".
    from .model import NatGw, Route, RouteTable, Subnet as _Subnet

    broken_snap = _Snap(region="eu-west-1")
    broken_snap.subnets = [
        _Subnet(id="subnet-app-1", region="eu-west-1", vpc_id="vpc-x",
                cidr="10.9.0.0/24", az="eu-west-1a", rtb_id="rtb-1"),
    ]
    # The default route points at a NAT gateway whose own subnet never made it
    # into the inventory (failed collection, or a cross-account reference).
    broken_snap.route_tables = [
        RouteTable(
            id="rtb-1", region="eu-west-1", vpc_id="vpc-x", subnet_ids=["subnet-app-1"],
            routes=[Route(destination="0.0.0.0/0", target_kind="nat", target_id="nat-dangling")],
        )
    ]
    broken_snap.nat_gateways = [
        NatGw(id="nat-dangling", region="eu-west-1", subnet_id="subnet-not-collected",
              vpc_id="vpc-x", state="available", connect_type="public",
              address="eipalloc-x", tags={})
    ]
    try:
        m2 = flow.build_flow_model(Topology([broken_snap]))
        nat_node = flow.nid("nat", "nat-dangling")
        drawn = [e for e in m2.edges if e.src == flow.sid("subnet-app-1")]
        c.check("a NAT gateway pointing at an uncollected subnet does not crash the model", True)
        c.check("the egress arrow to the dangling NAT is still drawn",
                any(e.dst == nat_node for e in drawn),
                str([(e.src, e.dst) for e in drawn]))
        c.check("the missing subnet is explained in the diagram, not silently dropped",
                any("not found in inventory" in n for n in m2.notes.get(nat_node, [])),
                str(m2.notes.get(nat_node)))
    except Exception as exc:  # noqa: BLE001
        c.check("a NAT gateway pointing at an uncollected subnet does not crash the model",
                False, repr(exc))

    # ------------------------------------------------------- WAN edge semantics
    print("\n[6c/8] external network semantics")

    col2 = FixtureCollector(
        build_fixtures(),
        cache_dir=None,
        services=("ec2-workloads", "elbv2", "rds", "ecs", "eks", "lambda"),
        pool_factory=lambda region: FakePool(region),
    )
    col2.start()
    m3 = flow.build_flow_model(
        Topology([col2.collect_region(region) for region in build_fixtures()])
    )

    def _edge(a, b):
        return [(e.src, e.dst, e.label) for e in m3.edges if e.src == a and e.dst == b]

    def _has(a, b):
        return any(es == a and ed == b for es, ed, _lbl in _edge(a, b))

    vgw_node = flow.nid("vgw", "vgw-sandbox")
    onprem = flow.onprem_node()
    net = flow.internet_node()

    c.check("a subnet routed to a VPN gateway continues on-premises",
            _has(vgw_node, onprem), str(_edge(vgw_node, onprem)))
    c.check("a VPN gateway is labelled by tunnel type, not 'VPN tunnel'",
            any("IPsec" in lbl for _s, _d, lbl in _edge(vgw_node, onprem)),
            str(_edge(vgw_node, onprem)))
    c.check("the VPN gateway internet leg names the on-premises network",
            all("on-premises" in lbl for _s, _d, lbl in _edge(vgw_node, net)),
            str(_edge(vgw_node, net)))
    c.check("a journey is not drawn in both directions for its own sake",
            _edge(onprem, vgw_node) == [], str(_edge(onprem, vgw_node)))
    c.check("a VPN gateway never claims a direct Internet Gateway hop",
            all("Internet Gateway" not in lbl for _s, _d, lbl in _edge(vgw_node, net)),
            str(_edge(vgw_node, net)))

    # The demo transit gateway has only VPC attachments, so it has no path to
    # either Direct Connect or the internet. Drawing either would be a fiction.
    tgw_node = flow.nid("tgw", "tgw-hub")
    c.check("a TGW with only VPC attachments has no Direct Connect leg",
            _edge(onprem, tgw_node) == [], str(_edge(onprem, tgw_node)))
    c.check("a TGW with only VPC attachments has no internet leg",
            _edge(tgw_node, net) == [], str(_edge(tgw_node, net)))

    # A TGW that really does front a VPN attachment must gain both legs.
    from .model import Tgw, TgwAttachment, TgwRoute, TgwRouteTable
    dx_snap = _Snap(region="eu-west-1")
    dx_snap.tgws = [
        Tgw(id="tgw-dx", region="eu-west-1", state="available",
            attachments=[
                TgwAttachment(id="tgw-attach-vpc", tgw_id="tgw-dx", region="eu-west-1",
                              resource_type="vpc", vpc_id="vpc-x", subnet_ids=[], cidr_blocks=[], tags={}),
                TgwAttachment(id="tgw-attach-vpn", tgw_id="tgw-dx", region="eu-west-1",
                              resource_type="vpn", vpc_id="", subnet_ids=[], cidr_blocks=[], tags={}),
            ],
            route_tables=[
                TgwRouteTable(id="tgw-rtb", tgw_id="tgw-dx", region="eu-west-1",
                              routes=[TgwRoute(destination="0.0.0.0/0", target_kind="vpn",
                                               target_id="tgw-attach-vpn",
                                               attachment_id="tgw-attach-vpn")])
            ])
    ]
    m4 = flow.build_flow_model(Topology([dx_snap]))
    dx_node = flow.nid("tgw", "tgw-dx")
    dx_edges = {(e.src, e.dst) for e in m4.edges}
    c.check("a TGW with a VPN attachment does get an on-premises leg",
            (dx_node, flow.onprem_node()) in dx_edges, str(sorted(dx_edges)))
    c.check("a TGW whose route table sends 0.0.0.0/0 to VPN does get an internet leg",
            (dx_node, flow.internet_node()) in dx_edges, str(sorted(dx_edges)))

    print("\n[7/8] CSV / JSON / Markdown output")
    tmp = tempfile.mkdtemp(prefix="nm-selftest-")
    try:
        report.write_csv(os.path.join(tmp, "routes.csv"), report.route_rows(topo))
        with open(os.path.join(tmp, "routes.csv"), encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        c.check("routes.csv has rows", len(rows) > 0)
        header = set(rows[0].keys())
        for column in ("vpc_id", "subnet_id", "route_table_id", "destination", "target", "target_type"):
            c.check(f"routes.csv has {column}", column in header)
        app_row = next(
            (r for r in rows
             if r["subnet_id"] == "subnet-app-1" and r["destination"] == "10.30.0.0/16"),
            None,
        )
        c.check("routes.csv row for app -> tgw",
            app_row is not None
            and app_row["target"] == "tgw-hub"
            and app_row["target_type"] == "transit-gateway",
            str(app_row))
        local_row = next((r for r in rows if r["target_type"] == "local"), None)
        c.check("local routes are labelled", local_row is not None and local_row["target"] == "local")

        report.write_inventory_json(os.path.join(tmp, "inventory.json"), topo, {"mode": "selftest"})
        with open(os.path.join(tmp, "inventory.json"), encoding="utf-8") as fh:
            payload = json.load(fh)
        c.eq("inventory.json VPC count", len(payload["vpcs"]), 6)
        c.check("inventory.json route tables present", len(payload["route_tables"]) > 0)

        report.write_text(
            os.path.join(tmp, "findings.md"), report.findings_markdown(findings, topo)
        )
        with open(os.path.join(tmp, "findings.md"), encoding="utf-8") as fh:
            md = fh.read()
        c.check("findings.md lists the rule ids", "NET015" in md and "NET001" in md)

        # ------------------------------------------------------- cache round-trip
        cache_dir = os.path.join(tmp, "cache")
        for region, payloads in fixtures.items():
            for key, value in payloads.items():
                report.write_text(
                    os.path.join(cache_dir, region, key.replace("/", "_") + ".json"),
                    json.dumps(value, default=str),
                )
        offline = Collector(
            regions=sorted(fixtures),
            cache_dir=cache_dir,
            offline=True,
            services=("ec2-workloads", "elbv2", "rds", "ecs", "eks", "lambda"),
        )
        offline.start()
        offline_snapshots = [offline.collect_region(r) for r in sorted(fixtures)]
        offline_topo = Topology(offline_snapshots)
        c.eq("offline rebuild matches live summary", offline_topo.summary(), topo.summary())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Regression: an account with no findings at all used to crash report
    # generation with "append() takes exactly one argument (2 given)".
    try:
        empty_md = report.start_here_markdown(topo, [], ["00-network-topology.mmd"])
        c.check("START-HERE renders for an account with zero findings", True)
        c.check("a clean account is told there are no findings",
                "None" in empty_md or "none" in empty_md.lower(), empty_md[:120])
    except Exception as exc:  # noqa: BLE001
        c.check("START-HERE renders for an account with zero findings", False, repr(exc))

    # Determinism must not be a coin flip. Two runs can agree by luck, so check
    # the property directly: the optional collectors append to snap.workloads
    # from a thread pool, so collect_region must hand back a sorted list.
    col4 = FixtureCollector(
        build_fixtures(), cache_dir=None,
        services=("ec2-workloads", "elbv2", "rds", "ecs", "eks", "lambda"),
        pool_factory=lambda region: FakePool(region),
    )
    col4.start()
    ordered = [col4.collect_region(region) for region in build_fixtures()]
    for snap4 in ordered:
        keys = [(w.kind, w.vpc_id, w.id) for w in snap4.workloads]
        c.check(f"{snap4.region}: collected workloads are sorted, not thread-ordered",
                keys == sorted(keys), str(keys[:4]))

    # And the renderer must be a pure function of the topology it is handed.
    topo4 = Topology(ordered)
    m_a = mermaid.render_topology(topo4, flow.build_flow_model(topo4))
    m_b = mermaid.render_topology(topo4, flow.build_flow_model(topo4))
    c.check("rendering the same topology twice is byte-identical", m_a == m_b)

    # ------------------------------------------------- incomplete inventory
    print("\n[6d/8] incomplete inventory does not break the diagram")

    # The shape that produced a hard crash in the field: a NAT gateway whose own
    # subnet was never collected, while other subnets still route at it.
    holedict = build_fixtures()
    holedict["eu-west-1"]["describe_subnets"] = [
        s for s in holedict["eu-west-1"]["describe_subnets"] if s["SubnetId"] != "subnet-pub-1"
    ]
    col5 = FixtureCollector(
        holedict, cache_dir=None,
        services=("ec2-workloads", "elbv2", "rds", "ecs", "eks", "lambda"),
        pool_factory=lambda region: FakePool(region),
    )
    col5.start()
    try:
        topo5 = Topology([col5.collect_region(r) for r in holedict])
        m5 = flow.build_flow_model(topo5)
        t5 = mermaid.render_topology(topo5, m5)
        c.check("a NAT whose subnet was not collected still renders", True)
        c.check("a NAT whose subnet is missing still renders as a component",
                "NAT GATEWAY<br/>nat-prod" in t5,
                [x for x in t5.splitlines() if "NAT GATEWAY" in x])
        c.check("that NAT says which subnet is missing",
                "subnet-pub-1 not found in inventory" in t5,
                [x for x in t5.splitlines() if "not found in inventory" in x])
        c.check("no network component is ever a placeholder",
                "OFF DIAGRAM" not in t5 and "OMITTED" not in t5,
                [x for x in ("OFF DIAGRAM", "OMITTED") if x in t5])
        d5 = set(re.findall(r"^\s*(n\d+)[\[({]", t5, re.M))
        a5 = set()
        for line in t5.splitlines():
            mm = re.match(r"^\s*(n\d+)\s*-->\|?[^|]*\|?\s*(n\d+)", line)
            if mm:
                a5.update(mm.groups())
        c.check("no arrow points at an undeclared node with a hole in the inventory",
                a5 <= d5, f"missing={sorted(a5 - d5)}")
        c.check("the arrows into the unresolved NAT survive",
                any(e.dst == flow.nid("nat", "nat-prod") for e in m5.edges))
    except Exception as exc:  # noqa: BLE001
        c.check("a NAT whose subnet was not collected still renders", False, repr(exc))

    print("\n[8/8] CLI entry point")
    from .cli import main

    out = tempfile.mkdtemp(prefix="nm-cli-")
    try:
        rc = main(["--demo", "--out", out, "--quiet"])
        c.eq("demo run exits 0", rc, 0)

        # Default output is exactly ONE topology diagram. Reports are opt-in.
        c.check(
            "default output writes the single topology diagram",
            os.path.exists(os.path.join(out, "00-network-topology.mmd")),
        )
        c.check("default output writes START-HERE.md",
                os.path.exists(os.path.join(out, "START-HERE.md")))
        mmd = sorted(f for f in os.listdir(out) if f.endswith(".mmd"))
        c.eq("default output contains exactly one .mmd file", mmd, ["00-network-topology.mmd"])
        for name in ("report.md", "inventory.json", "findings", "reports", "vpcs", "subnets"):
            c.check(
                f"default output has no {name}",
                not os.path.exists(os.path.join(out, name)),
            )

        start_md = open(os.path.join(out, "START-HERE.md"), encoding="utf-8").read()
        c.check("START-HERE points at the one diagram",
                "00-network-topology.mmd" in start_md)
        c.check("START-HERE explains how to render", "mermaid.live" in start_md)
        c.check("START-HERE lists findings", "NET0" in start_md)

        out2 = tempfile.mkdtemp(prefix="nm-cli-rep-")
        try:
            rc = main(["--demo", "--out", out2, "--quiet", "--reports"])
            c.eq("--reports run exits 0", rc, 0)
            for name in (
                "report.md",
                "inventory.json",
                "findings/findings.md",
                "findings/findings.csv",
                "reports/routes.csv",
                "reports/subnets.csv",
                "reports/cross-vpc-connectivity.csv",
                "reports/load-balancer-flows.csv",
                "reports/internet-exposure.csv",
                "reports/cidr-map.csv",
            ):
                c.check(f"--reports writes {name}", os.path.exists(os.path.join(out2, name)))
        finally:
            shutil.rmtree(out2, ignore_errors=True)

        rc = main(["--demo", "--out", out, "--quiet", "--no-diagrams", "--no-rules"])
        c.eq("flags are accepted together", rc, 0)
    finally:
        shutil.rmtree(out, ignore_errors=True)

    print()
    total = c.passed + len(c.failed)
    if c.failed:
        print(f"FAILED {len(c.failed)}/{total} checks:")
        for failure in c.failed:
            print(f"  - {failure}")
        return 1
    print(f"OK - all {total} checks passed")
    return 0
