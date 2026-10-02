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
from typing import Any, Callable, Dict, List, Tuple

from . import analysis, mermaid, report
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
EDGE_RE = re.compile(
    r"^\s*(n\d+)\s*(<-\.->|<-\.\.->|-\.\.->|-\.->|-->|==>|-\.-|->|<-)\s*"
    r"(?:\|[^|]*\|\s*)?(n\d+)\s*$"
)
CLASS_RE = re.compile(r"^\s*class\s+(n\d+)\s")
SUBGRAPH_RE = re.compile(r"^\s*subgraph\s+(sg\d+)\[")
LABEL_RE = re.compile(r'(["\[])("(?:[^"\\]|\\.)*")\s*[\])]}')


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
    diagrams: Dict[str, str] = {
        "overview": mermaid.render_overview(topo, max_vpcs=40),
        "tgw": mermaid.render_tgw(topo),
        "internet": mermaid.render_internet(topo),
        "vpc-prod": mermaid.render_vpc(topo, "vpc-prod"),
        "vpc-dev": mermaid.render_vpc(topo, "vpc-dev"),
        "subnet-app-1": mermaid.render_subnet(topo, "subnet-app-1"),
        "connectivity": mermaid.render_connectivity(topo, [cross[0]] if cross else []),
    }
    tricky = mermaid.MermaidBuilder("escaping", "TB")
    tricky.node("k1", 'quote " pipe | brace {} lt < gt > amp & hash #')
    tricky.node("k2", "second")
    tricky.edge("k1", "k2", 'label "with" quotes | and #hashes')
    diagrams["tricky-labels"] = tricky.render()
    for name, text in diagrams.items():
        problems = validate_mermaid(text)
        c.check(f"{name}.mmd is structurally valid", not problems, "; ".join(problems[:4]))
    c.check("overview names every VPC",
            all(v in diagrams["overview"] for v in ("vpc-prod", "vpc-data", "vpc-dev", "vpc-shared", "vpc-legacy")))
    c.check("per-VPC diagram includes its subnets",
            "subnet-app-1" in diagrams["vpc-prod"] and "rtb-prod-app" in diagrams["vpc-prod"])
    c.check("special characters are escaped in labels",
            "#quot;" in diagrams["tricky-labels"] and "#124;" in diagrams["tricky-labels"]
            and "#35;" in diagrams["tricky-labels"] and "#lt;" in diagrams["tricky-labels"],
            diagrams["tricky-labels"])

    # ---------------------------------------------------------------- reports
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

    print("\n[8/8] CLI entry point")
    from .cli import main

    out = tempfile.mkdtemp(prefix="nm-cli-")
    try:
        rc = main(["--demo", "--out", out, "--quiet"])
        c.eq("demo run exits 0", rc, 0)
        expected_files = [
            "report.md",
            "inventory.json",
            "00-overview.mmd",
            "01-transit-gateways.mmd",
            "02-internet-paths.mmd",
            "findings/findings.md",
            "findings/findings.csv",
            "reports/routes.csv",
            "reports/subnets.csv",
            "reports/cross-vpc-connectivity.csv",
            "reports/load-balancer-flows.csv",
            "reports/internet-exposure.csv",
            "reports/cidr-map.csv",
        ]
        for name in expected_files:
            c.check(f"demo output has {name}", os.path.exists(os.path.join(out, name)))
        c.check(
            "per-VPC diagrams written",
            any(f.startswith("eu-west-1-") for f in os.listdir(os.path.join(out, "vpcs"))),
        )
        rc = main(["--demo", "--out", out, "--quiet", "--no-diagrams", "--no-reports", "--no-rules"])
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
