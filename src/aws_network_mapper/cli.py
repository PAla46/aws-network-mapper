"""Command line interface for the AWS network mapper."""

from __future__ import annotations

import argparse
import datetime
import os
import sys
import time
import traceback
from typing import Dict, List, Optional, Sequence

from .discovery import Collector, CollectorError
from .graph import Topology, connectivity as flow
from .graph import cross_vpc as analysis
from .graph.routing import PathEngine
from .model import AccountSnapshot
from .render import mermaid
from .render import reports as report
from .rules import Finding, run_rules

CORE_SERVICES = ("ec2-workloads", "elbv2", "rds", "ecs", "eks", "lambda")
SERVICE_CHOICES = CORE_SERVICES + ("core-only",)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-network-mapper",
        description=(
            "Read-only AWS network and route topology mapper. Collects VPCs, subnets, "
            "route tables and attached resources, then draws how everything connects. "
            "Diagrams only by default; pass --reports for CSV/Markdown evidence."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  aws-network-mapper.py --regions eu-west-1,us-east-1 --out ./map\n"
            "  aws-network-mapper.py --all-regions\n"
            "  aws-network-mapper.py --offline --cache-dir ./map/.cache --out ./map2\n"
            "  aws-network-mapper.py --demo --out ./demo     # no AWS calls at all\n"
        ),
    )
    parser.add_argument("--regions", default="", help="comma separated region list")
    parser.add_argument(
        "--all-regions",
        action="store_true",
        help="scan every region that is enabled for the account",
    )
    parser.add_argument("--out", default="aws-network-map", help="output directory")
    parser.add_argument(
        "--cache-dir",
        default="",
        help="raw response cache (default: <out>/.cache)",
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="neither read nor write the cache"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="rebuild all output from the cache without calling AWS",
    )
    parser.add_argument(
        "--services",
        default=",".join(CORE_SERVICES),
        help=f"comma separated subset of: {','.join(SERVICE_CHOICES)} (default: all)",
    )
    parser.add_argument("--max-workers", type=int, default=8, help="parallel API calls per region")
    parser.add_argument(
        "--reports",
        action="store_true",
        help="also write CSV/JSON/Markdown evidence (off by default)",
    )
    parser.add_argument("--no-diagrams", action="store_true", help="skip Mermaid diagrams")
    parser.add_argument(
        "--no-rules",
        action="store_true",
        help="do not annotate diagrams with findings",
    )
    parser.add_argument(
        "--deep",
        action="store_true",
        help="evaluate extra flows (more cross-VPC pairs) for the reports",
    )
    parser.add_argument("--max-vpc-pairs", type=int, default=500, help="cap on cross-VPC evaluations")
    parser.add_argument(
        "--max-diagram-subnets",
        type=int,
        default=200,
        help="subnets drawn per VPC in the topology diagram",
    )
    parser.add_argument(
        "--max-diagram-vpcs",
        type=int,
        default=60,
        help="VPCs drawn in the topology diagram",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="less console output")
    parser.add_argument("--demo", action="store_true", help="run the bundled synthetic scenario")
    parser.add_argument("--self-test", action="store_true", help="run offline checks and exit")
    parser.add_argument("--version", action="version", version="aws-network-mapper 1.0.0")
    return parser


class Logger:
    def __init__(self, quiet: bool = False, logfile: Optional[str] = None):
        self.quiet = quiet
        self.handle = None
        if logfile:
            report.ensure_dir(os.path.dirname(logfile) or ".")
            self.handle = open(logfile, "a", encoding="utf-8")

    def __call__(self, message: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {message}"
        if self.handle:
            self.handle.write(line + "\n")
            self.handle.flush()
        if not self.quiet:
            print(line, file=sys.stderr)

    def close(self) -> None:
        if self.handle:
            self.handle.close()


def parse_services(value: str) -> List[str]:
    value = (value or "").strip().lower()
    if value in ("core-only", "core", "none", "ec2"):
        return []
    chosen = [s.strip() for s in value.split(",") if s.strip()]
    invalid = [s for s in chosen if s not in SERVICE_CHOICES]
    if invalid:
        raise SystemExit(f"unknown services: {', '.join(invalid)}; valid: {', '.join(SERVICE_CHOICES)}")
    return chosen


# --------------------------------------------------------------------------- #


def _load_test_support():
    """Import the offline scenario from the source checkout's ``tests`` package.

    ``--demo`` and ``--self-test`` both need the synthetic fixtures. They live
    outside the installable package, so we look for them next to ``src/``. In an
    installed wheel they are absent and the caller is told to use a checkout.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    try:
        from tests import build_fixtures
        from tests.fake_aws import FakePool, FixtureCollector
    except ImportError:
        print("--demo and --self-test need the source checkout (tests/ not found).", file=sys.stderr)
        print(f"expected it at: {os.path.join(repo_root, 'tests')}", file=sys.stderr)
        return None
    return build_fixtures, FakePool, FixtureCollector


def run_demo(out_dir: str, logger: Logger, args) -> int:
    support = _load_test_support()
    if support is None:
        return 2
    build_fixtures, FakePool, FixtureCollector = support

    fixtures = build_fixtures()
    logger("demo mode: using the bundled synthetic scenario (no AWS API calls)")
    # Honour --cache-dir so a demo run can seed a cache that a later --offline
    # run rebuilds from. Hardcoding None silently ignored the flag.
    collector = FixtureCollector(
        fixtures,
        cache_dir="" if args.no_cache else (args.cache_dir or os.path.join(out_dir, ".cache")),
        services=CORE_SERVICES,
        log=logger,
        pool_factory=lambda region: FakePool(region),
    )
    collector.start()
    snapshots = [collector.collect_region(region) for region in fixtures]
    return finish(snapshots, out_dir, logger, args)


def run_live(args, out_dir: str, logger: Logger) -> int:
    regions: List[str] = []
    if args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    cache_dir = args.cache_dir or os.path.join(out_dir, ".cache")
    if args.no_cache:
        cache_dir = ""
    collector = Collector(
        regions=regions,
        cache_dir=cache_dir or None,
        offline=args.offline,
        services=parse_services(args.services),
        max_workers=args.max_workers,
        log=logger,
    )
    try:
        collector.start()
    except CollectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.all_regions:
        regions = collector.resolve_regions(regions)
    else:
        regions = collector.resolve_regions(regions) or regions
    if not regions:
        print("error: no regions to scan (use --regions or --all-regions)", file=sys.stderr)
        return 2
    logger(f"scanning {len(regions)} region(s): {', '.join(regions)}")
    snapshots: List[AccountSnapshot] = []
    for region in regions:
        started = time.time()
        snap = collector.collect_region(region)
        snapshots.append(snap)
        logger(
            f"{region}: {len(snap.vpcs)} VPCs, {len(snap.subnets)} subnets, "
            f"{len(snap.route_tables)} route tables, {len(snap.workloads)} workloads "
            f"({time.time() - started:.1f}s)"
        )
    return finish(snapshots, out_dir, logger, args)


def finish(snapshots: Sequence[AccountSnapshot], out_dir: str, logger: Logger, args) -> int:
    topo = Topology(snapshots)
    summary = topo.summary()
    logger("inventory: " + ", ".join(f"{k}={v}" for k, v in summary.items()))
    if topo.error_count:
        logger(f"warning: {topo.error_count} collection error(s) - see the run log")

    # Findings are cheap and they annotate the diagrams, so they always run.
    findings: List[Finding] = []
    if not args.no_rules:
        findings = run_rules(topo)
        logger(f"findings: {len(findings)} across {len({f.rule_id for f in findings})} rules")

    # The pairwise connectivity analysis is the expensive part and is only needed
    # for the CSV/Markdown evidence, so it only runs with --reports.
    cross_rows: list = []
    lb_rows: list = []
    exposure: list = []
    cidr_rows: list = []
    if args.reports:
        engine = PathEngine(topo)
        started = time.time()
        cross_rows = analysis.evaluate_cross_vpc(topo, engine, max_pairs=args.max_vpc_pairs)
        lb_rows = analysis.evaluate_lb_flows(topo, engine)
        exposure = analysis.internet_exposure(topo)
        cidr_rows = analysis.cidr_map(topo)
        logger(
            f"connectivity: {len(cross_rows)} cross-VPC evaluations, {len(lb_rows)} LB flows "
            f"({time.time() - started:.1f}s)"
        )

    meta = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "account_id": topo.account_id,
        "partition": topo.partition,
        "regions": topo.regions,
        "mode": "demo" if args.demo else ("offline" if args.offline else "live"),
    }

    diagram_index: List[str] = []
    flow_model = None
    if not args.no_diagrams:
        diagram_index, flow_model = write_diagrams(topo, findings, out_dir, args, logger)
        report.write_text(os.path.join(out_dir, "START-HERE.md"), report.start_here_markdown(topo, findings, diagram_index))
    if args.reports:
        write_reports(topo, findings, cross_rows, lb_rows, exposure, cidr_rows, meta, out_dir, logger)

    print_summary(
        topo, findings, cross_rows, lb_rows, exposure, out_dir, diagram_index, args,
        flow_model,
    )
    return 0


def write_diagrams(topo: Topology, findings, out_dir: str, args, logger: Logger):
    """Write exactly ONE topology diagram for the whole account.

    There is deliberately no per-VPC, per-AZ, per-subnet, "security" or
    "routing" companion diagram: containers carry location, arrows carry traffic
    paths, and security controls ride along as label metadata.

    Returns ``(written_names, flow_model)``. The diagram itself stays pure
    architecture -- no totals, no summary node -- so the numbers the model holds
    are reported on the console instead, here.
    """
    model = flow.build_flow_model(topo)
    content = mermaid.render_topology(
        topo,
        model,
        max_vpcs=args.max_diagram_vpcs,
        max_subnets=args.max_diagram_subnets,
    )
    name = "00-network-topology.mmd"
    report.write_text(os.path.join(out_dir, name), content)
    logger(
        f"diagram: {name} ({len(model.edges)} network paths, "
        f"{model.traced} allowed / {model.blocked} blocked / "
        f"{model.conditional} unknown workload paths)"
    )
    return [name], model


def write_reports(
    topo: Topology,
    findings,
    cross_rows,
    lb_rows,
    exposure,
    cidr_rows,
    meta: Dict[str, str],
    out_dir: str,
    logger: Logger,
) -> None:
    reports = report.ensure_dir(os.path.join(out_dir, "reports"))
    findings_dir = report.ensure_dir(os.path.join(out_dir, "findings"))

    report.write_csv(os.path.join(reports, "routes.csv"), report.route_rows(topo))
    report.write_csv(os.path.join(reports, "subnets.csv"), report.subnet_rows(topo))
    report.write_csv(os.path.join(reports, "resources.csv"), report.resource_rows(topo))
    report.write_csv(os.path.join(reports, "network-interfaces.csv"), report.eni_rows(topo))
    report.write_csv(os.path.join(reports, "security-groups.csv"), report.sg_rows(topo))
    report.write_csv(
        os.path.join(reports, "internet-exposure.csv"), report.exposure_rows(exposure)
    )
    report.write_csv(
        os.path.join(reports, "cross-vpc-connectivity.csv"), report.cross_vpc_rows(cross_rows)
    )
    report.write_csv(
        os.path.join(reports, "load-balancer-flows.csv"), report.lb_flow_rows(lb_rows)
    )
    report.write_csv(os.path.join(reports, "cidr-map.csv"), report.cidr_rows(cidr_rows))
    report.write_csv(
        os.path.join(findings_dir, "findings.csv"), [f.as_row() for f in findings]
    )
    report.write_text(
        os.path.join(findings_dir, "findings.md"), report.findings_markdown(findings, topo)
    )
    report.write_inventory_json(os.path.join(out_dir, "inventory.json"), topo, meta)
    report.write_text(
        os.path.join(out_dir, "report.md"),
        report.main_markdown(topo, findings, meta, cross_rows, lb_rows, []),
    )
    logger(f"reports: CSV/JSON/Markdown written under {out_dir}")


def print_summary(
    topo: Topology,
    findings,
    cross_rows,
    lb_rows,
    exposure,
    out_dir: str,
    diagram_index,
    args,
    flow_model=None,
) -> None:
    summary = topo.summary()
    print()
    print("=" * 72)
    print(f"Account {topo.account_id or 'unknown'}  regions: {', '.join(topo.regions) or '-'}")
    print(
        "  "
        + "  ".join(
            f"{k}={v}"
            for k, v in summary.items()
            if k not in ("regions", "collection_errors") and v
        )
    )
    # The diagram is pure architecture, so the connectivity totals that describe
    # it are printed here rather than drawn inside it.
    if flow_model is not None:
        routing = flow_model.routing
        pub = sum(1 for r in routing.values() if r.classification == flow.PUBLIC)
        priv = sum(1 for r in routing.values() if r.classification == flow.PRIVATE)
        iso = len(routing) - pub - priv
        print(
            f"  topology: {len(topo.vpcs)} VPC(s), {len(routing)} subnet(s) "
            f"({pub} public / {priv} private / {iso} isolated)"
        )
        print(
            f"  paths drawn: {len(flow_model.edges)} network path(s); workload paths "
            f"{flow_model.traced} allowed / {flow_model.blocked} blocked / "
            f"{flow_model.conditional} unknown"
        )

    blocked = [r for r in cross_rows if r.forward != "reachable"]
    if cross_rows:
        print(f"  cross-VPC links evaluated: {len(cross_rows)}  not fully reachable: {len(blocked)}")
        for row in blocked[:10]:
            print(
                f"    ! {row.src_vpc} -> {row.dst_vpc} via {row.link_kind}: {row.forward} "
                f"(return {row.reverse})  {row.reasons[:110]}"
            )
    if lb_rows:
        bad = [r for r in lb_rows if r.verdict != "reachable"]
        print(f"  load balancer flows evaluated: {len(lb_rows)}  not reachable: {len(bad)}")
        for row in bad[:10]:
            print(f"    ! {row.lb} -> {row.target} ({row.target_ip}): {row.verdict}  {row.reasons[:100]}")
    if exposure:
        print(f"  internet-exposed addresses: {len(exposure)}")
    if findings:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        top = sorted(findings, key=lambda f: (order.get(f.severity, 9), f.rule_id))[:5]
        print(f"  findings: {len(findings)}")
        for f in top:
            print(f"    [{f.severity:8}] {f.rule_id} {f.title} :: {f.resource}")
        if len(findings) > len(top):
            where = "findings/findings.md" if args.reports else "START-HERE.md"
            print(f"    ... {len(findings) - len(top)} more (see {where})")
    else:
        print("  findings: none")
    print("=" * 72)
    print(f"Output: {os.path.abspath(out_dir)}")
    if diagram_index:
        print(f"  start at: {os.path.join(out_dir, 'START-HERE.md')}")
        print(f"  topology: {os.path.join(out_dir, diagram_index[0])}")
        print("  (one diagram for the whole account: location + traffic paths)")
    if args.reports:
        print(f"  reports:  {os.path.join(out_dir, 'reports', 'routes.csv')} (+8 more)")
    else:
        print("  (add --reports for CSV/Markdown evidence)")
    print()
    print("View it: open https://mermaid.live and paste the .mmd text.")


def run_self_test(verbose: bool = True) -> int:
    """Run the offline check suite from the source checkout."""
    if _load_test_support() is None:
        return 2
    from tests.suite import run_self_test as _run

    return _run(verbose=verbose)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        return run_self_test(verbose=not args.quiet)

    out_dir = args.out
    report.ensure_dir(out_dir)
    logger = Logger(quiet=args.quiet, logfile=os.path.join(out_dir, "logs", "run.log"))
    try:
        if args.demo:
            return run_demo(out_dir, logger, args)
        return run_live(args, out_dir, logger)
    except KeyboardInterrupt:
        logger("interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001
        logger(f"fatal: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        return 1
    finally:
        logger.close()
