"""Command line interface for the AWS network mapper."""

from __future__ import annotations

import argparse
import datetime
import os
import sys
import time
import traceback
from typing import Dict, List, Optional, Sequence

from . import analysis, mermaid, report
from .collect import Collector, CollectorError
from .findings import Finding, run_rules
from .model import AccountSnapshot
from .paths import PathEngine
from .topology import Topology

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
            "  aws-network-mapper.py --all-regions --deep\n"
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
        help="evaluate extra flows (per-subnet drill-down diagrams, extra cross-VPC pairs)",
    )
    parser.add_argument("--max-vpc-pairs", type=int, default=500, help="cap on cross-VPC evaluations")
    parser.add_argument("--max-diagram-subnets", type=int, default=40, help="subnets drawn per VPC")
    parser.add_argument("--max-diagram-vpcs", type=int, default=40, help="VPCs in the overview")
    parser.add_argument("--max-drilldown", type=int, default=40, help="per-subnet diagrams to write")
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


def run_demo(out_dir: str, logger: Logger, args) -> int:
    from .fixtures import build_fixtures
    from .testing import FakePool, FixtureCollector

    fixtures = build_fixtures()
    logger("demo mode: using the bundled synthetic scenario (no AWS API calls)")
    collector = FixtureCollector(
        fixtures,
        cache_dir=None,
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
    if not args.no_diagrams:
        diagram_index = write_diagrams(topo, findings, out_dir, args, logger)
        report.write_text(os.path.join(out_dir, "START-HERE.md"), report.start_here_markdown(topo, findings, diagram_index))
    if args.reports:
        write_reports(topo, findings, cross_rows, lb_rows, exposure, cidr_rows, meta, out_dir, logger)

    print_summary(topo, findings, cross_rows, lb_rows, exposure, out_dir, diagram_index, args)
    return 0


def write_diagrams(topo: Topology, findings, out_dir: str, args, logger: Logger) -> List[str]:
    written: List[str] = []
    vpc_dir = report.ensure_dir(os.path.join(out_dir, "vpcs"))
    subnet_dir = os.path.join(out_dir, "subnets")

    def save(name: str, content: str) -> None:
        path = os.path.join(out_dir, name)
        report.write_text(path, content)
        written.append(name)

    save("00-overview.mmd", mermaid.render_overview(topo, max_vpcs=args.max_diagram_vpcs))
    save("01-transit-gateways.mmd", mermaid.render_tgw(topo))
    save("02-internet-paths.mmd", mermaid.render_internet(topo))

    for vpc in sorted(topo.vpcs.values(), key=lambda v: (v.region, v.id)):
        fname = f"{vpc.region}-{mermaid.slug(vpc.label)}-{vpc.id}.mmd"
        report.write_text(
            os.path.join(vpc_dir, fname),
            mermaid.render_vpc(
                topo,
                vpc.id,
                max_subnets=args.max_diagram_subnets,
                max_workloads=args.max_diagram_subnets,
            ),
        )
        written.append(f"vpcs/{fname}")

    # Per-subnet drill-downs are only useful when chasing a specific path.
    interesting = set(topo.subnets) if args.deep else set()
    for subnet_id in sorted(interesting)[: args.max_drilldown]:
        if subnet_id not in topo.subnets:
            continue
        fname = f"{topo.subnets[subnet_id].region}-{mermaid.slug(topo.subnets[subnet_id].name)}-{subnet_id}.mmd"
        report.ensure_dir(subnet_dir)
        report.write_text(
            os.path.join(subnet_dir, fname),
            mermaid.render_subnet(topo, subnet_id),
        )
        written.append(f"subnets/{fname}")
    logger(f"diagrams: {len(written)} file(s) under {out_dir}")
    return written


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
        print(f"  overview: {os.path.join(out_dir, '00-overview.mmd')}")
        print(f"  diagrams: {len(diagram_index)} .mmd files total")
    if args.reports:
        print(f"  reports:  {os.path.join(out_dir, 'reports', 'routes.csv')} (+8 more)")
    else:
        print("  (add --reports for CSV/Markdown evidence)")
    print()
    print("View a diagram: open https://mermaid.live and paste the .mmd text, or")
    print("  npx -y @mermaid-js/mermaid-cli -i 00-overview.mmd -o overview.svg")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        from .selftest import run_self_test

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
