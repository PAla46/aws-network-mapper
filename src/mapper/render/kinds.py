"""How each kind of workload is presented in the diagram.

One row per ``Workload.kind`` holds everything the renderer needs to know about
that kind: the label it is drawn under, the node shape, the kind-specific detail
lines, and whether it shows its primary private IP.

This used to be three separate ``if``/``elif`` chains inside ``mermaid.py``
(the title, the shape, and the detail lines). Adding a service then meant
finding all three, and a kind missing from one of them failed silently -- an
ECS cluster had a title but no shape and no detail lines, and looked correct by
accident. Here a kind either has a row or falls to ``DEFAULT_KIND``, and the
self-test asserts every collected kind is covered.

Adding a service is now one row here plus one collector in ``discovery/``.
Connectivity is untouched by anything in this module: it is presentation only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List

from ..model import Workload

DetailFn = Callable[[Workload], List[str]]


def _no_detail(wl: Workload) -> List[str]:
    """No kind-specific lines. The generic IP / SG / id lines still apply."""
    return []


@dataclass(frozen=True)
class KindStyle:
    """Presentation rules for one ``Workload.kind``.

    label       drawn before the workload name. Empty means "use the kind,
                upper-cased", which is how an unlisted kind still reads
                sensibly rather than as an empty title.
    shape       Mermaid node shape: ``box``, ``hex`` or ``stadium``.
    detail      kind-specific lines, emitted between the title and the
                security group summary.
    shows_ip    whether the primary private IP is appended. Load balancers do
                not: their node leads with listeners, which is where traffic
                actually enters.
    """

    label: str
    shape: str
    detail: DetailFn = _no_detail
    shows_ip: bool = True

    def title(self, wl: Workload) -> str:
        return self.label or (wl.kind or "").upper()


# --- detail builders -------------------------------------------------------


def _listener_summary(wl: Workload) -> List[str]:
    """``443 HTTPS · 80 HTTP`` -- compact, and where traffic enters."""
    seen: List[str] = []
    for ln in wl.extra.get("listeners") or []:
        proto = str(ln.get("protocol") or "")
        port = ln.get("port")
        text = f"{port} {proto}".strip() if port else proto
        if text and text not in seen:
            seen.append(text)
    return [" · ".join(seen[:4])] if seen else []


def _lb_detail(wl: Workload) -> List[str]:
    """ALB / NLB / GWLB: scheme, listeners, and how many subnets they span."""
    lines: List[str] = []
    scheme = wl.extra.get("scheme") or ""
    if scheme:
        lines.append("internet-facing" if scheme == "internet-facing" else "internal")
    lines.extend(_listener_summary(wl))
    if len(wl.subnet_ids) > 1:
        lines.append(f"in {len(wl.subnet_ids)} subnets")
    return lines


def _rds_detail(wl: Workload) -> List[str]:
    port = wl.extra.get("port") or ""
    engine = (wl.engine or "").strip()
    # Mirrors the original inline expression exactly, including appending an
    # empty engine when the collector recorded neither field.
    return [f"{engine} :{port}".strip().rstrip(":").strip() if port else engine]


def _ecs_service_detail(wl: Workload) -> List[str]:
    running = wl.extra.get("running_tasks")
    desired = wl.extra.get("desired_tasks")
    if running is None:
        # The collector could not see the task list. Saying so is better than
        # drawing a node that looks like a healthy service with no tasks.
        return ["running tasks: unknown"]
    if running:
        return [f"{running}/{desired} tasks running"]
    # A service scaled to zero is a valid state, and must not be drawn with an
    # invented runtime endpoint.
    return [f"running tasks: 0 (desired {desired})"]


def _eks_detail(wl: Workload) -> List[str]:
    return [f"v{wl.engine or '?'} control plane"]


def _lambda_detail(wl: Workload) -> List[str]:
    return [wl.engine or "function"]


# --- the registry ----------------------------------------------------------

KIND_STYLES: Dict[str, KindStyle] = {
    # Load balancers. "lb" is not produced by any collector today but is kept
    # as an alias so any future generic-LB path renders identically.
    "alb": KindStyle("ALB", "stadium", _lb_detail, shows_ip=False),
    "nlb": KindStyle("NLB", "stadium", _lb_detail, shows_ip=False),
    "gwlb": KindStyle("GWLB", "stadium", _lb_detail, shows_ip=False),
    "lb": KindStyle("LB", "stadium", _lb_detail, shows_ip=False),
    "rds": KindStyle("RDS", "hex", _rds_detail),
    "ec2": KindStyle("EC2", "box"),
    # An ECS cluster has no detail of its own: it is a grouping, and the
    # services under it carry the task counts.
    "ecs-cluster": KindStyle("ECS CLUSTER", "box"),
    "ecs-service": KindStyle("ECS SERVICE", "box", _ecs_service_detail),
    "eks": KindStyle("EKS", "box", _eks_detail),
    "lambda": KindStyle("LAMBDA", "box", _lambda_detail),
}

# Anything not listed still renders as a readable node rather than falling off
# the end of a chain. The self-test asserts the collector never produces a kind
# that lands here, so this is a safety net rather than a normal path.
DEFAULT_KIND = KindStyle("", "box")


def style_for(kind: str) -> KindStyle:
    return KIND_STYLES.get(kind, DEFAULT_KIND)


def unstyled_kinds(kinds) -> List[str]:
    """Collected kinds with no registry row. Should always be empty."""
    return sorted({k for k in kinds if k and k not in KIND_STYLES})