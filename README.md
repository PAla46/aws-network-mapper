# aws-network-mapper

Read-only AWS network mapper. It collects VPCs, subnets, route tables, gateways
and the resources attached to them, then answers one question in a single picture:

> For this path — source, entry point, VPC, subnet, route, next hop, destination —
> what does the configuration actually permit, and what does security allow?

It only calls `Describe*` and `List*` APIs. It never creates, modifies or
deletes anything.

```bash
python3 aws_network_mapper.py --all-regions --out ./network-map
```

Then paste `./network-map/00-network-topology.mmd` into
<https://mermaid.live>.

No AWS account handy?

```bash
python3 aws_network_mapper.py --self-test     # 215 offline checks, no AWS calls
python3 aws_network_mapper.py --demo --out ./demo
```

---

## Contents

- [What it produces](#what-it-produces)
- [The diagram](#the-diagram)
  - [Containers are location, arrows are traffic](#containers-are-location-arrows-are-traffic)
  - [Arrow labels](#arrow-labels)
  - [One arrow per journey](#one-arrow-per-journey)
  - [Security status](#security-status)
  - [What is deliberately not a node](#what-is-deliberately-not-a-node)
  - [Large accounts](#large-accounts)
- [How a path is derived](#how-a-path-is-derived)
  - [Subnet classification comes from routing](#subnet-classification-comes-from-routing)
  - [Longest-prefix match](#longest-prefix-match)
  - [Gateway next hops](#gateway-next-hops)
  - [Workload targets](#workload-targets)
  - [No invented connectivity](#no-invented-connectivity)
  - [Configured is not observed](#configured-is-not-observed)
- [A worked example](#a-worked-example)
- [CLI reference](#cli-reference)
- [Permissions](#permissions)
- [Rules](#rules)
- [Reports](#reports)
- [Design notes](#design-notes)
- [Limitations](#limitations)

---

## What it produces

Default output is **one diagram** and a short index. Nothing else:

```
<out>/
  00-network-topology.mmd   THE diagram: the whole account, one picture
  START-HERE.md             how to read it, plus every finding in a table
  logs/run.log              collection log, including any denied API call
  .cache/                   raw API responses, for offline rebuilds
```

There is deliberately no second diagram. No separate network / security view, no
separate routing / resource view, no simplified-and-detailed pair, and nothing
per VPC, per AZ or per subnet. Location and traffic paths share one picture
because splitting them is what made the previous output read like an inventory.

Add `--reports` for the CSV and Markdown evidence set:

```
  report.md                        narrative summary
  inventory.json                   full normalized snapshot
  findings/findings.md             findings grouped by severity
  findings/findings.csv            same findings, one row each
  reports/routes.csv               every route, normalised
  reports/subnets.csv              reports/resources.csv
  reports/security-groups.csv      reports/network-interfaces.csv
  reports/cross-vpc-connectivity.csv
  reports/load-balancer-flows.csv  reports/internet-exposure.csv
  reports/cidr-map.csv
```

---

## The diagram

`00-network-topology.mmd` is the point of the tool.

It is **pure architecture**: containers, nodes and arrows. No totals, no summary
box, no report text — a picture that argues with its own statistics is worse than
no picture. The counts are printed to the console instead:

```
  topology: 6 VPC(s), 14 subnet(s) (6 public / 3 private / 5 isolated)
  paths drawn: 44 network path(s); workload paths 5 allowed / 0 blocked / 0 unknown
```

The `.mmd` file does carry `%%` comment lines explaining how to read it. Those
are Mermaid comments: they render as nothing at all, and they are what makes a
pasted diagram self-explanatory.

### Containers are location, arrows are traffic

Two visual languages, never mixed.

**Containers are where things live.** They nest:

```
AWS Account > VPC > Availability Zone > Subnet > resources
```

Each subnet header carries its id, CIDR, AZ, associated route table, NACL, and
routing-derived classification:

```
subnet-pub-1  ·  10.0.1.0/24  ·  AZ eu-west-1a
Route table: public-tier (rtb-prod-public)
NACL: acl-prod-default  ·  2 in / 0 out
Type: PUBLIC — 0.0.0.0/0 → Internet Gateway
```

**Arrows are traffic paths.** Every arrow exists because real configuration
supports it, and carries the label that justifies it.

### Arrow labels

A label names the **route**, never the node it points at. The arrowhead already
says where the arrow goes, so repeating the destination is noise:

```
0.0.0.0/0
10.30.0.0/16
172.16.0.0/16
10.0.0.0/16 local
TCP :5432
HTTPS:443 / TG: app-tg / 10.0.0.0/16 local / security: allowed
```

`local` is the one word that names a mechanism rather than a node, and it is
correct: intra-VPC routing is not a gateway.

A load balancer arrow uses the **listener** port and protocol — the port a client
actually connects to — and names the target group as metadata, because traffic is
delivered to the targets, not to the group:

```
ALB my-alb  ──HTTPS:443 / TG: app-tg──▶  EC2 app-01
```

### One arrow per journey

Each path is drawn **once, in the direction traffic travels**:

```
inbound    INTERNET → IGW → public subnet → ALB
outbound   private subnet → NAT → IGW → INTERNET
peering    subnet → VPC peering → subnet
transit    subnet → TGW → subnet
```

A reverse arrow appears only when routing genuinely supports it. Nothing is
mirrored for the sake of a tidy picture.

### Security status

Every path edge states its security verdict, so "the route exists" is never
mistaken for "the traffic gets through":

```
security: allowed
security: blocked
security: unknown
```

- `blocked` — a security group rule was evaluated and refuses the flow. The route
  is still a route; the block is never drawn as a fake hop, and the arrow stays.
- `unknown` — the rules could not be fully evaluated: a missing permission, or an
  ENI whose security groups were not collected. This is deliberately **not** the
  same as `allowed`, and is never folded into `blocked`.
- `allowed` — every relevant egress and ingress rule was evaluated and permits it.

An unevaluated rule must never be indistinguishable from a permitted one, which
is why the field is always present rather than only shown when it is negative.

### What is deliberately not a node

Traffic does not travel through a NACL or a security group, so neither is a node:

| Concept | Role | Where it appears |
| --- | --- | --- |
| Subnet | where the resource lives | container, with id / CIDR / AZ / route table / NACL |
| Route table | where traffic goes next | subnet header, and the label on each arrow |
| IGW / NAT / TGW / peering / VPCE | how networks connect | nodes on the traffic path |
| VPN gateway | how a VPC reaches on-premises | node, joined to ON-PREMISES |
| NACL | subnet-boundary filtering | `NACL: acl-...  ·  2 in / 0 out` in the subnet header |
| Security group | ENI-level filtering | `SG: sg-...` in the resource node, plus the edge verdict |
| Target group | names a set of targets | metadata on the arrow that uses it |
| Network interface | belongs to a resource | folded into the resource that owns it |
| Resource | where traffic terminates | node inside its subnet |

Two consequences worth stating:

- **ENIs are folded into their owner.** A Lambda with a VPC attachment does not
  appear twice, once as `LAMBDA` and once as `NETWORK INTERFACE`.
- **`local` is never a "Local Gateway" box.** The arrow runs straight from source
  resource to destination resource, crossing the subnet containers that contain
  them, labelled `10.0.0.0/16 local`.

A multi-subnet resource is drawn **once** and states its placement
(`in 2 subnets`), because duplicating the node would imply several load
balancers. Subnets are grouped into their own AZ container, so multi-AZ
deployments stay visible.

### Large accounts

`--max-diagram-vpcs` (default 60) and `--max-diagram-subnets` (default 200 per
VPC) bound the drawing.

When the budget bites, **subnet and workload nodes are shed first**. A dropped
subnet or workload is replaced by an `OMITTED` placeholder that names the reason,
so an arrow never silently loses its destination and the file still parses.

Network components are never shed: a NAT gateway, IGW, TGW, peering, VPN gateway
or VPC endpoint that an arrow points at is always drawn, even when its own subnet
could not be. Hiding one would turn "this path exists" into "I could not draw
this path", which is a different claim. A NAT whose subnet is missing from the
inventory still appears, annotated with the subnet it expects.

Resources that attach to nothing have no place in a topology, so they are
recorded as `%%` comments at the end of the file rather than silently dropped.

---

## How a path is derived

Discovery is unchanged and independent of the renderer: it collects, normalizes
into `model/`, indexes in `graph/Topology`, and evaluates reachability in
`graph/routing.py`. The diagram is built *from* those verdicts, never by
re-deriving routing, so the picture and the `--reports` CSVs cannot disagree.

### Subnet classification comes from routing

Not from the subnet name. The tool reads the subnet's effective route table:

| Classification | Derived from |
| --- | --- |
| `PUBLIC` | `0.0.0.0/0` targets an Internet Gateway |
| `PRIVATE` | `0.0.0.0/0` targets a NAT Gateway, or leaves via TGW / VGW |
| `ISOLATED` | no `0.0.0.0/0` route at all |

Each header states the route that proves its classification, e.g.
`Type: ISOLATED — no 0.0.0.0/0 route in its route table`.

### Longest-prefix match

Route selection follows AWS behaviour: the most specific applicable route wins, via
`util/cidr.py:longest_prefix_match()`. `graph/routing.py:PathEngine.resolve()`
walks the route table, resolves the next hop, records the hops, then evaluates
security groups for the port.

`graph/connectivity.py` reuses that engine rather than re-deriving routing, so the
diagram and the cross-VPC CSV are the same computation.

### Gateway next hops

| Next hop | Requires |
| --- | --- |
| Internet Gateway | an attached IGW on a subnet with a `0.0.0.0/0` route to it |
| NAT Gateway | a NAT in the account, resolvable to its own subnet and IGW |
| Transit Gateway | a TGW route table entry that really delivers into an attached VPC, then resolved further through *that* VPC's own route table |
| VPC peering | a route table that actually points at the peering, and an active connection |
| VPN gateway | reached via its VPC; grows an internet leg only when a VPN connection advertises `0.0.0.0/0` |
| VPC endpoint | an endpoint with ENIs in the subnets that route to it |

Gateways are not given reachability they do not have. A transit gateway grows a
Direct Connect or IPsec leg only when it has a `dx-gateway` or `vpn` attachment,
and an internet leg only when a TGW route table really sends `0.0.0.0/0` to one of
those. A TGW with nothing but VPC attachments has neither.

### Workload targets

Every workload arrow originates from a real target group registration. The
registration is authoritative: a target is drawn because it is registered, not
because it shares a VPC, subnet, route table or security group.

The collector resolves the target types that actually appear in ELBv2:

| Target type | Resolved to |
| --- | --- |
| `instance` | the instance's ENI, so the correct source subnet and SGs are used |
| `ip` / `instance-ip` | the interface holding that address |
| `ecs` | the service, via its task ENIs |
| `lambda` | the function's VPC ENI, so the path is routable; a function with no ENI in the inventory draws no arrow and says so |

An empty target group produces **no arrow** rather than a hopeful one. When a
target cannot be resolved, the load balancer node carries a note naming the
target and the reason.

Registration, not health, is what draws the arrow. A registered target that is
currently `unhealthy` still gets an arrow, because the diagram reports configured
reachability — see [Configured is not observed](#configured-is-not-observed).
Health state is collected from `DescribeTargetHealth` and carried on the target
record, but it does not gate the arrow.

Other workload kinds attach to the topology through their own configuration:

- **RDS** — via its DB subnet group, then the instance ENI. The ENI is what makes
  the `EC2 → RDS` arrow traceable, and it is matched from
  `Attachment.AttachmentId`, the field EC2 actually populates.
- **ECS** — clusters *and* services are separate nodes, keyed by ARN. Services
  show their running-task count, resolved through `ListTasks` / `DescribeTasks`.
  Only `RUNNING` tasks contribute task IPs, so a service with nothing running does
  not gain an invented endpoint.
- **EKS** — via `resourcesVpcConfig`; the node shows the Kubernetes version.
- **Lambda** — via its VPC subnets and security groups. Its ENI is attributed to
  the function (matching on subnet plus security group, and only when that match
  is unambiguous) so it folds into the `LAMBDA` node instead of appearing a second
  time as a bare interface. Functions are keyed by ARN, like every other workload.

### No invented connectivity

An arrow is drawn only when configuration supports it:

- a route in a real route table, resolved by longest-prefix match
- a registered load balancer target, at its real listener port
- a TGW route table entry that actually delivers into an attached VPC
- a VPC peering that some route table actually points at

### Configured is not observed

Arrows show **configured reachability**, not observed traffic. The tool says
"network path" and "route exists", never "application talks to". Distinguishing
configured from used needs telemetry that configuration does not contain: VPC
Flow Logs, Transit Gateway Flow Logs, or a Network Firewall. `NET018` flags VPCs
without flow logs for exactly that reason.

---

## A worked example

Inbound, as drawn for the bundled demo:

```
INTERNET
  │  inbound to vpc-prod
  ▼
Internet Gateway ──(inbound to 10.0.1.0/24)──▶
  ▼
PUBLIC SUBNET 10.0.1.0/24            ← the ALB lives here
  │  terminates here :443   security: allowed
  ▼
ALB my-alb
  │  HTTPS:443 / TG: app-tg / 10.0.0.0/16 local / security: allowed
  ▼
PRIVATE SUBNET 10.0.10.0/24          ← the app server lives here
```

And the egress story for that same private subnet, independently:

```
EC2
  ▼
PRIVATE SUBNET 10.0.10.0/24
  │  0.0.0.0/0
  ▼
NAT Gateway (public, in subnet-pub-1 · 10.0.1.0/24 · eu-west-1a)
  │  via public subnet
  ▼
Internet Gateway
  │  egress
  ▼
INTERNET
```

And the database path, resolved through the RDS instance's own ENI:

```
EC2 app-01
  │  TCP :5432   10.0.0.0/16 local   security: allowed
  ▼
RDS prod-postgres  (postgres :5432, 10.0.20.30, SG: sg-db)
```

Run `--demo` to see all of it, plus the findings engine reacting to deliberate
misconfigurations: an unattached IGW in a route table, a NAT that cannot reach the
internet, a security group open to everywhere, an orphaned NACL.

---

## CLI reference

```
--regions LIST          comma separated region list
--all-regions           scan every region enabled for the account
--out DIR               output directory (default: aws-network-map)
--cache-dir DIR         raw response cache (default: <out>/.cache)
--no-cache              neither read nor write the cache
--offline               rebuild all output from the cache, no AWS calls at all
--services LIST         comma separated subset of:
                        ec2-workloads, elbv2, rds, ecs, eks, lambda, core-only
--max-workers N         parallel API calls per region (default: 8)
--reports               also write the CSV/JSON/Markdown evidence files
--no-diagrams           skip the Mermaid diagram
--no-rules              skip the findings that annotate it
--deep                  evaluate more cross-VPC pairs for the reports
--max-vpc-pairs N       cap on cross-VPC evaluations (default: 500)
--max-diagram-vpcs N    VPCs drawn in the diagram (default: 60)
--max-diagram-subnets N subnets drawn per VPC (default: 200)
-q, --quiet             less console output
--demo                  run the bundled synthetic scenario
--self-test             run the offline checks and exit
```

`core-only` skips the six optional service integrations, which is faster and
needs fewer permissions:

```bash
python3 aws_network_mapper.py --all-regions --services core-only --out ./map
```

Re-render after tweaking rules without re-collecting anything:

```bash
python3 aws_network_mapper.py --offline --cache-dir ./map/.cache --out ./map-2
```

Rendering is deterministic: the same inventory produces a byte-identical
`.mmd`, which is asserted by the self-test.

---

## Permissions

Read-only EC2, plus the service APIs you enable. `--services core-only` needs:

```
ec2:DescribeVpcs                    ec2:DescribeSubnets
ec2:DescribeRouteTables             ec2:DescribeInternetGateways
ec2:DescribeNatGateways             ec2:DescribeTransitGateways
ec2:DescribeTransitGatewayAttachments
ec2:DescribeTransitGatewayRouteTables
ec2:DescribeVpcPeeringConnections   ec2:DescribeVpcEndpoints
ec2:DescribeNetworkInterfaces       ec2:DescribeSecurityGroups
ec2:DescribeNetworkAcls             ec2:DescribeVpnGateways
ec2:DescribeVpnConnections          ec2:DescribeInstances
ec2:DescribeRegions
```

The default service set additionally uses:

```
elasticloadbalancing:DescribeLoadBalancers    elasticloadbalancing:DescribeTargetGroups
elasticloadbalancing:DescribeTargetHealth     elasticloadbalancing:DescribeListeners
rds:DescribeDBInstances                       rds:DescribeDBSubnetGroups
ecs:ListClusters       ecs:DescribeClusters   ecs:ListServices
ecs:DescribeServices   ecs:ListTasks          ecs:DescribeTasks
eks:ListClusters       eks:DescribeCluster
lambda:ListFunctions
```

Any missing permission is recorded in `logs/run.log` and in the
`collection_errors` metric; the affected part of the output degrades instead of
failing the run. A partially readable security group yields `security: unknown`
on the paths it touches, never a false `allowed`.

---

## Rules

| Rule | Severity | Title |
| --- | --- | --- |
| `NET001` | high | Subnet is directly internet-routable |
| `NET002` | medium | Dual default routes (IGW and NAT) in the same route table |
| `NET003` | high | NAT gateway cannot reach the internet |
| `NET004` | medium | NAT gateway subnet default route points at another NAT gateway |
| `NET005` | high | Route table points at an internet gateway that is not attached |
| `NET006` | low | Internet gateway attached to no VPC |
| `NET007` | info | Route table is not associated with any subnet |
| `NET008` | high | Overlapping CIDR blocks between connected VPCs |
| `NET009` | high | One-way transit gateway routing |
| `NET010` | medium | Transit gateway route table has a catch-all route |
| `NET011` | high | One-way VPC peering routing |
| `NET012` | medium | VPC peering connection is not active |
| `NET013` | medium | Transit gateway attachment CIDR does not cover the whole VPC |
| `NET014` | medium | Public IP assigned in a subnet without an internet route |
| `NET015` | high | Security group exposes a sensitive management port to the internet |
| `NET016` | critical | Security group allows all traffic from everywhere |
| `NET017` | info | Security group is not attached to any network interface |
| `NET018` | medium | VPC has no flow logs |
| `NET019` | high | Database instance is publicly accessible |
| `NET020` | medium | Network ACL allows a sensitive port from any source |
| `NET021` | low | VPC endpoint policy allows every resource and principal |
| `NET022` | low | Transit gateway attachment has no association with a route table |
| `NET023` | info | Subnet has no route to the internet and no gateway route |
| `NET024` | medium | Subnets still use the main route table |
| `NET025` | low | Internet-facing load balancer |
| `NET026` | medium | Overlapping CIDR blocks between subnets in the same VPC |
| `NET027` | high | VPC route table points at a transit gateway with no attachment |

Findings carry the resource, region, VPC, the evidence string that triggered
them, and a recommendation. They annotate the diagram's nodes and are also
written to `START-HERE.md` as a table.

---

## Reports

`--reports` adds the evidence set. Every verdict in
`cross-vpc-connectivity.csv` and `load-balancer-flows.csv` is derived from
routing tables, gateway attachments and security groups — it answers "is this
path configured correctly?", not "is traffic using it?".

Each row carries a verdict, the reason, and the **return-path verdict
separately**, because one-way routing is the most common finding in real
accounts.

---

## Design notes

The layers are deliberately separate, and the diagram is a *view* of the model,
not a second implementation of it.

```
aws_network_mapper.py    entry point
src/aws_network_mapper/
  cli.py                argument parsing and orchestration
  model/                normalized resource model and API response parsing
  discovery/            concurrent, cached, permission-tolerant collection
  graph/                indexes and path evaluation; no AWS calls
    __init__.py         Topology: indexes, subnet -> effective route table
    routing.py          route, gateway, peering and security group evaluation
    connectivity.py     the node/edge model the diagram is drawn from
    cross_vpc.py        cross-VPC, load balancer, exposure, CIDR analyses
  rules/                the rules above, with their IDs and severities
  render/               artefact writers
    mermaid.py          the single topology renderer
    reports.py          CSV, JSON and Markdown writers
  util/
    cidr.py             CIDR and IP helpers, longest-prefix match

tests/                  offline checks; not part of the installed package
  suite.py              the 215 checks
  scenario.py           synthetic two-region demo scenario
  fake_aws.py           boto3 stand-in used by --demo and the suite
```

Conventions the code holds to:

- **Identity is the ARN when one exists.** Workloads are keyed by ARN, not by
  name, so two clusters or services that share a name cannot overwrite each other
  in the workloads map. The self-test asserts ids are unique.
- **Nodes are rendered, never inferred.** `graph/connectivity.py` decides the
  topology; `render/mermaid.py` decides only how it looks. A rendering concern
  never requires touching path evaluation.
- **Deterministic output.** Subgraph ids come from a counter, not `hash()`,
  because Python randomizes string hashes per process. The same inventory yields
  a byte-identical file.
- **Every arrow has a referent.** If an arrow points at a node the renderer did
  not emit, that node is drawn — Mermaid drops arrows to undeclared nodes and
  reports a parse error.
- **Degenerate inventory must not crash.** Missing subnets, absent ENIs, empty
  target groups, a NAT whose subnet was never collected: each is handled and
  asserted, because those are the shapes that appear in real accounts.

Python 3.9+, standard library plus `boto3`.

### Where to add things

Each layer has one job, so a change belongs in exactly one place:

| To add... | Put it in | Then |
| --- | --- | --- |
| A new AWS resource type | `model/` (the dataclass) + `discovery/` (the describe call) | Nothing else — `Topology` picks it up |
| A new finding | a `@rule`-decorated function in `rules/` | It registers itself; the registry and the report pick it up |
| A new way to resolve a path | `graph/routing.py` | `connectivity.py` and the diagram follow automatically |
| A new diagram element or layout tweak | `render/mermaid.py` | No path evaluation changes |
| A new CSV or report file | `render/reports.py` | Add the filename to the `report_files` list |
| A new CLI flag | `cli.py` (`build_parser` + the run path) | Document it in the CLI section above |
| A new check | `tests/suite.py` | No wiring; `run_self_test` discovers it |

The dependency direction is one-way: `discovery → model`, then
`graph → model`, then `rules`/`render → graph`. `graph` and below never import
`discovery`, which is what makes `--offline` and the test suite possible.

### Running the checks

```bash
python3 run_tests.py                    # the 215 offline checks
python3 aws_network_mapper.py --demo --reports --out ./demo   # no AWS access
python3 aws_network_mapper.py --all-regions --out ./map       # live, read-only
```

Optionally install it for the `aws-network-mapper` console script:

```bash
pip install -e .
aws-network-mapper --demo --out ./demo
```

---

## Limitations

Worth knowing before you rely on a result:

- **Configured, never observed.** There is no flow data. See
  [Configured is not observed](#configured-is-not-observed).
- **One arrow per target, not per listener.** A multi-listener load balancer puts
  its primary listener on the arrow and lists the remaining listeners on the
  node, rather than drawing a duplicate arrow for each one.
- **ECS tasks are `RUNNING` only.** `PENDING` and `PROVISIONING` tasks have no
  network interface to route through yet.
- **Security group evaluation needs both ends.** If either side's groups are
  unreadable the verdict is `unknown`, by design.
- **Peering and TGW evaluation is bounded.** `--max-vpc-pairs` (default 500)
  caps cross-VPC analysis for the reports; the diagram itself is not capped by it.
- **The diagram is a text file.** Layout is Mermaid's problem, not the tool's.
  Large accounts will need patience or a narrower region list.
