# aws-network-mapper

Read-only AWS network and route topology mapper. It collects VPCs, subnets, route
tables and the resources attached to them, then draws how it all connects: which
route tables exist, where the internet gateway goes, what hangs off the transit
gateway, and what can reach what.

Output is Mermaid diagrams by default. Pass `--reports` if you also want CSV and
Markdown evidence.

It only calls `Describe*` and `List*` APIs. It never creates, modifies or deletes
anything.

## What it produces

Default output is **one diagram**, plus an index:

```
<out>/
  START-HERE.md          how to read the diagram, plus every finding in a table
  00-network-topology.mmd  THE diagram: the whole account, one picture
  logs/run.log
```

There is deliberately no second diagram. No separate network / security view, no
separate routing / resource view, no simplified and detailed pair, and nothing
per VPC, per AZ or per subnet. Location and traffic paths share one picture
because splitting them is what made the old output read like an inventory.

Add `--reports` for the CSV/Markdown evidence set:

```
  report.md                  summary
  findings/findings.md       findings grouped by severity
  findings/findings.csv      same findings, one row each
  reports/routes.csv         every route, normalised
  reports/subnets.csv        reports/resources.csv        reports/security-groups.csv
  reports/network-interfaces.csv
  reports/cross-vpc-connectivity.csv     reports/load-balancer-flows.csv
  reports/internet-exposure.csv          reports/cidr-map.csv
  inventory.json             full normalized snapshot
  .cache/                    raw API responses, for offline rebuilds
```

The diagram is Mermaid text. Paste it into <https://mermaid.live>.

## The topology diagram

`00-network-topology.mmd` is the point of the tool. It answers, in one picture:
where things live, how traffic leaves them, which route is used, what the next
hop is, and where the traffic ends up.

### Two visual languages, never mixed

**Containers are location.** They nest:

```
AWS Account > VPC > Availability Zone > Subnet > resources
```

A subnet container tells you *where* a resource lives. Each subnet header also
carries its id, CIDR, AZ, associated route table, NACL, and classification.

**Arrows are traffic paths.** Every arrow is labelled with the route that
justifies it, so you can look at any line and know why it exists:

```
0.0.0.0/0 → Internet Gateway
0.0.0.0/0 → NAT Gateway
10.30.0.0/16 → Transit Gateway
172.16.0.0/16 → VPC Peering
TCP :8080
TCP :5432
via 10.0.0.0/16 local
```

### Reading a path

```
INTERNET
  |  0.0.0.0/0 → Internet Gateway
  v
Internet Gateway  --(inbound to 10.0.1.0/24)-->
  v
PUBLIC SUBNET 10.0.1.0/24          <- where the ALB lives
  |
  |  TCP :443
  v
ALB
  |  TCP :8080   via 10.0.0.0/16 local
  v
PRIVATE SUBNET 10.0.10.0/24        <- where the app server lives
  |
  |  TCP :5432   via 10.0.0.0/16 local
  v
ISOLATED SUBNET 10.0.20.0/24       <- where the database lives
  |
  v
RDS PostgreSQL
```

And independently, the egress story for the same private subnet:

```
EC2
  v
PRIVATE SUBNET
  |  0.0.0.0/0 → NAT Gateway
  v
NAT Gateway (public, eu-west-1a / 10.0.1.0/24)
  |  via public subnet
  v
Internet Gateway
  v
INTERNET
```

### What is deliberately *not* a node

The old diagram drew generic association arrows such as `Subnet --filtered by-->
NACL`. Traffic does not travel through a NACL or a security group, so those are
not nodes here:

| Concept | Role | Where it appears |
| --- | --- | --- |
| Subnet | where the resource lives | container, with id/CIDR/AZ/route table/NACL |
| Route table | where traffic goes next | on the subnet header, and as the label on each arrow |
| IGW / NAT / TGW / peering / VGW / VPN | how networks connect | nodes on the traffic path |
| NACL | subnet-level filtering | `NACL: acl-...  4 in / 2 out` in the subnet header |
| Security group | ENI-level filtering | `SG: sg-...` plus inbound rules in the resource node |
| Resource | where traffic terminates | node inside its subnet |

`local` is not drawn as a "Local Gateway" either. `10.0.0.0/16 → local` is
intra-VPC routing, so it appears in an *arrow label* and the arrow runs straight
from the source resource to the destination resource across the subnet
containers that contain them.

### Subnet classification comes from routing

Not from the subnet name. The tool reads the subnet's effective route table:

| Classification | Derived from |
| --- | --- |
| `PUBLIC` | `0.0.0.0/0` targets an Internet Gateway |
| `PRIVATE` | `0.0.0.0/0` targets a NAT Gateway (or leaves via TGW/VGW) |
| `ISOLATED` | no `0.0.0.0/0` route at all |

Each subnet header states the route that proves its classification, e.g.
`Type: ISOLATED — no 0.0.0.0/0 route in its route table`.

### Longest-prefix match

Route selection follows AWS behaviour: the most specific applicable route wins,
via `cidrutil.longest_prefix_match`. `nm/paths.py:PathEngine.resolve()` walks the
route table, resolves the next hop (IGW, NAT, TGW, peering, VGW, VPC endpoint),
and records the hops. `nm/flow.py` reuses that engine rather than re-deriving
routing, so the diagram and the `--reports` cross-VPC CSV cannot disagree.

### No invented connectivity

An arrow is only drawn when real configuration supports it:

- a route in a real route table, resolved by longest-prefix match
- a registered load balancer target, at its real target-group port
- a Transit Gateway route table entry that actually delivers into an attached
  VPC, resolved further through *that* VPC's own route table
- a VPC peering that some route table actually points at

Arrows show **configured reachability**, not observed traffic. The diagram says
"network path" and "route exists", never "application talks to". If a route
exists but a security group blocks the port, the arrow stays and gains an
`SG DENIES` annotation — the route is still a route, and the block is not turned
into a fake hop.

### Multi-AZ and multi-subnet resources

Subnets are grouped into their own AZ container, so multi-AZ deployments are
visible. A load balancer with ENIs in several subnets is drawn once and lists
its placement, because duplicating the node would imply several load balancers.

### Large accounts

`--max-diagram-vpcs` (default 60) and `--max-diagram-subnets` (default 200 per
VPC) bound the drawing. Security resources that attach to nothing have no place
in a topology, so they are recorded as `%%` comments at the end of the file
rather than being silently dropped.

## Running it in CloudShell

CloudShell already has `boto3` and the AWS CLI, and its credentials are
pre-configured, so no setup is needed:

```bash
unzip aws-network-mapper.zip
python3 aws_network_mapper.py --all-regions --deep --out ./network-map
```

Start narrower while you are tuning the options:

```bash
python3 aws_network_mapper.py --regions eu-west-1,us-east-1 --out ./map
```

Then open `./map/START-HERE.md`, which lists every diagram and every finding.

Useful flags:

| Flag | Effect |
| --- | --- |
| `--all-regions` | scan every region enabled for the account |
| `--deep` | also write a per-subnet diagram for every subnet |
| `--reports` | also write the CSV/JSON/Markdown evidence files |
| `--services core-only` | skip ELBv2, RDS, ECS, EKS, Lambda (faster, fewer permissions) |
| `--cache-dir DIR` | cache location, default `<out>/.cache` |
| `--offline` | rebuild all output from the cache, no AWS calls at all |
| `--no-cache` | neither read nor write the cache |
| `--no-diagrams` / `--no-rules` | skip diagrams, or the findings that annotate them |
| `--max-workers N` | parallel API calls per region (default 8) |
| `-q` | quieter console output |

Re-render after tweaking rules or diagrams without re-collecting:

```bash
python3 aws_network_mapper.py --offline --cache-dir ./network-map/.cache --out ./network-map-2
```

## Trying it without an AWS account

```bash
python3 aws_network_mapper.py --self-test     # 131 offline checks, no AWS calls
python3 aws_network_mapper.py --demo --out ./demo
```

`--demo` runs a synthetic two-region account (6 VPCs, a transit gateway, a
cross-region peering, NAT, an ALB with targets, RDS, EKS, ECS, Lambda, endpoints,
plus deliberate misconfigurations) so you can see the output shape and the
findings engine working.

Outside CloudShell you need `pip install boto3`.

## Permissions

Read-only EC2 plus the service APIs you enable. `--services core-only` needs:

```
ec2:DescribeVpcs            ec2:DescribeSubnets         ec2:DescribeRouteTables
ec2:DescribeInternetGateways ec2:DescribeNatGateways    ec2:DescribeTransitGateways
ec2:DescribeTransitGatewayAttachments          ec2:DescribeTransitGatewayRouteTables
ec2:DescribeVpcPeeringConnections             ec2:DescribeVpcEndpoints
ec2:DescribeNetworkInterfaces                  ec2:DescribeSecurityGroups
ec2:DescribeNetworkAcls                       ec2:DescribeVpnGateways
ec2:DescribeVpnConnections                     ec2:DescribeInstances
ec2:DescribeRegions
```

The default service set additionally uses `elasticloadbalancing:DescribeLoadBalancers`,
`elasticloadbalancing:DescribeTargetGroups`,
`elasticloadbalancing:DescribeTargetHealth`, `elasticloadbalancing:DescribeListeners`,
`elasticloadbalancing:DescribeRules`, `rds:DescribeDBInstances`,
`ecs:DescribeServices`, `ecs:DescribeTaskDefinitions`, `ecs:ListClusters`,
`ecs:ListTasks`, `ecs:ListServices`, `ecs:DescribeClusters`,
`eks:DescribeClusters`, `eks:DescribeNodegroups`, `lambda:ListFunctions`.

Any missing permission is recorded in `logs/run.log` and in the
`collection_errors` metric; the affected part of the report degrades instead of
failing the run.

## Configuration-derived connectivity

Every verdict in `cross-vpc-connectivity.csv` and `load-balancer-flows.csv` is
derived from routing tables, gateway attachments and security groups. It answers
"is this path configured correctly?", not "is traffic using it?".

Actual flows need telemetry that is not part of configuration: VPC Flow Logs,
Transit Gateway Flow Logs, or a Network Firewall. `NET018` flags VPCs with no
flow logs, since without them you cannot tell configured from used.

Each row carries a verdict, the reason, and the return-path verdict separately,
because one-way routing is the most common finding in real accounts.

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
them, and a recommendation.

## Layout

```
aws_network_mapper.py    entry point
nm/cidrutil.py           CIDR and IP helpers
nm/model.py              normalized resource model and API parsing
nm/collect.py            concurrent cached collection
nm/topology.py           indexes, subnet to route table resolution
nm/paths.py              route, gateway, peering and security group path evaluation
nm/flow.py               normalized connectivity model: subnet classification,
                         route arrows, workload arrows (reuses paths.py)
nm/analysis.py           cross-VPC, load balancer, exposure, CIDR analyses
nm/findings.py           the rules above
nm/mermaid.py            the single topology diagram renderer
nm/report.py             CSV, JSON and Markdown writers
nm/cli.py                argument parsing and orchestration
nm/fixtures.py           synthetic scenario
nm/testing.py            fixture-backed collector used by the self-test
nm/selftest.py           the offline checks
```

Python 3.9+, standard library plus `boto3`.