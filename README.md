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

Default output is diagrams only:

```
<out>/
  START-HERE.md              what to open first, and every finding in a table
  00-data-flow.mmd           THE one to read: internet -> gateways -> subnets
                             -> workloads -> ENIs -> security groups -> ports
  01-overview.mmd            all VPCs, TGWs, peerings, IGWs, on-prem, internet
  02-transit-gateways.mmd    attachments, TGW route tables, associations
  03-internet-paths.mmd      IGWs, NAT gateways, public subnets, EIPs
  vpcs/<region>-<name>-<id>-flow.mmd   layered flow for one VPC
  vpcs/<region>-<name>-<id>.mmd        same VPC as a reference diagram
  logs/run.log
```

Add `--deep` for a per-subnet file under `subnets/`, or `--reports` for the
CSV/Markdown evidence set:

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

Each `.mmd` file is Mermaid text. Paste one into <https://mermaid.live>, or render:

```bash
npx -y @mermaid-js/mermaid-cli -i 00-data-flow.mmd -o flow.svg
```

## The data-flow diagram

`00-data-flow.mmd` is the point of the tool. It lays the network out in the order
a packet crosses it, so you can read it top to bottom:

```
INTERNET
  |  HTTPS/80/443
Internet Gateway
  |  routes here
public subnet          (route table named on the node)
  |  hosts
ALB / EC2
  |  :8080             (load balancer target port)
EC2 target
  |
ENI                    (private and public IPs)
  |  uses
Security group
  |  allows
ingress TCP 8080 from sg sg-alb
```

Subnets are grouped into public / private / data tiers, and every arrow is a real
configured route, a real load balancer target, or a real security group rule,
not a generic association. Per-VPC versions of the same diagram are under `vpcs/`.

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
nm/analysis.py           cross-VPC, load balancer, exposure, CIDR analyses
nm/findings.py           the rules above
nm/mermaid.py            diagram builders
nm/report.py             CSV, JSON and Markdown writers
nm/cli.py                argument parsing and orchestration
nm/fixtures.py           synthetic scenario
nm/testing.py            fixture-backed collector used by the self-test
nm/selftest.py           the offline checks
```

Python 3.9+, standard library plus `boto3`.