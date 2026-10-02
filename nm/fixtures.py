"""Synthetic AWS API payloads used by the self-test.

The payloads mirror real ``describe_*`` response items closely enough to drive
the collector, the analysis layer, the rules engine and the renderers, so the
whole pipeline can be verified without AWS credentials.

The scenario deliberately contains the mistakes a real audit looks for:
a broken NAT, a detached IGW referenced by a route table, dual default routes,
one-way VPC peering, a missing return route through the transit gateway,
overlapping CIDRs on a connected pair, open management ports and unused groups.
"""

from __future__ import annotations

from typing import Any, Dict, List

Fixture = Dict[str, Dict[str, Any]]


def _tags(name: str) -> List[Dict[str, str]]:
    return [{"Key": "Name", "Value": name}]


def build_fixtures() -> Fixture:
    eu = _eu_west_1()
    us = _us_east_1()
    return {"eu-west-1": eu, "us-east-1": us}


# --------------------------------------------------------------------------- #
# eu-west-1: hub VPC (prod) with public/app/db tiers, TGW and NAT
# --------------------------------------------------------------------------- #


def _eu_west_1() -> Dict[str, Any]:
    return {
        "describe_vpcs": [
            {
                "VpcId": "vpc-prod",
                "CidrBlock": "10.0.0.0/16",
                "IsDefault": False,
                "DhcpOptionsId": "dopt-prod",
                "CidrBlockAssociationSet": [
                    {"CidrBlock": "10.0.0.0/16", "CidrBlockState": {"State": "associated"}}
                ],
                "Tags": _tags("prod-app"),
            },
            {
                "VpcId": "vpc-data",
                "CidrBlock": "10.30.0.0/16",
                "IsDefault": False,
                "DhcpOptionsId": "dopt-data",
                "CidrBlockAssociationSet": [
                    {"CidrBlock": "10.30.0.0/16", "CidrBlockState": {"State": "associated"}}
                ],
                "Tags": _tags("data-platform"),
            },
            {
                "VpcId": "vpc-sandbox",
                "CidrBlock": "10.50.0.0/16",
                "IsDefault": False,
                "DhcpOptionsId": "dopt-sandbox",
                "CidrBlockAssociationSet": [
                    {"CidrBlock": "10.50.0.0/16", "CidrBlockState": {"State": "associated"}}
                ],
                "Tags": _tags("sandbox"),
            },
            {
                "VpcId": "vpc-dev",
                "CidrBlock": "10.40.0.0/16",
                "IsDefault": False,
                "DhcpOptionsId": "dopt-dev",
                "CidrBlockAssociationSet": [
                    {"CidrBlock": "10.40.0.0/16", "CidrBlockState": {"State": "associated"}},
                    {"CidrBlock": "10.0.5.0/24", "CidrBlockState": {"State": "associated"}},
                ],
                "Tags": _tags("dev-sandbox"),
            },
        ],
        "describe_subnets": [
            _subnet("subnet-pub-1", "vpc-prod", "10.0.1.0/24", "eu-west-1a", "public-1a"),
            _subnet("subnet-pub-2", "vpc-prod", "10.0.2.0/24", "eu-west-1b", "public-1b"),
            _subnet("subnet-app-1", "vpc-prod", "10.0.10.0/24", "eu-west-1a", "app-private-1"),
            _subnet("subnet-app-2", "vpc-prod", "10.0.11.0/24", "eu-west-1b", "app-private-2"),
            _subnet("subnet-db-1", "vpc-prod", "10.0.20.0/24", "eu-west-1a", "db-primary"),
            _subnet("subnet-dup", "vpc-prod", "10.0.30.0/24", "eu-west-1c", "app-dup"),
            _subnet("subnet-data-1", "vpc-data", "10.30.1.0/24", "eu-west-1a", "data-1"),
            _subnet("subnet-data-nat", "vpc-data", "10.30.2.0/24", "eu-west-1b", "data-nat"),
            _subnet("subnet-dev-1", "vpc-dev", "10.40.1.0/24", "eu-west-1a", "dev-1"),
            _subnet("subnet-sandbox-1", "vpc-sandbox", "10.50.1.0/24", "eu-west-1a", "sandbox-1"),
        ],
        "describe_route_tables": [
            {
                "RouteTableId": "rtb-prod-main",
                "VpcId": "vpc-prod",
                "Associations": [{"Main": True, "RouteTableAssociationId": "rtbassoc-prod-main"}],
                "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"}],
                "Tags": [],
            },
            _rtb(
                "rtb-prod-public",
                "vpc-prod",
                "public-tier",
                ["subnet-pub-1", "subnet-pub-2"],
                [
                    _route("10.0.0.0/16", "GatewayId", "local"),
                    _route("0.0.0.0/0", "GatewayId", "igw-prod"),
                ],
            ),
            _rtb(
                "rtb-prod-app",
                "vpc-prod",
                "app-tier",
                ["subnet-app-1", "subnet-app-2"],
                [
                    _route("10.0.0.0/16", "GatewayId", "local"),
                    _route("10.30.0.0/16", "TransitGatewayId", "tgw-hub"),
                    _route("172.16.0.0/16", "VpcPeeringConnectionId", "pcx-prod-shared"),
                    _route("10.40.0.0/16", "TransitGatewayId", "tgw-hub"),
                    _route("0.0.0.0/0", "NatGatewayId", "nat-prod"),
                ],
            ),
            _rtb(
                "rtb-prod-db",
                "vpc-prod",
                "db-tier",
                ["subnet-db-1"],
                [_route("10.0.0.0/16", "GatewayId", "local")],
            ),
            # deliberate: two active 0.0.0.0/0 routes with different targets
            _rtb(
                "rtb-prod-dup",
                "vpc-prod",
                "app-dup",
                ["subnet-dup"],
                [
                    _route("10.0.0.0/16", "GatewayId", "local"),
                    _route("0.0.0.0/0", "NatGatewayId", "nat-prod"),
                    _route("0.0.0.0/0", "GatewayId", "igw-prod"),
                ],
            ),
            {
                "RouteTableId": "rtb-data-main",
                "VpcId": "vpc-data",
                "Associations": [{"Main": True, "RouteTableAssociationId": "rtbassoc-data-main"}],
                "Routes": [
                    _route("10.30.0.0/16", "GatewayId", "local"),
                    _route("10.0.0.0/16", "TransitGatewayId", "tgw-hub"),
                ],
                "Tags": _tags("data-main"),
            },
            {
                "RouteTableId": "rtb-dev-main",
                "VpcId": "vpc-dev",
                "Associations": [{"Main": True, "RouteTableAssociationId": "rtbassoc-dev-main"}],
                "Routes": [
                    _route("10.40.0.0/16", "GatewayId", "local"),
                    # points at an internet gateway that is not attached anywhere
                    _route("0.0.0.0/0", "GatewayId", "igw-orphan"),
                ],
                "Tags": _tags("dev-main"),
            },
            {
                # routes at the transit gateway but was never attached to it
                "RouteTableId": "rtb-sandbox-main",
                "VpcId": "vpc-sandbox",
                "Associations": [{"Main": True, "RouteTableAssociationId": "rtbassoc-sandbox-main"}],
                "Routes": [
                    _route("10.50.0.0/16", "GatewayId", "local"),
                    _route("10.0.0.0/16", "TransitGatewayId", "tgw-hub"),
                ],
                "Tags": _tags("sandbox-main"),
            },
            # unused route table
            _rtb(
                "rtb-orphan",
                "vpc-prod",
                "leftover",
                [],
                [_route("10.0.0.0/16", "GatewayId", "local")],
            ),
        ],
        "describe_internet_gateways": [
            {
                "InternetGatewayId": "igw-prod",
                "Attachments": [
                    {"VpcId": "vpc-prod", "State": "available"}
                ],
                "Tags": _tags("prod-igw"),
            },
            {"InternetGatewayId": "igw-orphan", "Attachments": [], "Tags": _tags("orphan-igw")},
        ],
        "describe_nat_gateways": [
            {
                "NatGatewayId": "nat-prod",
                "SubnetId": "subnet-pub-1",
                "VpcId": "vpc-prod",
                "State": "available",
                "ConnectivityType": "public",
                "NatGatewayAddresses": [{"AllocationId": "eipalloc-prod"}],
                "Tags": _tags("prod-nat"),
            },
            {
                "NatGatewayId": "nat-data",
                "SubnetId": "subnet-data-nat",
                "VpcId": "vpc-data",
                "State": "available",
                "ConnectivityType": "public",
                "NatGatewayAddresses": [{"AllocationId": "eipalloc-data"}],
                "Tags": _tags("data-nat"),
            },
        ],
        "describe_transit_gateways": [
            {
                "TransitGatewayId": "tgw-hub",
                "OwnerId": "111122223333",
                "State": "available",
                "Tags": _tags("corp-hub"),
            }
        ],
        "describe_transit_gateway_attachments": [
            {
                "TransitGatewayAttachmentId": "tgw-attach-prod",
                "TransitGatewayId": "tgw-hub",
                "ResourceType": "vpc",
                "ResourceId": "vpc-prod",
                "State": "available",
                "CidrBlock": "10.0.0.0/16",
                "SubnetIds": ["subnet-app-1", "subnet-app-2"],
                "Tags": _tags("prod"),
            },
            {
                "TransitGatewayAttachmentId": "tgw-attach-data",
                "TransitGatewayId": "tgw-hub",
                "ResourceType": "vpc",
                "ResourceId": "vpc-data",
                "State": "available",
                "CidrBlock": "10.30.0.0/16",
                "SubnetIds": ["subnet-data-1"],
                "Tags": _tags("data"),
            },
            {
                "TransitGatewayAttachmentId": "tgw-attach-dev",
                "TransitGatewayId": "tgw-hub",
                "ResourceType": "vpc",
                "ResourceId": "vpc-dev",
                "State": "available",
                "CidrBlock": "10.40.0.0/16",
                "SubnetIds": ["subnet-dev-1"],
                "Tags": _tags("dev"),
            },
        ],
        "describe_transit_gateway_route_tables": [
            {
                "TransitGatewayRouteTableId": "tgw-rtb-hub",
                "TransitGatewayId": "tgw-hub",
                "DefaultAssociationRouteTable": True,
                "DefaultPropagationRouteTable": True,
                "Associations": [
                    {"TransitGatewayAttachmentId": "tgw-attach-prod"},
                    {"TransitGatewayAttachmentId": "tgw-attach-data"},
                    {"TransitGatewayAttachmentId": "tgw-attach-dev"},
                ],
                "Propagation": [
                    {"TransitGatewayAttachmentId": "tgw-attach-prod"},
                    {"TransitGatewayAttachmentId": "tgw-attach-data"},
                    {"TransitGatewayAttachmentId": "tgw-attach-dev"},
                ],
                "Tags": _tags("hub-rtb"),
            }
        ],
        "search_transit_gateway_routes:tgw-rtb-hub": [
            {"DestinationCidrBlock": "10.0.0.0/16", "TransitGatewayAttachmentId": "tgw-attach-prod", "State": "active"},
            {"DestinationCidrBlock": "10.30.0.0/16", "TransitGatewayAttachmentId": "tgw-attach-data", "State": "active"},
            {"DestinationCidrBlock": "10.40.0.0/16", "TransitGatewayAttachmentId": "tgw-attach-dev", "State": "active"},
            {"DestinationCidrBlock": "0.0.0.0/0", "TransitGatewayAttachmentId": "tgw-attach-prod", "State": "active"},
        ],
        "describe_vpc_peering_connections": [
            {
                "VpcPeeringConnectionId": "pcx-prod-shared",
                "VpcPeeringConnection": {
                    "VpcPeeringConnectionId": "pcx-prod-shared",
                    "VpcId": "vpc-prod",
                    "PeeredVpcId": "vpc-shared",
                    "PeerOwnerId": "111122223333",
                    "PeerRegion": "us-east-1",
                    "ExpirationTime": "2027-01-01T00:00:00.000Z",
                    "Tags": _tags("prod-to-shared"),
                },
                "Status": {"Code": "active", "Message": "Active"},
                "AccepterVpcInfo": {"OwnerId": "111122223333"},
                "Options": {"AllowDnsResolutionFromRemoteVpc": False},
            }
        ],
        "describe_vpn_gateways": [],
        "describe_vpn_connections": [],
        "describe_vpc_endpoints": [
            {
                "VpcEndpointId": "vpce-s3-prod",
                "VpcId": "vpc-prod",
                "ServiceName": "com.amazonaws.eu-west-1.s3",
                "VpcEndpointType": "Gateway",
                "State": "available",
                "RouteTableIds": ["rtb-prod-app", "rtb-prod-db"],
                "PolicyDocument": json_dumps(
                    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}
                ),
                "Tags": _tags("prod-s3-endpoint"),
            }
        ],
        "describe_network_interfaces": _enis_eu(),
        "describe_network_acls": _nacls_eu(),
        "describe_security_groups": _sgs_eu(),
        "describe_instances": [{"Instances": _instances_eu()}],
        "elbv2.describe_load_balancers": _elb_eu(),
        "elbv2.describe_target_groups": [_target_group()],
        "elbv2.target_health:tg-app/abc123": [
            {"Target": {"Id": "i-app-01", "Port": 8080, "AvailabilityZone": "eu-west-1a"}, "TargetHealth": {"State": "healthy"}},
            {"Target": {"Id": "i-app-02", "Port": 8080, "AvailabilityZone": "eu-west-1b"}, "TargetHealth": {"State": "healthy"}},
        ],
        "rds.describe_db_instances": [
            {
                "DBInstanceIdentifier": "prod-postgres",
                "DbiResourceId": "db-prod-postgres",
                "Engine": "postgres",
                "DBInstanceClass": "db.r6g.xlarge",
                "DBInstanceStatus": "available",
                "DBSubnetGroup": {"DBSubnetGroupName": "sg-prod-db", "VpcId": "vpc-prod"},
                "PubliclyAccessible": False,
                "MultiAZ": True,
                "StorageEncrypted": True,
                "Endpoint": {"Address": "prod-postgres.abc.eu-west-1.rds.amazonaws.com", "Port": 5432},
            }
        ],
        "rds.describe_db_subnet_groups": [
            {
                "DBSubnetGroupName": "sg-prod-db",
                "VpcId": "vpc-prod",
                "Subnets": [
                    {"SubnetIdentifier": "subnet-db-1", "SubnetStatus": "Active", "SubnetVpcId": "vpc-prod"}
                ],
            }
        ],
        "ecs.list_clusters": [],
        "eks.list_clusters": [],
        "lambda.list_functions": [],
    }


def json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj)


TG_APP_ARN = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/tg-app/abc123"
ALB_ARN = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/my-alb/def456"


def _target_group() -> Dict[str, Any]:
    return {
        "TargetGroupName": "tg-app",
        "TargetGroupArn": TG_APP_ARN,
        "LoadBalancerArns": [ALB_ARN],
        "TargetType": "instance",
    }


def _subnet(sid: str, vpc: str, cidr: str, az: str, name: str) -> Dict[str, Any]:
    return {
        "SubnetId": sid,
        "VpcId": vpc,
        "CidrBlock": cidr,
        "AvailabilityZone": az,
        "AvailabilityZoneId": az + "x",
        "MapPublicIpOnLaunch": False,
        "AvailableIpAddressCount": 200,
        "Tags": _tags(name),
    }


def _route(dest: str, field_name: str, target: str) -> Dict[str, Any]:
    return {
        "DestinationCidrBlock": dest,
        field_name: target,
        "State": "active",
        "Origin": "CreateRoute",
    }


def _rtb(
    rid: str,
    vpc: str,
    name: str,
    subnets: List[str],
    routes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "RouteTableId": rid,
        "VpcId": vpc,
        "Associations": [
            {"Main": False, "SubnetId": s, "RouteTableAssociationId": f"rtbassoc-{s}"}
            for s in subnets
        ],
        "Routes": routes,
        "Tags": _tags(name),
    }


def _eni(
    eni: str,
    vpc: str,
    subnet: str,
    private_ip: str,
    sgs: List[str],
    desc: str,
    *,
    public_ip: str = "",
    instance: str = "",
    iface_type: str = "interface",
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "NetworkInterfaceId": eni,
        "VpcId": vpc,
        "SubnetId": subnet,
        "Description": desc,
        "PrivateIpAddress": private_ip,
        "PrivateIpAddresses": [{"PrivateIpAddress": private_ip, "Primary": True}],
        "InterfaceType": iface_type,
        "Status": "in-use",
        "OwnerId": "111122223333",
        "Groups": [{"GroupId": g, "GroupName": g} for g in sgs],
    }
    if public_ip:
        out["Association"] = {"PublicIp": public_ip}
    if instance:
        out["Attachment"] = {"InstanceId": instance, "InstanceOwnerId": "111122223333"}
    return out


def _enis_eu() -> List[Dict[str, Any]]:
    return [
        _eni("eni-alb-1", "vpc-prod", "subnet-pub-1", "10.0.1.10", ["sg-alb"], "ELB app/my-alb/1234/1234", iface_type="loadBalancer"),
        _eni("eni-alb-2", "vpc-prod", "subnet-pub-2", "10.0.2.10", ["sg-alb"], "ELB app/my-alb/1234/1234", iface_type="loadBalancer"),
        _eni("eni-app-01", "vpc-prod", "subnet-app-1", "10.0.10.20", ["sg-app"], "ip-10.0.10.20.eu-west-1.compute.internal", instance="i-app-01"),
        _eni("eni-app-02", "vpc-prod", "subnet-app-2", "10.0.11.20", ["sg-app"], "ip-10.0.11.20.eu-west-1.compute.internal", instance="i-app-02"),
        _eni("eni-bastion", "vpc-prod", "subnet-pub-1", "10.0.1.50", ["sg-ssh"], "bastion host", public_ip="203.0.113.50", instance="i-bastion"),
        _eni("eni-rds", "vpc-prod", "subnet-db-1", "10.0.20.30", ["sg-db"], "RDSNetworkInterface"),
        _eni("eni-nat-prod", "vpc-prod", "subnet-pub-1", "10.0.1.200", ["sg-nat"], "AWS Elastic NAT Gateway eni-prod", iface_type="natGateway"),
        _eni("eni-data-01", "vpc-data", "subnet-data-1", "10.30.1.20", ["sg-data"], "ip-10.30.1.20.eu-west-1.compute.internal", instance="i-data-01"),
        _eni("eni-nat-data", "vpc-data", "subnet-data-nat", "10.30.2.200", ["sg-nat"], "AWS Elastic NAT Gateway eni-data", iface_type="natGateway"),
        _eni("eni-dev-01", "vpc-dev", "subnet-dev-1", "10.40.1.20", ["sg-dev"], "ip-10.40.1.20.eu-west-1.compute.internal", instance="i-dev-01"),
    ]


def _nacls_eu() -> List[Dict[str, Any]]:
    return [
        {
            "NetworkAclId": "acl-prod-default",
            "VpcId": "vpc-prod",
            "IsDefault": True,
            "Entries": [
                {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"},
                {"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny", "Egress": False, "CidrBlock": "0.0.0.0/0"},
            ],
            "Tags": [],
        },
        {
            "NetworkAclId": "acl-prod-strict",
            "VpcId": "vpc-prod",
            "IsDefault": False,
            "Entries": [
                {
                    "RuleNumber": 110,
                    "Protocol": "6",
                    "RuleAction": "allow",
                    "Egress": False,
                    "CidrBlock": "0.0.0.0/0",
                    "PortRange": {"From": 22, "To": 22},
                },
                {"RuleNumber": 32767, "Protocol": "-1", "RuleAction": "deny", "Egress": False, "CidrBlock": "0.0.0.0/0"},
            ],
            "Tags": _tags("prod-strict"),
        },
    ]


def _sg(
    gid: str,
    vpc: str,
    name: str,
    ingress: List[Dict[str, Any]],
    egress: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    if egress is None:
        egress = [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "UserIdGroupPairs": [],
            }
        ]
    return {
        "GroupId": gid,
        "GroupName": name,
        "Description": f"{name} for {vpc}",
        "VpcId": vpc,
        "IpPermissions": ingress,
        "IpPermissionsEgress": egress,
        "Tags": _tags(name),
    }


def _sgs_eu() -> List[Dict[str, Any]]:
    return [
        _sg(
            "sg-alb",
            "vpc-prod",
            "alb-ingress",
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        ),
        _sg(
            "sg-app",
            "vpc-prod",
            "app-tier",
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpRanges": [],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [{"GroupId": "sg-alb"}],
                }
            ],
        ),
        _sg(
            "sg-ssh",
            "vpc-prod",
            "bastion-ssh",
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        ),
        _sg(
            "sg-db",
            "vpc-prod",
            "db-tier",
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        ),
        _sg(
            "sg-all",
            "vpc-prod",
            "wide-open",
            [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        ),
        _sg("sg-unused", "vpc-prod", "orphan-group", []),
        _sg("sg-nat", "vpc-prod", "nat-group", []),
        _sg("sg-data", "vpc-data", "data-tier", []),
        _sg("sg-dev", "vpc-dev", "dev-tier", []),
    ]


def _instance(
    iid: str,
    vpc: str,
    subnet: str,
    ip: str,
    sgs: List[str],
    name: str,
    *,
    public_ip: str = "",
    eni: str = "",
) -> Dict[str, Any]:
    assoc = {"PublicIp": public_ip} if public_ip else {}
    eni_block = {
        "NetworkInterfaceId": eni,
        "SubnetId": subnet,
        "VpcId": vpc,
        "PrivateIpAddress": ip,
        "SourceDestCheck": True,
        "Groups": [{"GroupId": g, "GroupName": g} for g in sgs],
    }
    if assoc:
        eni_block["Association"] = assoc
    return {
        "InstanceId": iid,
        "VpcId": vpc,
        "State": {"Name": "running", "Code": 16},
        "InstanceType": "t3.medium",
        "ImageId": "ami-0abc",
        "Placement": {"AvailabilityZone": subnet.rsplit("-", 1)[-1] and "eu-west-1a"},
        "NetworkInterfaces": [eni_block],
        "SecurityGroups": [{"GroupId": g, "GroupName": g} for g in sgs],
        "Tags": _tags(name),
    }


def _instances_eu() -> List[Dict[str, Any]]:
    return [
        _instance("i-app-01", "vpc-prod", "subnet-app-1", "10.0.10.20", ["sg-app"], "app-01", eni="eni-app-01"),
        _instance("i-app-02", "vpc-prod", "subnet-app-2", "10.0.11.20", ["sg-app"], "app-02", eni="eni-app-02"),
        _instance("i-bastion", "vpc-prod", "subnet-pub-1", "10.0.1.50", ["sg-ssh"], "bastion", public_ip="203.0.113.50", eni="eni-bastion"),
        _instance("i-data-01", "vpc-data", "subnet-data-1", "10.30.1.20", ["sg-data"], "data-01", eni="eni-data-01"),
        _instance("i-dev-01", "vpc-dev", "subnet-dev-1", "10.40.1.20", ["sg-dev"], "dev-01", eni="eni-dev-01"),
    ]


def _elb_eu() -> List[Dict[str, Any]]:
    return [
        {
            "LoadBalancerArn": ALB_ARN,
            "LoadBalancerName": "my-alb",
            "Type": "application",
            "Scheme": "internet-facing",
            "DNSName": "my-alb-123.eu-west-1.elb.amazonaws.com",
            "State": {"Code": "active"},
            "AvailabilityZones": [
                {"ZoneName": "eu-west-1a", "SubnetId": "subnet-pub-1", "NetworkInterfaceId": "eni-alb-1", "IpAddress": "10.0.1.10"},
                {"ZoneName": "eu-west-1b", "SubnetId": "subnet-pub-2", "NetworkInterfaceId": "eni-alb-2", "IpAddress": "10.0.2.10"},
            ],
            "SecurityGroups": ["sg-alb"],
        }
    ]


# --------------------------------------------------------------------------- #
# us-east-1: shared services + an unconnected legacy VPC with an overlapping CIDR
# --------------------------------------------------------------------------- #


def _us_east_1() -> Dict[str, Any]:
    return {
        "describe_vpcs": [
            {
                "VpcId": "vpc-shared",
                "CidrBlock": "172.16.0.0/16",
                "IsDefault": False,
                "DhcpOptionsId": "dopt-shared",
                "CidrBlockAssociationSet": [
                    {"CidrBlock": "172.16.0.0/16", "CidrBlockState": {"State": "associated"}}
                ],
                "Tags": _tags("shared-services"),
            },
            {
                "VpcId": "vpc-legacy",
                "CidrBlock": "10.0.0.0/16",
                "IsDefault": False,
                "DhcpOptionsId": "dopt-legacy",
                "CidrBlockAssociationSet": [
                    {"CidrBlock": "10.0.0.0/16", "CidrBlockState": {"State": "associated"}}
                ],
                "Tags": _tags("legacy"),
            },
        ],
        "describe_subnets": [
            _subnet("subnet-shared-1", "vpc-shared", "172.16.1.0/24", "us-east-1a", "shared-app-1"),
            _subnet("subnet-shared-2", "vpc-shared", "172.16.2.0/24", "us-east-1b", "shared-app-2"),
            _subnet("subnet-shared-db", "vpc-shared", "172.16.20.0/24", "us-east-1a", "shared-db"),
            _subnet("subnet-legacy-1", "vpc-legacy", "10.0.99.0/24", "us-east-1a", "legacy-1"),
        ],
        "describe_route_tables": [
            {
                "RouteTableId": "rtb-shared-main",
                "VpcId": "vpc-shared",
                "Associations": [{"Main": True, "RouteTableAssociationId": "rtbassoc-shared-main"}],
                "Routes": [
                    _route("172.16.0.0/16", "GatewayId", "local"),
                    _route("0.0.0.0/0", "GatewayId", "igw-shared"),
                ],
                "Tags": _tags("shared-main"),
            },
            {
                "RouteTableId": "rtb-legacy-main",
                "VpcId": "vpc-legacy",
                "Associations": [{"Main": True, "RouteTableAssociationId": "rtbassoc-legacy-main"}],
                "Routes": [_route("10.0.0.0/16", "GatewayId", "local")],
                "Tags": _tags("legacy-main"),
            },
        ],
        "describe_internet_gateways": [
            {
                "InternetGatewayId": "igw-shared",
                "Attachments": [{"VpcId": "vpc-shared", "State": "available"}],
                "Tags": _tags("shared-igw"),
            }
        ],
        "describe_nat_gateways": [],
        "describe_transit_gateways": [],
        "describe_transit_gateway_attachments": [],
        "describe_transit_gateway_route_tables": [],
        "describe_vpc_peering_connections": [
            {
                "VpcPeeringConnectionId": "pcx-prod-shared",
                "VpcPeeringConnection": {
                    "VpcPeeringConnectionId": "pcx-prod-shared",
                    "VpcId": "vpc-shared",
                    "PeeredVpcId": "vpc-prod",
                    "PeerOwnerId": "111122223333",
                    "PeerRegion": "eu-west-1",
                    "Tags": _tags("shared-to-prod"),
                },
                "Status": {"Code": "active", "Message": "Active"},
                "AccepterVpcInfo": {"OwnerId": "111122223333"},
                "Options": {"AllowDnsResolutionFromRemoteVpc": False},
            }
        ],
        "describe_vpn_gateways": [],
        "describe_vpn_connections": [],
        "describe_vpc_endpoints": [
            {
                "VpcEndpointId": "vpce-ecr-shared",
                "VpcId": "vpc-shared",
                "ServiceName": "com.amazonaws.us-east-1.ecr.api",
                "VpcEndpointType": "Interface",
                "State": "available",
                "SubnetIds": ["subnet-shared-1", "subnet-shared-2"],
                "GroupsList": [{"GroupId": "sg-ep-shared"}],
                "NetworkInterfaceIdList": ["eni-ep-shared-1", "eni-ep-shared-2"],
                "PolicyDocument": json_dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": "*", "Action": "ecr:*", "Resource": "arn:aws:ecr:*:*:repository/prod/*"}
                        ],
                    }
                ),
                "Tags": _tags("shared-ecr-endpoint"),
            }
        ],
        "describe_network_interfaces": [
            _eni("eni-shared-01", "vpc-shared", "subnet-shared-1", "172.16.1.20", ["sg-shared"], "AWS Lambda VPC ENI-fn-1", iface_type="lambda"),
            _eni("eni-ep-shared-1", "vpc-shared", "subnet-shared-1", "172.16.1.51", ["sg-ep-shared"], "AWS VPC Endpoint vpce-ecr-shared", iface_type="vpce"),
            _eni("eni-ep-shared-2", "vpc-shared", "subnet-shared-2", "172.16.2.51", ["sg-ep-shared"], "AWS VPC Endpoint vpce-ecr-shared", iface_type="vpce"),
            _eni("eni-nlb-shared", "vpc-shared", "subnet-shared-1", "172.16.1.40", ["sg-nlb"], "ELB net/shared-nlb/1/2", iface_type="loadBalancer"),
            _eni("eni-legacy-01", "vpc-legacy", "subnet-legacy-1", "10.0.99.20", ["sg-legacy"], "ip-10.0.99.20.us-east-1.compute.internal", instance="i-legacy-01"),
        ],
        "describe_network_acls": [
            {
                "NetworkAclId": "acl-shared-default",
                "VpcId": "vpc-shared",
                "IsDefault": True,
                "Entries": [
                    {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"}
                ],
                "Tags": [],
            }
        ],
        "describe_security_groups": [
            _sg("sg-shared", "vpc-shared", "shared-app", []),
            _sg("sg-nlb", "vpc-shared", "nlb-tier", []),
            _sg("sg-ep-shared", "vpc-shared", "endpoint", []),
            _sg(
                "sg-legacy",
                "vpc-legacy",
                "legacy-all",
                [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [],
                        "PrefixListIds": [],
                        "UserIdGroupPairs": [],
                    }
                ],
            ),
        ],
        "describe_instances": [
            {
                "Instances": [
                    _instance("i-legacy-01", "vpc-legacy", "subnet-legacy-1", "10.0.99.20", ["sg-legacy"], "legacy-01", eni="eni-legacy-01")
                ]
            }
        ],
        "elbv2.describe_load_balancers": [
            {
                "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/net/shared-nlb/aaa",
                "LoadBalancerName": "shared-nlb",
                "Type": "network",
                "Scheme": "internal",
                "DNSName": "shared-nlb-abc.us-east-1.elb.amazonaws.com",
                "State": {"Code": "active"},
                "AvailabilityZones": [
                    {"ZoneName": "us-east-1a", "SubnetId": "subnet-shared-1", "NetworkInterfaceId": "eni-nlb-shared", "IpAddress": "172.16.1.40"}
                ],
                "SecurityGroups": [],
            }
        ],
        "elbv2.describe_target_groups": [],
        "rds.describe_db_instances": [
            {
                "DBInstanceIdentifier": "shared-mysql",
                "DbiResourceId": "db-shared-mysql",
                "Engine": "mysql",
                "DBInstanceClass": "db.t3.medium",
                "DBInstanceStatus": "available",
                "DBSubnetGroup": {"DBSubnetGroupName": "sg-shared-db"},
                "PubliclyAccessible": True,
                "MultiAZ": False,
                "StorageEncrypted": False,
                "Endpoint": {"Address": "shared-mysql.abc.us-east-1.rds.amazonaws.com", "Port": 3306},
            }
        ],
        "rds.describe_db_subnet_groups": [
            {
                "DBSubnetGroupName": "sg-shared-db",
                "VpcId": "vpc-shared",
                "Subnets": [
                    {"SubnetIdentifier": "subnet-shared-db", "SubnetStatus": "Active", "SubnetVpcId": "vpc-shared"}
                ],
            }
        ],
        "ecs.list_clusters": ["arn:aws:ecs:us-east-1:111122223333:cluster/batch"],
        "ecs.describe_clusters": [
            {
                "clusterName": "batch",
                "clusterArn": "arn:aws:ecs:us-east-1:111122223333:cluster/batch",
                "status": "ACTIVE",
                "registeredContainerInstancesCount": 0,
                "resourcesVpcConfig": {
                    "vpcId": "vpc-shared",
                    "subnetIds": ["subnet-shared-1", "subnet-shared-2"],
                    "securityGroups": ["sg-shared"],
                },
            }
        ],
        "ecs.services:batch": ["arn:aws:ecs:us-east-1:111122223333:service/batch/ingest"],
        "ecs.describe_services:batch": [
            {
                "serviceName": "ingest",
                "serviceArn": "arn:aws:ecs:us-east-1:111122223333:service/batch/ingest",
                "status": "ACTIVE",
                "desiredCount": 2,
                "launchType": "FARGATE",
                "networkConfiguration": {
                    "awsvpcConfiguration": {
                        "subnets": ["subnet-shared-1", "subnet-shared-2"],
                        "securityGroups": ["sg-shared"],
                    }
                },
            }
        ],
        "eks.list_clusters": ["platform"],
        "eks.describe_cluster": [
            {
                "name": "platform",
                "status": "ACTIVE",
                "version": "1.30",
                "endpoint": "https://platform.eks.amazonaws.com",
                "resourcesVpcConfig": {
                    "vpcId": "vpc-shared",
                    "subnetIds": ["subnet-shared-1", "subnet-shared-2"],
                    "securityGroupIds": ["sg-shared"],
                },
            }
        ],
        "lambda.list_functions": [
            {
                "FunctionName": "ingest-handler",
                "Runtime": "python3.12",
                "State": "Active",
                "VpcConfig": {
                    "VpcId": "vpc-shared",
                    "SubnetIds": ["subnet-shared-1"],
                    "SecurityGroupIds": ["sg-shared"],
                },
            }
        ],
    }
