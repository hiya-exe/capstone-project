import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"


def _vpcs_with_igw(internet_gateways):
    attached = set()
    for gw in internet_gateways:
        for att in gw.get("Attachments", []):
            if att.get("State") == "available":
                vpc_id = att.get("VpcId")
                if vpc_id:
                    attached.add(vpc_id)
    return attached


def _check_flow_logs(findings, add_finding, ec2, vpcs):
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId")
        if not vpc_id:
            continue
        try:
            logs = ec2.describe_flow_logs(
                Filter=[{"Name": "resource-id", "Values": [vpc_id]}]
            ).get("FlowLogs", [])
        except ClientError:
            logs = []
        active = [l for l in logs if l.get("FlowLogStatus") == "ACTIVE"]
        if not active:
            reason = (
                "VPC Flow Logs are not enabled. Network traffic accepted or rejected "
                "by this VPC is not recorded, leaving no evidence for incident response, "
                "forensic investigation, or anomaly detection."
            )
            evidence = f"VpcId={vpc_id}, ActiveFlowLogs=0"
            add_finding(findings, "VPC-001", vpc_id, reason, evidence, service="VPC")


def _check_public_routes(findings, add_finding, route_tables):
    public_subnet_ids = set()
    for rt in route_tables:
        rt_id = rt.get("RouteTableId")
        vpc_id = rt.get("VpcId")
        public_routes = [
            r for r in rt.get("Routes", [])
            if r.get("DestinationCidrBlock") == "0.0.0.0/0"
            and r.get("GatewayId", "").startswith("igw-")
            and r.get("State", "active") == "active"
        ]
        if not public_routes:
            continue

        assoc_subnets = []
        for assoc in rt.get("Associations", []):
            sid = assoc.get("SubnetId")
            if sid:
                assoc_subnets.append(sid)
                public_subnet_ids.add(sid)

        gw_ids = sorted({r.get("GatewayId") for r in public_routes if r.get("GatewayId")})
        subnet_text = ", ".join(assoc_subnets) if assoc_subnets else "main route table (no explicit subnet association)"

        reason = (
            "A route table has a default route (0.0.0.0/0) pointing to an Internet Gateway. "
            "Subnets associated with this route table have direct internet connectivity, "
            "and resources placed there may become publicly reachable if security groups allow it."
        )
        evidence = (
            f"RouteTableId={rt_id}, VpcId={vpc_id}, "
            f"InternetGateway={', '.join(gw_ids)}, AssociatedSubnets={subnet_text}"
        )
        add_finding(findings, "VPC-002", rt_id, reason, evidence, service="VPC")

    return public_subnet_ids


def _check_auto_public_ip(findings, add_finding, subnets, public_subnet_ids):
    for subnet in subnets:
        subnet_id = subnet.get("SubnetId")
        if not subnet_id or not subnet.get("MapPublicIpOnLaunch", False):
            continue
        vpc_id = subnet.get("VpcId")
        az = subnet.get("AvailabilityZone", "Unknown")
        route_note = "Public route detected" if subnet_id in public_subnet_ids else "No explicit public route detected"
        reason = (
            "This subnet automatically assigns a public IPv4 address to every instance "
            "launched in it. New resources may be unintentionally exposed to the internet "
            "if their security group allows inbound traffic."
        )
        evidence = (
            f"SubnetId={subnet_id}, VpcId={vpc_id}, AvailabilityZone={az}, "
            f"MapPublicIpOnLaunch=True, RouteClassification={route_note}"
        )
        add_finding(findings, "VPC-003", subnet_id, reason, evidence, service="VPC")


def run_vpc_checks(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        subnets = ec2.describe_subnets().get("Subnets", [])
        route_tables = ec2.describe_route_tables().get("RouteTables", [])
        internet_gateways = ec2.describe_internet_gateways().get("InternetGateways", [])
    except ClientError as e:
        print(f"[WARN] VPC checks skipped: {e.response['Error']['Code']}")
        return

    _check_flow_logs(findings, add_finding, ec2, vpcs)
    public_subnet_ids = _check_public_routes(findings, add_finding, route_tables)
    _check_auto_public_ip(findings, add_finding, subnets, public_subnet_ids)
