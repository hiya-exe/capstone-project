
import boto3
from botocore.exceptions import ClientError


# ------------------------------------------------------------
# VPC CHECKS
# Rule IDs: VPC-001 .. VPC-003
# ------------------------------------------------------------

def _build_desc(issue_lines, evidence_lines, impact_lines, fix_lines):
    """
    Creates the detailed description displayed in the dashboard dropdown.
    """
    return "\n".join(
        ["Issue:"] + [f"• {line}" for line in issue_lines] +
        ["", "Evidence:"] + [f"• {line}" for line in evidence_lines] +
        ["", "Why it matters:"] + [f"• {line}" for line in impact_lines] +
        ["", "Suggested fix:"] + [f"• {line}" for line in fix_lines]
    )


def _add(
    findings,
    add_finding,
    rule_id,
    resource_id,
    issue_lines,
    evidence_lines,
    impact_lines,
    fix_lines
):
    """
    Sends a VPC finding to the project's existing add_finding callback.
    """
    add_finding(
        rule_id=rule_id,
        resource=resource_id,
        description=_build_desc(
            issue_lines,
            evidence_lines,
            impact_lines,
            fix_lines
        )
    )


def run_vpc_checks(findings, add_finding, region):
    """
    Runs VPC security checks and appends findings using the project's
    add_finding callback.

    Expected callback:
        add_finding(rule_id: str, resource: str, description: str)
    """

    ec2 = boto3.client("ec2", region_name=region)

    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        subnets = ec2.describe_subnets().get("Subnets", [])
        route_tables = ec2.describe_route_tables().get("RouteTables", [])
        internet_gateways = ec2.describe_internet_gateways().get(
            "InternetGateways", []
        )
    except ClientError as error:
        print(f"Unable to run VPC checks: {error}")
        return

    # Create a set of VPC IDs that have an Internet Gateway attached
    vpcs_with_igw = set()

    for gateway in internet_gateways:
        for attachment in gateway.get("Attachments", []):
            if attachment.get("State") == "available":
                vpc_id = attachment.get("VpcId")

                if vpc_id:
                    vpcs_with_igw.add(vpc_id)

    # --------------------------------------------------------
    # VPC-001: VPC Flow Logs Disabled
    # --------------------------------------------------------
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId")

        if not vpc_id:
            continue

        try:
            flow_logs = ec2.describe_flow_logs(
                Filter=[
                    {
                        "Name": "resource-id",
                        "Values": [vpc_id]
                    }
                ]
            ).get("FlowLogs", [])
        except ClientError:
            flow_logs = []

        active_flow_logs = [
            log for log in flow_logs
            if log.get("FlowLogStatus") == "ACTIVE"
        ]

        if not active_flow_logs:
            _add(
                findings,
                add_finding,
                "VPC-001",
                vpc_id,
                issue_lines=[
                    "VPC Flow Logs are not enabled.",
                    "Network traffic accepted or rejected by the VPC is not being recorded."
                ],
                evidence_lines=[
                    f"VPC ID: {vpc_id}",
                    "Active VPC Flow Logs found: 0"
                ],
                impact_lines=[
                    "Suspicious network activity may be harder to investigate.",
                    "The organization may lack evidence needed for incident response.",
                    "Network troubleshooting and security monitoring become more difficult."
                ],
                fix_lines=[
                    "Enable VPC Flow Logs for the VPC.",
                    "Send flow-log records to Amazon CloudWatch Logs or Amazon S3.",
                    "Monitor rejected connections and unexpected traffic patterns."
                ]
            )

    # --------------------------------------------------------
    # VPC-002: Public route through an Internet Gateway
    # --------------------------------------------------------
    public_subnet_ids = set()

    for route_table in route_tables:
        route_table_id = route_table.get("RouteTableId")
        vpc_id = route_table.get("VpcId")

        public_routes = []

        for route in route_table.get("Routes", []):
            destination = route.get("DestinationCidrBlock")
            gateway_id = route.get("GatewayId", "")

            if (
                destination == "0.0.0.0/0"
                and gateway_id.startswith("igw-")
                and route.get("State", "active") == "active"
            ):
                public_routes.append(route)

        if not public_routes:
            continue

        associated_subnet_ids = []

        for association in route_table.get("Associations", []):
            subnet_id = association.get("SubnetId")

            if subnet_id:
                associated_subnet_ids.append(subnet_id)
                public_subnet_ids.add(subnet_id)

        gateway_ids = sorted({
            route.get("GatewayId")
            for route in public_routes
            if route.get("GatewayId")
        })

        subnet_text = (
            ", ".join(associated_subnet_ids)
            if associated_subnet_ids
            else "No explicit subnet association; review the main route table association"
        )

        _add(
            findings,
            add_finding,
            "VPC-002",
            route_table_id,
            issue_lines=[
                "A route table contains a default route to an Internet Gateway.",
                "Subnets associated with this route table may have direct internet connectivity."
            ],
            evidence_lines=[
                f"Route table ID: {route_table_id}",
                f"VPC ID: {vpc_id}",
                "Destination: 0.0.0.0/0",
                f"Internet Gateway: {', '.join(gateway_ids)}",
                f"Associated subnets: {subnet_text}"
            ],
            impact_lines=[
                "Resources in these subnets may become publicly reachable when public IP addresses and permissive security rules are present.",
                "Unnecessary internet exposure increases the risk of unauthorized access.",
                "Sensitive workloads could be placed in a public subnet by mistake."
            ],
            fix_lines=[
                "Confirm that only intentionally public subnets use this route table.",
                "Place databases and internal systems in private subnets.",
                "Remove the Internet Gateway route when direct internet access is not required.",
                "Use a NAT Gateway for private-subnet outbound internet access when appropriate."
            ]
        )

    # --------------------------------------------------------
    # VPC-003: Automatic public IPv4 assignment enabled
    # --------------------------------------------------------
    for subnet in subnets:
        subnet_id = subnet.get("SubnetId")
        vpc_id = subnet.get("VpcId")
        availability_zone = subnet.get("AvailabilityZone", "Unknown")

        if not subnet_id:
            continue

        map_public_ip = subnet.get("MapPublicIpOnLaunch", False)

        if map_public_ip:
            route_classification = (
                "Public route detected"
                if subnet_id in public_subnet_ids
                else "No explicit public route detected"
            )

            _add(
                findings,
                add_finding,
                "VPC-003",
                subnet_id,
                issue_lines=[
                    "The subnet automatically assigns public IPv4 addresses to launched instances.",
                    "New resources may receive internet-routable addresses by default."
                ],
                evidence_lines=[
                    f"Subnet ID: {subnet_id}",
                    f"VPC ID: {vpc_id}",
                    f"Availability Zone: {availability_zone}",
                    "MapPublicIpOnLaunch: True",
                    f"Route classification: {route_classification}"
                ],
                impact_lines=[
                    "Instances may be unintentionally exposed to the internet.",
                    "A permissive security group could make services publicly accessible.",
                    "Public IP assignment increases the external attack surface."
                ],
                fix_lines=[
                    "Disable automatic public IPv4 assignment unless the subnet is intentionally public.",
                    "Use private subnets for internal applications and sensitive workloads.",
                    "Assign public addresses only to resources that specifically require them.",
                    "Review security groups and network ACLs for resources in the subnet."
                ]
            )
