import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"

# =============================================================================
# SECURITY GROUP CHECKS
# =============================================================================

def _check_sg_ssh_open_to_internet(findings, add_finding):
    """
    SG-001: Check if any security group allows SSH (port 22) from 0.0.0.0/0 or ::/0.
    SSH open to the internet exposes instances to brute force and unauthorized access.
    CIS Mapping: CIS Controls v8 - 4.4
    NIST CSF: PR.AC-3
    """
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        exposed = []

        for sg in sgs:
            sg_name = sg.get("GroupName", sg["GroupId"])
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)
                protocol = rule.get("IpProtocol", "")

                is_ssh_port = (protocol == "tcp" and from_port <= 22 <= to_port)
                is_all_traffic = (protocol == "-1")

                if is_ssh_port or is_all_traffic:
                    open_to_all = any(
                        r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
                    )
                    if open_to_all:
                        exposed.append(sg_name)
                        break

        if exposed:
            count = len(exposed)
            reason = (
                f"{count} security group(s) allow SSH (port 22) from the entire internet (0.0.0.0/0). "
                "This exposes EC2 instances to brute force login attacks and unauthorized remote access. "
                "SSH access should be restricted to known IP ranges only."
            )
            evidence = "Security groups with SSH open to internet: " + ", ".join(exposed)
            add_finding(
                findings, "SG-001",
                f"{count} group(s) with SSH open to internet",
                reason, evidence, service="SecurityGroups", severity="High"
            )
    except ClientError as e:
        print(f"[SKIP] SG SSH check skipped: {e.response['Error']['Code']}")


def _check_sg_rdp_open_to_internet(findings, add_finding):
    """
    SG-002: Check if any security group allows RDP (port 3389) from 0.0.0.0/0 or ::/0.
    RDP open to the internet is a common ransomware and brute force attack vector.
    CIS Mapping: CIS Controls v8 - 4.4
    NIST CSF: PR.AC-3
    """
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        exposed = []

        for sg in sgs:
            sg_name = sg.get("GroupName", sg["GroupId"])
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)
                protocol = rule.get("IpProtocol", "")

                is_rdp_port = (protocol == "tcp" and from_port <= 3389 <= to_port)
                is_all_traffic = (protocol == "-1")

                if is_rdp_port or is_all_traffic:
                    open_to_all = any(
                        r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
                    )
                    if open_to_all:
                        exposed.append(sg_name)
                        break

        if exposed:
            count = len(exposed)
            reason = (
                f"{count} security group(s) allow RDP (port 3389) from the entire internet (0.0.0.0/0). "
                "Open RDP is one of the most common entry points for ransomware attacks and brute force "
                "credential stuffing. RDP access should be restricted to trusted IPs or a VPN only."
            )
            evidence = "Security groups with RDP open to internet: " + ", ".join(exposed)
            add_finding(
                findings, "SG-002",
                f"{count} group(s) with RDP open to internet",
                reason, evidence, service="SecurityGroups", severity="High"
            )
    except ClientError as e:
        print(f"[SKIP] SG RDP check skipped: {e.response['Error']['Code']}")


def _check_sg_all_traffic_open(findings, add_finding):
    """
    SG-003: Check if any security group allows all inbound traffic from 0.0.0.0/0.
    Allowing all traffic removes any network-level protection for the resource.
    CIS Mapping: CIS Controls v8 - 12.2
    NIST CSF: PR.AC-5
    """
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        exposed = []

        for sg in sgs:
            sg_name = sg.get("GroupName", sg["GroupId"])
            for rule in sg.get("IpPermissions", []):
                protocol = rule.get("IpProtocol", "")
                if protocol == "-1":
                    open_to_all = any(
                        r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
                    )
                    if open_to_all:
                        exposed.append(sg_name)
                        break

        if exposed:
            count = len(exposed)
            reason = (
                f"{count} security group(s) allow all inbound traffic from the internet (0.0.0.0/0 "
                "with protocol -1). This completely removes network-level protection and exposes "
                "every port and protocol on attached resources to the public internet."
            )
            evidence = "Security groups allowing all inbound traffic: " + ", ".join(exposed)
            add_finding(
                findings, "SG-003",
                f"{count} group(s) allowing all inbound traffic",
                reason, evidence, service="SecurityGroups", severity="High"
            )
    except ClientError as e:
        print(f"[SKIP] SG all-traffic check skipped: {e.response['Error']['Code']}")


def _check_sg_unrestricted_outbound(findings, add_finding):
    """
    SG-004: Check if any security group allows all outbound traffic to 0.0.0.0/0.
    Unrestricted outbound traffic can allow data exfiltration or communication
    with malicious external servers.
    CIS Mapping: CIS Controls v8 - 12.2
    NIST CSF: PR.AC-5
    """
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        exposed = []

        for sg in sgs:
            sg_name = sg.get("GroupName", sg["GroupId"])
            for rule in sg.get("IpPermissionsEgress", []):
                protocol = rule.get("IpProtocol", "")
                if protocol == "-1":
                    open_to_all = any(
                        r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])
                    ) or any(
                        r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
                    )
                    if open_to_all:
                        exposed.append(sg_name)
                        break

        if exposed:
            count = len(exposed)
            reason = (
                f"{count} security group(s) allow all outbound traffic to the internet (0.0.0.0/0). "
                "Unrestricted outbound rules can allow data exfiltration, communication with "
                "command-and-control servers, or unauthorized data transfers from compromised instances."
            )
            evidence = "Security groups with unrestricted outbound: " + ", ".join(exposed)
            add_finding(
                findings, "SG-004",
                f"{count} group(s) with unrestricted outbound traffic",
                reason, evidence, service="SecurityGroups", severity="Medium"
            )
    except ClientError as e:
        print(f"[SKIP] SG outbound check skipped: {e.response['Error']['Code']}")


def _check_sg_unused_groups(findings, add_finding):
    """
    SG-005: Check if any security groups are not attached to any resource.
    Unused security groups are unnecessary clutter and may be accidentally
    reused with overly permissive rules in the future.
    CIS Mapping: CIS Controls v8 - 12.1
    NIST CSF: ID.AM-1
    """
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])

        # Collect all SG IDs that are in use by network interfaces
        used_sg_ids = set()
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for ni in page.get("NetworkInterfaces", []):
                for group in ni.get("Groups", []):
                    used_sg_ids.add(group["GroupId"])

        unused = []
        for sg in sgs:
            if sg["GroupId"] not in used_sg_ids and sg.get("GroupName") != "default":
                unused.append(sg.get("GroupName", sg["GroupId"]))

        if unused:
            count = len(unused)
            reason = (
                f"{count} security group(s) are not attached to any network interface or resource. "
                "Unused security groups add unnecessary complexity to the environment and may be "
                "mistakenly reused with overly permissive rules in the future."
            )
            evidence = "Unused security groups: " + ", ".join(unused)
            add_finding(
                findings, "SG-005",
                f"{count} unused security group(s) found",
                reason, evidence, service="SecurityGroups", severity="Low"
            )
    except ClientError as e:
        print(f"[SKIP] SG unused groups check skipped: {e.response['Error']['Code']}")


# =============================================================================
# MAIN RUNNER
# =============================================================================

def run_sg_checks(findings, add_finding):
    """Run all Security Group security checks."""
    _check_sg_ssh_open_to_internet(findings, add_finding)
    _check_sg_rdp_open_to_internet(findings, add_finding)
    _check_sg_all_traffic_open(findings, add_finding)
    _check_sg_unrestricted_outbound(findings, add_finding)
    _check_sg_unused_groups(findings, add_finding)
