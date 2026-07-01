import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"


def _is_world_open(ip_ranges):
    return any(r.get("CidrIp") == "0.0.0.0/0" for r in (ip_ranges or []))


def _get_used_sg_ids(ec2):
    used = set()
    try:
        for eni in ec2.describe_network_interfaces().get("NetworkInterfaces", []):
            for g in eni.get("Groups", []):
                gid = g.get("GroupId")
                if gid:
                    used.add(gid)
    except ClientError:
        pass
    return used


def run_sg_checks(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    except ClientError as e:
        print(f"[WARN] SG check skipped: {e.response['Error']['Code']}")
        return

    used_sg_ids = _get_used_sg_ids(ec2)

    for sg in sgs:
        sg_id = sg.get("GroupId", "Unknown")
        sg_name = sg.get("GroupName", sg_id)

        if used_sg_ids and sg_id not in used_sg_ids:
            reason = (
                "This security group is not attached to any network interface. "
                "Unused security groups can be accidentally reused with overly permissive "
                "rules that were never reviewed for the new workload."
            )
            evidence = f"GroupId={sg_id}, GroupName={sg_name}, AttachedENIs=0"
            add_finding(findings, "SG-005", sg_id, reason, evidence, service="SG")

        for perm in sg.get("IpPermissions", []):
            proto = perm.get("IpProtocol")
            fp = perm.get("FromPort")
            tp = perm.get("ToPort")
            ip_ranges = perm.get("IpRanges", [])

            if proto == "-1" and _is_world_open(ip_ranges):
                reason = (
                    "This security group allows ALL inbound traffic from the internet. "
                    "Every port and protocol is reachable, exposing admin services, "
                    "databases, and internal applications to the public."
                )
                evidence = f"GroupId={sg_id}, GroupName={sg_name}, Inbound=ALL(-1) from 0.0.0.0/0"
                add_finding(findings, "SG-003", sg_id, reason, evidence, service="SG")
                continue

            if fp == 22 and tp == 22 and _is_world_open(ip_ranges):
                reason = (
                    "Inbound SSH (port 22) is open to the entire internet. "
                    "Automated bots continuously scan for open SSH ports and attempt "
                    "brute-force logins. A single weak credential gives an attacker "
                    "full shell access to the instance."
                )
                evidence = f"GroupId={sg_id}, GroupName={sg_name}, Inbound=TCP 22 from 0.0.0.0/0"
                add_finding(findings, "SG-001", sg_id, reason, evidence, service="SG")

            if fp == 3389 and tp == 3389 and _is_world_open(ip_ranges):
                reason = (
                    "Inbound RDP (port 3389) is open to the entire internet. "
                    "RDP is a prime target for ransomware operators and brute-force attacks. "
                    "Public exposure increases the likelihood of remote takeover and "
                    "lateral movement once a foothold is established."
                )
                evidence = f"GroupId={sg_id}, GroupName={sg_name}, Inbound=TCP 3389 from 0.0.0.0/0"
                add_finding(findings, "SG-002", sg_id, reason, evidence, service="SG")

        for perm in sg.get("IpPermissionsEgress", []):
            if perm.get("IpProtocol") == "-1" and _is_world_open(perm.get("IpRanges", [])):
                reason = (
                    "This security group allows all outbound traffic to the internet. "
                    "If a workload is compromised, unrestricted egress makes it easy to "
                    "exfiltrate data or establish command-and-control communications."
                )
                evidence = f"GroupId={sg_id}, GroupName={sg_name}, Outbound=ALL(-1) to 0.0.0.0/0"
                add_finding(findings, "SG-004", sg_id, reason, evidence, service="SG")
                break
