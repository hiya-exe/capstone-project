import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 1521, 21, 23}


def _iter_paged(client, method_name, result_key, **kwargs):
    paginator = client.get_paginator(method_name)
    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item


def _rule_matches_sensitive_port(perm, target_ports):
    fp = perm.get("FromPort")
    tp = perm.get("ToPort")
    if fp is None or tp is None:
        return False
    return any(port in target_ports for port in range(fp, tp + 1))


def _sg_allows_world_on_port(ec2_client, sg_ids, target_ports):
    if not sg_ids:
        return False
    try:
        response = ec2_client.describe_security_groups(GroupIds=sg_ids)
        for sg in response.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                if not _rule_matches_sensitive_port(perm, target_ports):
                    continue

                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return True

                for ip_range in perm.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        return True

        return False
    except ClientError:
        return False


def _is_runnable_instance(instance):
    state = instance.get("State", {}).get("Name", "unknown")
    return state == "running"


def check_ec2(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        for reservation in _iter_paged(ec2, "describe_instances", "Reservations"):
            for inst in reservation.get("Instances", []):
                if not _is_runnable_instance(inst):
                    continue

                instance_id = inst.get("InstanceId", "Unknown")
                public_ip = inst.get("PublicIpAddress", "None")
                has_public_ip = "PublicIpAddress" in inst
                sg_ids = [
                    sg.get("GroupId")
                    for sg in inst.get("SecurityGroups", [])
                    if sg.get("GroupId")
                ]
                subnet_id = inst.get("SubnetId", "Unknown")
                vpc_id = inst.get("VpcId", "Unknown")
                tags = {
                    t.get("Key"): t.get("Value")
                    for t in inst.get("Tags", [])
                    if t.get("Key")
                }
                name = tags.get("Name", instance_id)

                sensitive_open = _sg_allows_world_on_port(ec2, sg_ids, SENSITIVE_PORTS)

                if has_public_ip and sensitive_open:
                    reason = (
                        "When SSH or RDP is open to the whole internet, automated bots can constantly "
                        "try to log in using weak passwords or stolen keys. If they succeed, an attacker "
                        "gets full control of the server. From there, they can run commands, install "
                        "malware, steal data, or pivot to other resources inside the VPC."
                    )
                    evidence = (
                        f"InstanceId={instance_id}, Name={name}, PublicIpAddress={public_ip}, "
                        f"SubnetId={subnet_id}, VpcId={vpc_id}, "
                        f"SecurityGroups={', '.join(sg_ids) if sg_ids else 'None'}; "
                        f"a security group allows 0.0.0.0/0 or ::/0 on a sensitive port."
                    )
                    add_finding(findings, "EC2-001", instance_id, reason, evidence, service="EC2")

                elif has_public_ip:
                    reason = (
                        "A public IP makes the instance reachable from the internet even when it does not "
                        "need direct exposure. That increases the attack surface and gives attackers a "
                        "target to scan, probe, and exploit."
                    )
                    evidence = (
                        f"InstanceId={instance_id}, Name={name}, PublicIpAddress={public_ip}, "
                        f"SubnetId={subnet_id}, VpcId={vpc_id}, "
                        f"SecurityGroups={', '.join(sg_ids) if sg_ids else 'None'}"
                    )
                    add_finding(findings, "EC2-002", instance_id, reason, evidence, service="EC2")

    except ClientError as e:
        print(f"[WARN] EC2 check skipped: {e.response['Error']['Code']}")


def check_unencrypted_ebs_attached(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        for vol in _iter_paged(ec2, "describe_volumes", "Volumes"):
            if vol.get("Encrypted", False):
                continue

            vol_id = vol.get("VolumeId", "Unknown")
            attached = vol.get("Attachments", [])
            if not attached:
                continue

            for att in attached:
                instance_id = att.get("InstanceId", "Unknown")
                device = att.get("Device", "Unknown")
                reason = (
                    "If an EC2 instance uses an unencrypted EBS volume, anyone who gets access to the "
                    "disk or a copied snapshot can read the data directly. That is dangerous for "
                    "databases, logs, and files stored on the instance."
                )
                evidence = (
                    f"VolumeId={vol_id}, InstanceId={instance_id}, Device={device}, "
                    f"Encrypted={vol.get('Encrypted')}, KmsKeyId={vol.get('KmsKeyId', 'None')}"
                )
                add_finding(findings, "EC2-003", instance_id, reason, evidence, service="EC2")

    except ClientError as e:
        print(f"[WARN] EC2 EBS encryption check skipped: {e.response['Error']['Code']}")


def check_security_group_world_open(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        for sg in _iter_paged(ec2, "describe_security_groups", "SecurityGroups"):
            sg_id = sg.get("GroupId", "Unknown")
            group_name = sg.get("GroupName", sg_id)
            vpc_id = sg.get("VpcId", "Unknown")

            for perm in sg.get("IpPermissions", []):
                fp = perm.get("FromPort")
                tp = perm.get("ToPort")
                proto = perm.get("IpProtocol", "unknown")

                world_open = False

                if proto == "-1":
                    world_open = (
                        any(ip.get("CidrIp") == "0.0.0.0/0" for ip in perm.get("IpRanges", [])) or
                        any(ip.get("CidrIpv6") == "::/0" for ip in perm.get("Ipv6Ranges", []))
                    )
                elif fp is not None and tp is not None and any(p in SENSITIVE_PORTS for p in range(fp, tp + 1)):
                    world_open = (
                        any(ip.get("CidrIp") == "0.0.0.0/0" for ip in perm.get("IpRanges", [])) or
                        any(ip.get("CidrIpv6") == "::/0" for ip in perm.get("Ipv6Ranges", []))
                    )

                if world_open:
                    reason = (
                        "A security group open to the whole internet on sensitive ports exposes the service "
                        "to brute-force attacks, scanning, and exploitation. If the service is compromised, "
                        "the attacker may gain a foothold in the environment."
                    )
                    evidence = (
                        f"GroupId={sg_id}, GroupName={group_name}, VpcId={vpc_id}, "
                        f"FromPort={fp}, ToPort={tp}, Source=0.0.0.0/0 or ::/0"
                    )
                    add_finding(findings, "EC2-004", sg_id, reason, evidence, service="EC2")
                    break

    except ClientError as e:
        print(f"[WARN] Security group world-open check skipped: {e.response['Error']['Code']}")


def run_ec2_checks(findings, add_finding):
    check_ec2(findings, add_finding)
    check_unencrypted_ebs_attached(findings, add_finding)
    check_security_group_world_open(findings, add_finding)