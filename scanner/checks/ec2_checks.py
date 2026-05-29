import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"

def _sg_allows_world_on_port(ec2_client, sg_ids, target_ports):
    if not sg_ids:
        return False
    try:
        response = ec2_client.describe_security_groups(GroupIds=sg_ids)
        for sg in response.get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                fp = perm.get("FromPort")
                tp = perm.get("ToPort")
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") != "0.0.0.0/0":
                        continue
                    if fp is not None and tp is not None:
                        for port in range(fp, tp + 1):
                            if port in target_ports:
                                return True
                    else:
                        return True
        return False
    except ClientError:
        return False

def check_ec2(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    sensitive_ports = {22, 3389, 3306, 5432, 1433, 1521, 21, 23}
    try:
        response = ec2.describe_instances()
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "Unknown")
                public_ip = instance.get("PublicIpAddress", "None")
                has_public_ip = "PublicIpAddress" in instance
                sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                subnet_id = instance.get("SubnetId", "Unknown")
                vpc_id = instance.get("VpcId", "Unknown")
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                name = tags.get("Name", instance_id)
                sensitive_open = _sg_allows_world_on_port(ec2, sg_ids, sensitive_ports)

                if has_public_ip and sensitive_open:
                    reason = "When SSH or RDP is open to the whole internet, automated bots can constantly try to log in using weak passwords or stolen keys. If they succeed, an attacker gets full control of the server. From there, they can run commands, install malware, steal data, or pivot to other resources inside the VPC."
                    evidence = f"InstanceId={instance_id}, Name={name}, PublicIpAddress={public_ip}, SubnetId={subnet_id}, VpcId={vpc_id}, SecurityGroups={', '.join(sg_ids) if sg_ids else 'None'}; a security group allows 0.0.0.0/0 on a sensitive port."
                    add_finding(findings, "EC2-001", instance_id, reason, evidence, service="EC2")
                elif has_public_ip:
                    reason = "A public IP makes the instance reachable from the internet even when it does not need direct exposure. That increases the attack surface and gives attackers a target to scan, probe, and exploit."
                    evidence = f"InstanceId={instance_id}, Name={name}, PublicIpAddress={public_ip}, SubnetId={subnet_id}, VpcId={vpc_id}, SecurityGroups={', '.join(sg_ids) if sg_ids else 'None'}"
                    add_finding(findings, "EC2-002", instance_id, reason, evidence, service="EC2")
    except ClientError as e:
        print(f"[WARN] EC2 check skipped: {e.response['Error']['Code']}")

def check_unencrypted_ebs_attached(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        response = ec2.describe_volumes()
        for vol in response.get("Volumes", []):
            if vol.get("Encrypted", False):
                continue
            vol_id = vol.get("VolumeId", "Unknown")
            attached = vol.get("Attachments", [])
            if not attached:
                continue
            for att in attached:
                instance_id = att.get("InstanceId", "Unknown")
                device = att.get("Device", "Unknown")
                reason = "If an EC2 instance uses an unencrypted EBS volume, anyone who gets access to the disk or a copied snapshot can read the data directly. That is dangerous for databases, logs, and files stored on the instance."
                evidence = f"VolumeId={vol_id}, InstanceId={instance_id}, Device={device}, Encrypted={vol.get('Encrypted')}, KmsKeyId={vol.get('KmsKeyId', 'None')}"
                add_finding(findings, "EC2-003", instance_id, reason, evidence, service="EC2")
    except ClientError as e:
        print(f"[WARN] EC2 EBS encryption check skipped: {e.response['Error']['Code']}")

def check_security_group_world_open(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    target_ports = {22, 3389, 3306, 5432, 1433, 1521, 21, 23}
    try:
        response = ec2.describe_security_groups()
        for sg in response.get("SecurityGroups", []):
            sg_id = sg.get("GroupId", "Unknown")
            group_name = sg.get("GroupName", sg_id)
            vpc_id = sg.get("VpcId", "Unknown")
            for perm in sg.get("IpPermissions", []):
                fp = perm.get("FromPort")
                tp = perm.get("ToPort")
                proto = perm.get("IpProtocol", "unknown")
                if proto == "-1":
                    cidrs = [ip.get("CidrIp") for ip in perm.get("IpRanges", []) if ip.get("CidrIp") == "0.0.0.0/0"]
                    if cidrs:
                        reason = "A security group that allows all traffic from the whole internet creates a broad attack surface. Attackers can probe every exposed service and look for a weak point to exploit."
                        evidence = f"GroupId={sg_id}, GroupName={group_name}, VpcId={vpc_id}, IpProtocol=all, Source=0.0.0.0/0"
                        add_finding(findings, "EC2-004", sg_id, reason, evidence, service="EC2")
                        break
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") != "0.0.0.0/0":
                        continue
                    if fp is not None and tp is not None and any(p in target_ports for p in range(fp, tp + 1)):
                        reason = "A security group open to the whole internet on sensitive ports exposes the service to brute-force attacks, scanning, and exploitation. If the service is compromised, the attacker may gain a foothold in the environment."
                        evidence = f"GroupId={sg_id}, GroupName={group_name}, VpcId={vpc_id}, FromPort={fp}, ToPort={tp}, Source=0.0.0.0/0"
                        add_finding(findings, "EC2-004", sg_id, reason, evidence, service="EC2")
                        break
    except ClientError as e:
        print(f"[WARN] Security group world-open check skipped: {e.response['Error']['Code']}")

def run_ec2_checks(findings, add_finding):
    check_ec2(findings, add_finding)
    check_unencrypted_ebs_attached(findings, add_finding)
    check_security_group_world_open(findings, add_finding)
