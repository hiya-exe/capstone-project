import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"

def _check_unencrypted_volumes(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        resp = ec2.describe_volumes()
        for vol in resp.get("Volumes", []):
            if vol.get("Encrypted", False):
                continue
            vol_id = vol["VolumeId"]
            attached = [a.get("InstanceId", "Unknown") for a in vol.get("Attachments", [])]
            reason = "If an EBS volume is not encrypted, anyone who obtains the volume or a snapshot can read the data directly. That is dangerous for backups, databases, and files that contain sensitive information."
            evidence = f"VolumeId={vol_id}, Encrypted={vol.get('Encrypted')}, KmsKeyId={vol.get('KmsKeyId', 'None')}, AttachedInstances={', '.join(attached) if attached else 'None'}"
            add_finding(findings, "EBS-001", vol_id, reason, evidence, service="EBS")
    except ClientError as e:
        print(f"[WARN] EBS volume check skipped: {e.response['Error']['Code']}")

def _check_ebs_encryption_by_default(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        resp = ec2.get_ebs_encryption_by_default()
        flag = resp.get("EbsEncryptionByDefault", False)
        if flag:
            return
        reason = "If encryption by default is turned off, new volumes can be created unencrypted by mistake. That means the security of future data depends on every user remembering to enable encryption manually."
        evidence = f"EbsEncryptionByDefault={flag}"
        add_finding(findings, "EBS-002", "AWS Account", reason, evidence, service="EBS")
    except ClientError as e:
        print(f"[WARN] EBS encryption-by-default check skipped: {e.response['Error']['Code']}")

def run_ebs_checks(findings, add_finding):
    _check_unencrypted_volumes(findings, add_finding)
    _check_ebs_encryption_by_default(findings, add_finding)
