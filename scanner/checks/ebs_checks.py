import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"

 
def _iter_paged(client, method_name, result_key, **kwargs):
    paginator = client.get_paginator(method_name)
    for page in paginator.paginate(**kwargs):
        for item in page.get(result_key, []):
            yield item


def _check_unencrypted_volumes(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        for vol in _iter_paged(ec2, "describe_volumes", "Volumes"):
            if vol.get("Encrypted", False):
                continue
            vol_id = vol.get("VolumeId", "Unknown")
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
        print(f"[SKIP] EBS encryption-by-default check skipped: {e.response['Error']['Code']}")


def _check_snapshots_shared_externally(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        for snap in _iter_paged(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
            snap_id = snap.get("SnapshotId", "Unknown")
            vol_id = snap.get("VolumeId", "Unknown")
            encrypted = snap.get("Encrypted", False)
            try:
                attr_resp = ec2.describe_snapshot_attribute(SnapshotId=snap_id, Attribute="createVolumePermission")
            except ClientError:
                continue
            permissions = attr_resp.get("CreateVolumePermissions", [])
            external_accounts = [p["UserId"] for p in permissions if p.get("UserId")]
            if not external_accounts:
                continue
            reason = "This snapshot is shared with one or more external AWS account IDs. Shared snapshots can expose sensitive data if shared too broadly or forgotten. If the snapshot is not encrypted, anyone with access can read the raw data directly."
            evidence = f"SnapshotId={snap_id}, VolumeId={vol_id}, Encrypted={encrypted}, KmsKeyId={snap.get('KmsKeyId', 'None')}, SharedWithAccounts={', '.join(external_accounts)}"
            add_finding(findings, "EBS-003", snap_id, reason, evidence, service="EBS")
    except ClientError as e:
        print(f"[WARN] EBS snapshot external share check skipped: {e.response['Error']['Code']}")


def _check_public_snapshots(findings, add_finding):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    try:
        for snap in _iter_paged(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
            snap_id = snap.get("SnapshotId", "Unknown")
            vol_id = snap.get("VolumeId", "Unknown")
            encrypted = snap.get("Encrypted", False)
            description = snap.get("Description", "")
            try:
                attr_resp = ec2.describe_snapshot_attribute(SnapshotId=snap_id, Attribute="createVolumePermission")
            except ClientError:
                continue
            permissions = attr_resp.get("CreateVolumePermissions", [])
            is_public = any(p.get("Group") == "all" for p in permissions)
            if not is_public:
                continue
            reason = "This snapshot is publicly accessible to any AWS account. Public snapshots can be browsed and copied by anyone. If they contain real application data, credentials, or internal code, this is a direct and critical data exposure."
            evidence = f"SnapshotId={snap_id}, VolumeId={vol_id}, Encrypted={encrypted}, KmsKeyId={snap.get('KmsKeyId', 'None')}, Visibility=public, Description={description!r}"
            add_finding(findings, "EBS-004", snap_id, reason, evidence, service="EBS")
    except ClientError as e:
        print(f"[WARN] EBS public snapshot check skipped: {e.response['Error']['Code']}")


def run_ebs_checks(findings, add_finding):
    _check_unencrypted_volumes(findings, add_finding)
    _check_ebs_encryption_by_default(findings, add_finding)
    _check_snapshots_shared_externally(findings, add_finding)
    _check_public_snapshots(findings, add_finding)
