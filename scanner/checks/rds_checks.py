import boto3
from botocore.exceptions import ClientError

from scanner.db_profiles import infer_environment

AWS_REGION = "ca-central-1"


def _db_context(db):
    tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
    return {
        "engine": db.get("Engine", "unknown"),
        "environment": infer_environment(db.get("DBInstanceIdentifier"), tags),
    }


def _check_public_rds(findings, add_finding):
    rds = boto3.client("rds", region_name=AWS_REGION)
    try:
        resp = rds.describe_db_instances()
        for db in resp.get("DBInstances", []):
            if not db.get("PubliclyAccessible", False):
                continue
            db_id = db["DBInstanceIdentifier"]
            endpoint = db.get("Endpoint", {})
            port = endpoint.get("Port", "Unknown")
            sg_ids = [sg["VpcSecurityGroupId"] for sg in db.get("VpcSecurityGroups", [])]
            reason = "A publicly accessible database can be reached directly from the internet. Attackers can scan the port, brute-force credentials, or try database engine exploits without first compromising another host."
            evidence = f"DBInstanceIdentifier={db_id}, PubliclyAccessible={db.get('PubliclyAccessible')}, Endpoint={endpoint.get('Address')}:{port}, VpcSecurityGroups={', '.join(sg_ids) if sg_ids else 'None'}"
            add_finding(findings, "RDS-001", db_id, reason, evidence, service="RDS", db_context=_db_context(db))
    except ClientError as e:
        print(f"[WARN] RDS public access check skipped: {e.response['Error']['Code']}")


def _check_rds_encryption(findings, add_finding):
    rds = boto3.client("rds", region_name=AWS_REGION)
    try:
        resp = rds.describe_db_instances()
        for db in resp.get("DBInstances", []):
            if db.get("StorageEncrypted", False):
                continue
            db_id = db["DBInstanceIdentifier"]
            reason = "Unencrypted database storage and snapshots can expose sensitive data if they are copied, shared, or leaked. Anyone who can access the storage can read the data directly."
            evidence = f"DBInstanceIdentifier={db_id}, StorageEncrypted={db.get('StorageEncrypted')}, KmsKeyId={db.get('KmsKeyId', 'None')}"
            add_finding(findings, "RDS-002", db_id, reason, evidence, service="RDS", db_context=_db_context(db))
    except ClientError as e:
        print(f"[WARN] RDS encryption check skipped: {e.response['Error']['Code']}")


def _check_backup_retention(findings, add_finding):
    rds = boto3.client("rds", region_name=AWS_REGION)
    try:
        resp = rds.describe_db_instances()
        for db in resp.get("DBInstances", []):
            retention = db.get("BackupRetentionPeriod", 0)
            if retention and retention >= 7:
                continue
            db_id = db["DBInstanceIdentifier"]
            reason = "If backups are kept for too few days, there may be no clean recovery point after ransomware, deletion, or corruption. Recovery becomes much harder when the window is too short."
            evidence = f"DBInstanceIdentifier={db_id}, BackupRetentionPeriod={retention}, PreferredBackupWindow={db.get('PreferredBackupWindow', 'None')}"
            add_finding(findings, "RDS-003", db_id, reason, evidence, service="RDS", db_context=_db_context(db))
    except ClientError as e:
        print(f"[WARN] RDS backup retention check skipped: {e.response['Error']['Code']}")


def _check_auto_minor_version_upgrade(findings, add_finding):
    rds = boto3.client("rds", region_name=AWS_REGION)
    try:
        resp = rds.describe_db_instances()
        for db in resp.get("DBInstances", []):
            if db.get("AutoMinorVersionUpgrade", True):
                continue
            db_id = db["DBInstanceIdentifier"]
            reason = "When automatic minor version upgrades are disabled, security patches and bug fixes may never be applied. That leaves the database exposed to known vulnerabilities for longer."
            evidence = f"DBInstanceIdentifier={db_id}, AutoMinorVersionUpgrade={db.get('AutoMinorVersionUpgrade')}"
            add_finding(findings, "RDS-004", db_id, reason, evidence, service="RDS", db_context=_db_context(db))
    except ClientError as e:
        print(f"[WARN] RDS auto minor version check skipped: {e.response['Error']['Code']}")


def run_rds_checks(findings, add_finding):
    _check_public_rds(findings, add_finding)
    _check_rds_encryption(findings, add_finding)
    _check_backup_retention(findings, add_finding)
    _check_auto_minor_version_upgrade(findings, add_finding)