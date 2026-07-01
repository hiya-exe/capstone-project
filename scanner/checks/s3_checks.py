import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"


def _iter_buckets(s3):
    try:
        return s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"[WARN] S3 list_buckets failed: {e.response['Error']['Code']}")
        return []


def _check_block_public_access(findings, add_finding, s3, bucket_name):
    try:
        config = s3.get_public_access_block(Bucket=bucket_name).get(
            "PublicAccessBlockConfiguration", {}
        )
        disabled = [k for k, v in config.items() if not v]
        if disabled:
            reason = (
                "One or more S3 Block Public Access settings are disabled. "
                "A single misconfigured bucket policy or ACL could make the bucket "
                "publicly accessible and expose its contents to anyone on the internet."
            )
            evidence = f"Bucket={bucket_name}, DisabledSettings={', '.join(disabled)}"
            add_finding(findings, "S3-001", bucket_name, reason, evidence, service="S3")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            reason = (
                "The bucket has no Block Public Access configuration at all. "
                "Without it, bucket policies or ACLs could expose the bucket publicly."
            )
            evidence = f"Bucket={bucket_name}, PublicAccessBlockConfiguration=NotFound"
            add_finding(findings, "S3-001", bucket_name, reason, evidence, service="S3")


def _check_default_encryption(findings, add_finding, s3, bucket_name):
    try:
        rules = s3.get_bucket_encryption(Bucket=bucket_name).get(
            "ServerSideEncryptionConfiguration", {}
        ).get("Rules", [])
        if not rules:
            raise ValueError("no rules")
    except (ClientError, ValueError) as e:
        code = getattr(e, "response", {}).get("Error", {}).get("Code", "") if isinstance(e, ClientError) else ""
        if not code or code == "ServerSideEncryptionConfigurationNotFoundError":
            reason = (
                "Default server-side encryption is not configured on this bucket. "
                "New objects may be stored without encryption, failing compliance "
                "requirements and leaving data weaker at rest."
            )
            evidence = f"Bucket={bucket_name}, DefaultEncryption=NotConfigured"
            add_finding(findings, "S3-002", bucket_name, reason, evidence, service="S3")


def _check_versioning(findings, add_finding, s3, bucket_name):
    try:
        status = s3.get_bucket_versioning(Bucket=bucket_name).get("Status", "Disabled")
        if status != "Enabled":
            reason = (
                "S3 bucket versioning is not enabled. Accidental deletion or "
                "overwrite of objects cannot be undone, and ransomware that "
                "overwrites objects may cause permanent data loss."
            )
            evidence = f"Bucket={bucket_name}, VersioningStatus={status}"
            add_finding(findings, "S3-003", bucket_name, reason, evidence, service="S3")
    except ClientError:
        pass


def _check_access_logging(findings, add_finding, s3, bucket_name):
    try:
        logging_enabled = s3.get_bucket_logging(Bucket=bucket_name).get("LoggingEnabled")
        if not logging_enabled:
            reason = (
                "S3 server access logging is not enabled. Requests to the bucket "
                "are not recorded, making it harder to investigate unauthorized access "
                "or anomalous activity after the fact."
            )
            evidence = f"Bucket={bucket_name}, AccessLogging=Disabled"
            add_finding(findings, "S3-004", bucket_name, reason, evidence, service="S3")
    except ClientError:
        pass


def _check_bucket_policy_public(findings, add_finding, s3, bucket_name):
    try:
        policy = s3.get_bucket_policy(Bucket=bucket_name).get("Policy", "")
        public_signals = ['"Principal":"*"', '"Principal": "*"', '"AWS":"*"', '"AWS": "*"']
        if any(sig in policy for sig in public_signals):
            reason = (
                "The bucket policy contains a wildcard principal, which may allow "
                "public or overly broad access to the bucket's contents. "
                "Unauthorized users could read, list, or modify objects."
            )
            evidence = f"Bucket={bucket_name}, BucketPolicy=WildcardPrincipalDetected"
            add_finding(findings, "S3-005", bucket_name, reason, evidence, service="S3")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
            pass


def run_s3_checks(findings, add_finding):
    s3 = boto3.client("s3", region_name=AWS_REGION)
    for bucket in _iter_buckets(s3):
        name = bucket.get("Name")
        if not name:
            continue
        _check_block_public_access(findings, add_finding, s3, name)
        _check_default_encryption(findings, add_finding, s3, name)
        _check_versioning(findings, add_finding, s3, name)
        _check_access_logging(findings, add_finding, s3, name)
        _check_bucket_policy_public(findings, add_finding, s3, name)
