import boto3
from botocore.exceptions import ClientError


# ------------------------------------------------------------
# S3 CHECKS
# Rule IDs: S3-001 .. S3-005
# ------------------------------------------------------------

def _build_desc(issue_lines, evidence_lines, impact_lines, fix_lines):
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


def run_s3_checks(findings, add_finding, region):
    """
    Runs S3 security checks using the project's add_finding callback.

    Expected callback:
        add_finding(rule_id: str, resource: str, description: str)
    """

    s3 = boto3.client("s3", region_name=region)

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as error:
        print(f"Unable to list S3 buckets: {error}")
        return

    for bucket in buckets:
        bucket_name = bucket.get("Name")

        if not bucket_name:
            continue

        # --------------------------------------------------------
        # S3-001: Block Public Access not fully enabled
        # --------------------------------------------------------
        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
            config = response.get(
                "PublicAccessBlockConfiguration",
                {}
            )

            required_settings = {
                "BlockPublicAcls": config.get("BlockPublicAcls", False),
                "IgnorePublicAcls": config.get("IgnorePublicAcls", False),
                "BlockPublicPolicy": config.get("BlockPublicPolicy", False),
                "RestrictPublicBuckets": config.get(
                    "RestrictPublicBuckets",
                    False
                )
            }

            disabled_settings = [
                setting
                for setting, enabled in required_settings.items()
                if not enabled
            ]

            if disabled_settings:
                _add(
                    findings,
                    add_finding,
                    "S3-001",
                    bucket_name,
                    issue_lines=[
                        "S3 Block Public Access is not fully enabled.",
                        "One or more public-access protection settings are disabled."
                    ],
                    evidence_lines=[
                        f"Bucket: {bucket_name}",
                        f"Disabled settings: {', '.join(disabled_settings)}"
                    ],
                    impact_lines=[
                        "The bucket may become publicly accessible through an ACL or bucket policy.",
                        "Sensitive files could be exposed to unauthorized users.",
                        "Accidental configuration changes could create public data exposure."
                    ],
                    fix_lines=[
                        "Enable all four S3 Block Public Access settings.",
                        "Review existing bucket policies and ACLs.",
                        "Allow public access only when there is a documented business requirement."
                    ]
                )

        except ClientError as error:
            error_code = error.response.get("Error", {}).get(
                "Code",
                "Unknown"
            )

            if error_code == "NoSuchPublicAccessBlockConfiguration":
                _add(
                    findings,
                    add_finding,
                    "S3-001",
                    bucket_name,
                    issue_lines=[
                        "The bucket has no Block Public Access configuration."
                    ],
                    evidence_lines=[
                        f"Bucket: {bucket_name}",
                        "Public Access Block configuration: Not found"
                    ],
                    impact_lines=[
                        "The bucket may be exposed through public ACLs or policies.",
                        "Data could be accessed without authorization."
                    ],
                    fix_lines=[
                        "Enable all S3 Block Public Access settings.",
                        "Review the bucket policy and object ACLs."
                    ]
                )

        # --------------------------------------------------------
        # S3-002: Default encryption not configured
        # --------------------------------------------------------
        try:
            encryption = s3.get_bucket_encryption(
                Bucket=bucket_name
            )

            rules = encryption.get(
                "ServerSideEncryptionConfiguration",
                {}
            ).get("Rules", [])

            if not rules:
                raise ValueError("No encryption rules found")

        except (ClientError, ValueError) as error:
            error_code = ""

            if isinstance(error, ClientError):
                error_code = error.response.get("Error", {}).get(
                    "Code",
                    ""
                )

            if (
                not error_code
                or error_code
                == "ServerSideEncryptionConfigurationNotFoundError"
            ):
                _add(
                    findings,
                    add_finding,
                    "S3-002",
                    bucket_name,
                    issue_lines=[
                        "Default server-side encryption is not configured.",
                        "New objects may not receive the expected encryption protection."
                    ],
                    evidence_lines=[
                        f"Bucket: {bucket_name}",
                        "Default encryption configuration: Not found"
                    ],
                    impact_lines=[
                        "Stored data may not meet organizational encryption requirements.",
                        "Sensitive information could have weaker protection at rest.",
                        "The bucket may fail security or compliance expectations."
                    ],
                    fix_lines=[
                        "Enable default encryption using SSE-S3 or AWS KMS.",
                        "Use a customer-managed KMS key when stronger control is required.",
                        "Review existing objects to confirm their encryption status."
                    ]
                )

        # --------------------------------------------------------
        # S3-003: Versioning disabled
        # --------------------------------------------------------
        try:
            versioning = s3.get_bucket_versioning(
                Bucket=bucket_name
            )

            status = versioning.get("Status", "Disabled")

            if status != "Enabled":
                _add(
                    findings,
                    add_finding,
                    "S3-003",
                    bucket_name,
                    issue_lines=[
                        "S3 bucket versioning is not enabled.",
                        "Deleted or overwritten objects may be difficult to recover."
                    ],
                    evidence_lines=[
                        f"Bucket: {bucket_name}",
                        f"Versioning status: {status}"
                    ],
                    impact_lines=[
                        "Accidental deletion or modification may cause permanent data loss.",
                        "Ransomware or malicious changes may be harder to recover from.",
                        "Previous versions of important files may not be available."
                    ],
                    fix_lines=[
                        "Enable S3 bucket versioning.",
                        "Use lifecycle rules to manage older object versions.",
                        "Consider MFA Delete for highly sensitive buckets."
                    ]
                )

        except ClientError:
            pass

        # --------------------------------------------------------
        # S3-004: Access logging disabled
        # --------------------------------------------------------
        try:
            logging_config = s3.get_bucket_logging(
                Bucket=bucket_name
            )

            logging_enabled = logging_config.get(
                "LoggingEnabled"
            )

            if not logging_enabled:
                _add(
                    findings,
                    add_finding,
                    "S3-004",
                    bucket_name,
                    issue_lines=[
                        "S3 server access logging is not enabled.",
                        "Requests made to the bucket may not be recorded."
                    ],
                    evidence_lines=[
                        f"Bucket: {bucket_name}",
                        "LoggingEnabled: False"
                    ],
                    impact_lines=[
                        "Unauthorized access may be harder to investigate.",
                        "The organization may lack detailed request records.",
                        "Troubleshooting and forensic analysis become more difficult."
                    ],
                    fix_lines=[
                        "Enable server access logging for the bucket.",
                        "Send logs to a separate protected logging bucket.",
                        "Apply lifecycle rules to control log-storage costs."
                    ]
                )

        except ClientError:
            pass

        # --------------------------------------------------------
        # S3-005: Bucket policy allows public principal
        # --------------------------------------------------------
        try:
            policy_response = s3.get_bucket_policy(
                Bucket=bucket_name
            )

            policy_text = policy_response.get("Policy", "")

            public_signals = [
                '"Principal":"*"',
                '"Principal": "*"',
                '"AWS":"*"',
                '"AWS": "*"'
            ]

            if any(signal in policy_text for signal in public_signals):
                _add(
                    findings,
                    add_finding,
                    "S3-005",
                    bucket_name,
                    issue_lines=[
                        "The S3 bucket policy contains a wildcard principal.",
                        "The policy may allow public or overly broad access."
                    ],
                    evidence_lines=[
                        f"Bucket: {bucket_name}",
                        "Wildcard principal detected in bucket policy."
                    ],
                    impact_lines=[
                        "Unauthorized users may be able to access bucket data.",
                        "Sensitive files may be exposed publicly.",
                        "A broad policy increases the bucket's attack surface."
                    ],
                    fix_lines=[
                        "Replace wildcard principals with specific IAM roles or accounts.",
                        "Apply least-privilege permissions.",
                        "Use policy conditions to limit access when appropriate.",
                        "Retest public access after updating the policy."
                    ]
                )

        except ClientError as error:
            error_code = error.response.get("Error", {}).get(
                "Code",
                ""
            )

            if error_code != "NoSuchBucketPolicy":
                pass
