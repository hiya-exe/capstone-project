# s3_checks.py
import boto3
import json
from botocore.exceptions import ClientError


def add_finding(findings, check_id, severity, bucket_name, issue, recommendation):
    findings.append({
        "service": "S3",
        "check_id": check_id,
        "severity": severity,
        "resource": bucket_name,
        "issue": issue,
        "recommendation": recommendation
    })


def check_s3_buckets():
    s3 = boto3.client("s3")
    findings = []

    response = s3.list_buckets()
    buckets = response.get("Buckets", [])

    for bucket in buckets:
        bucket_name = bucket["Name"]

        check_public_access_block(s3, bucket_name, findings)  #temporary checklist for sample buckets.
        check_bucket_policy_status(s3, bucket_name, findings)
        check_object_ownership(s3, bucket_name, findings)
        check_versioning(s3, bucket_name, findings)
        check_server_access_logging(s3, bucket_name, findings)
        check_default_encryption(s3, bucket_name, findings)

    return findings
