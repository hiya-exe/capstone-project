import boto3
import sqlite3
import json
from datetime import datetime
from botocore.exceptions import ClientError
from checks.vpc_checks import run_vpc_checks
from checks.s3_checks import run_s3_checks

# --------------------------------------------------
# CONFIG  — update these before running
# --------------------------------------------------
S3_BUCKET_NAME  = "capstone-s3-test-mehak-2026"
DB_PATH         = "capstone.db"
JSON_OUTPUT_PATH = "findings.json"
AWS_PROFILE     = "default"
AWS_REGION      = "ca-central-1"

# --------------------------------------------------
# RULE DATASET
# Maps rule IDs → metadata used by scanner + dashboard
# --------------------------------------------------
RULES = {
    "EC2-001": {
        "title":          "EC2 Instance with Public IP + Open Sensitive Port",
        "severity":       "Critical",
        "risk":           "Direct internet attack surface via sensitive port",
        "cis_mapping":    ["Control 4", "Control 12"],
        "recommendation": "Remove public exposure or restrict sensitive ports to trusted IP ranges only."
    },
    "EC2-002": {
        "title":          "EC2 Instance with Public IP (General Exposure)",
        "severity":       "Medium",
        "risk":           "Increased attack surface from unnecessary public IP",
        "cis_mapping":    ["Control 4"],
        "recommendation": "Avoid unnecessary public IP assignment. Use private subnets where possible."
    },
    "VPC-001": {
        "title": "VPC Flow Logs Disabled",
        "severity": "Medium",
        "risk": "Network activity may not be available for monitoring or investigation",
        "cis_mapping": ["Control 8", "Control 12"],
        "recommendation": "Enable VPC Flow Logs and send records to CloudWatch Logs or Amazon S3."
    },
    "VPC-002": {
        "title": "Public Route to Internet Gateway Detected",
        "severity": "High",
        "risk": "Associated subnets may expose resources directly to the internet",
        "cis_mapping": ["Control 4", "Control 12"],
        "recommendation": "Restrict Internet Gateway routes to intentionally public subnets and keep sensitive resources in private subnets."
    },
    "VPC-003": {
        "title": "Automatic Public IP Assignment Enabled",
        "severity": "High",
        "risk": "New resources may receive public IP addresses and become internet-accessible",
        "cis_mapping": ["Control 4", "Control 12"],
        "recommendation": "Disable automatic public IPv4 assignment for subnets that do not require public access."
    }
       "S3-001": {
        "title": "S3 Block Public Access Not Fully Enabled",
        "severity": "High",
        "risk": "The bucket may become publicly accessible through ACLs or bucket policies",
        "cis_mapping": ["Control 3", "Control 12"],
        "recommendation": "Enable all four S3 Block Public Access settings and review bucket ACLs and policies."
    },
    "S3-002": {
        "title": "S3 Default Encryption Not Configured",
        "severity": "High",
        "risk": "Objects may not have the required encryption protection at rest",
        "cis_mapping": ["Control 3"],
        "recommendation": "Enable default server-side encryption using SSE-S3 or AWS KMS."
    },
    "S3-003": {
        "title": "S3 Bucket Versioning Disabled",
        "severity": "Medium",
        "risk": "Deleted or overwritten objects may not be recoverable",
        "cis_mapping": ["Control 3", "Control 11"],
        "recommendation": "Enable bucket versioning and configure lifecycle rules for older versions."
    },
    "S3-004": {
        "title": "S3 Server Access Logging Disabled",
        "severity": "Medium",
        "risk": "Bucket access activity may not be available for investigation",
        "cis_mapping": ["Control 8"],
        "recommendation": "Enable server access logging and send logs to a separate protected bucket."
    },
    "S3-005": {
        "title": "S3 Bucket Policy Contains Public Principal",
        "severity": "Critical",
        "risk": "The bucket policy may allow unauthorized or public access",
        "cis_mapping": ["Control 3", "Control 6", "Control 12"],
        "recommendation": "Remove wildcard principals and restrict access to approved IAM identities."
    },
    "LOG-001": {
        "title":          "CloudTrail Not Configured",
        "severity":       "Medium",
        "risk":           "No audit logging — attacker activity goes undetected",
        "cis_mapping":    ["Control 8"],
        "recommendation": "Enable CloudTrail in all regions to capture and retain audit logs."
    }
}

# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def now_iso():
    return datetime.utcnow().isoformat()

def get_account_id():
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]

def infer_service_from_rule(rule_id):
    if rule_id.startswith("EC2"):
        return "EC2"
    if rule_id.startswith("VPC"):
        return "VPC"
    if rule_id.startswith("S3"):
        return "S3"
    if rule_id.startswith("LOG"):
        return "CloudTrail"
    return "Unknown"

def build_arn(service, resource):
    account_id = get_account_id()
    if service == "EC2":
        return f"arn:aws:ec2:{AWS_REGION}:{account_id}:instance/{resource}"
    if service == "S3":
        return f"arn:aws:s3:::{resource}"
    if service == "CloudTrail":
        return f"arn:aws:cloudtrail:{AWS_REGION}:{account_id}:trail/{resource}"
    if service == "VPC":
        if resource.startswith("vpc-"):
            return f"arn:aws:ec2:{AWS_REGION}:{account_id}:vpc/{resource}"
        if resource.startswith("subnet-"):
            return f"arn:aws:ec2:{AWS_REGION}:{account_id}:subnet/{resource}"
        if resource.startswith("rtb-"):
            return f"arn:aws:ec2:{AWS_REGION}:{account_id}:route-table/{resource}"
    return None

def add_finding(findings, rule_id, resource, description, service=None):
    rule = RULES[rule_id]
    findings.append({
        "finding_code":      rule_id,
        "title":             rule["title"],
        "resource":          resource,
        "description":       description,
        "severity":          rule["severity"],
        "compliance_status": "FAIL",
        "remediation":       rule["recommendation"],
        "risk":              rule["risk"],
        "cis_mapping":       rule["cis_mapping"],
        "service":           service or infer_service_from_rule(rule_id),
        "detected_at":       now_iso()
    })

def summarize_findings(findings):
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f["severity"]
        if sev in summary:
            summary[sev] += 1
    return summary

# --------------------------------------------------
# AWS CHECKS
# --------------------------------------------------
def check_insecure_network_exposure(ec2_client, security_group_ids):
    """Return True if any SG allows 0.0.0.0/0 on a sensitive port."""
    if not security_group_ids:
        return False

    sensitive_ports = {22, 3389, 3306, 5432, 1433, 1521, 21, 23}
    response = ec2_client.describe_security_groups(GroupIds=security_group_ids)

    for sg in response.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort")
            to_port   = perm.get("ToPort")
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    if from_port is not None and to_port is not None:
                        for port in range(from_port, to_port + 1):
                            if port in sensitive_ports:
                                return True
                    return True
    return False

def check_ec2(findings):
    """EC2-001: public IP + insecure SG  |  EC2-002: public IP only."""
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    response = ec2.describe_instances()

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instance_id    = instance.get("InstanceId", "Unknown")
            has_public_ip  = "PublicIpAddress" in instance
            sg_ids         = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
            insecure_net   = check_insecure_network_exposure(ec2, sg_ids)

            if has_public_ip and insecure_net:
                add_finding(
                    findings, "EC2-001", instance_id,
                    "Instance has a public IP and its security group allows "
                    "unrestricted internet exposure on a sensitive port.",
                    service="EC2"
                )
            elif has_public_ip:
                add_finding(
                    findings, "EC2-002", instance_id,
                    "Instance has a public IP, creating general internet exposure.",
                    service="EC2"
                )

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        msg = (
            "S3 bucket has no public access block configuration."
            if error_code == "NoSuchPublicAccessBlockConfiguration"
            else f"Unable to evaluate S3 bucket: {error_code}"
        )
        add_finding(findings, "S3-001", bucket_name, msg, service="S3")

def check_cloudtrail(findings):
    """LOG-001: No CloudTrail trail configured."""
    cloudtrail = boto3.client("cloudtrail", region_name=AWS_REGION)
    response   = cloudtrail.describe_trails()
    if not response.get("trailList"):
        add_finding(
            findings, "LOG-001", "AWS Account",
            "No CloudTrail trail is configured.",
            service="CloudTrail"
        )

def run_scan():
    findings = []
    check_ec2(findings)
    check_s3(findings, S3_BUCKET_NAME)
    check_cloudtrail(findings)
     run_vpc_checks(
        findings=findings,
        add_finding=lambda rule_id, resource, description: add_finding(
            findings=findings,
            rule_id=rule_id,
            resource=resource,
            description=description,
            service="VPC"
        ),
        region=AWS_REGION
    )
     run_s3_checks(
        findings=findings,
        add_finding=lambda rule_id, resource, description: add_finding(
            findings=findings,
            rule_id=rule_id,
            resource=resource,
            description=description,
            service="S3"
        ),
        region=AWS_REGION
    )


    return findings

# --------------------------------------------------
# DATABASE  — schema helpers
# --------------------------------------------------
def get_or_create_cis_control(cursor, control_code):
    cursor.execute(
        "SELECT cis_id FROM cis_controls WHERE control_code = ?",
        (control_code,)
    )
    row = cursor.fetchone()
    if row:
        return row[0]
    cursor.execute(
        "INSERT INTO cis_controls (cis_version, control_code, control_title) VALUES (?, ?, ?)",
        ("CIS v8", control_code, control_code)
    )
    return cursor.lastrowid

def insert_scan(cursor, account_id):
    ts = now_iso()
    cursor.execute(
        """
        INSERT INTO scans (
            aws_profile, aws_account_id, region, service,
            scan_type, started_at, completed_at, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (AWS_PROFILE, account_id, AWS_REGION,
         "Multi-Service", "PoC Manual Scan", ts, ts, "completed")
    )
    return cursor.lastrowid

def insert_resource(cursor, scan_id, finding):
    cursor.execute(
        """
        INSERT INTO resources (
            scan_id, aws_resource_id, resource_name,
            resource_type, service, region, arn
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            finding["resource"],
            finding["resource"],
            finding["service"],
            finding["service"],
            AWS_REGION,
            build_arn(finding["service"], finding["resource"])
        )
    )
    return cursor.lastrowid

def insert_finding(cursor, scan_id, resource_id, finding):
    cursor.execute(
        """
        INSERT INTO findings (
            scan_id, resource_id, finding_code, title,
            description, severity, compliance_status,
            remediation, detected_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id, resource_id,
            finding["finding_code"], finding["title"],
            finding["description"],  finding["severity"],
            finding["compliance_status"], finding["remediation"],
            finding["detected_at"]
        )
    )
    return cursor.lastrowid

def insert_finding_cis_mappings(cursor, finding_id, cis_controls):
    for control_code in cis_controls:
        cis_id = get_or_create_cis_control(cursor, control_code)
        cursor.execute(
            "INSERT INTO finding_cis_mappings (finding_id, cis_id) VALUES (?, ?)",
            (finding_id, cis_id)
        )

def save_findings_to_db(findings):
    conn   = sqlite3.connect(DB_PATH, timeout=10)
    cursor = conn.cursor()

    account_id = get_account_id()
    scan_id    = insert_scan(cursor, account_id)

    for finding in findings:
        resource_id = insert_resource(cursor, scan_id, finding)
        finding_id  = insert_finding(cursor, scan_id, resource_id, finding)
        insert_finding_cis_mappings(cursor, finding_id, finding["cis_mapping"])

    try:
        conn.commit()
    finally:
        conn.close()

    print(f"Findings saved to database: {DB_PATH}  (scan_id={scan_id})")

# --------------------------------------------------
# JSON EXPORT
# --------------------------------------------------
def save_findings_to_json(findings):
    output = {
        "scan_time":      now_iso(),
        "aws_profile":    AWS_PROFILE,
        "region":         AWS_REGION,
        "total_findings": len(findings),
        "summary":        summarize_findings(findings),
        "findings":       findings
    }
    with open(JSON_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    print(f"Findings exported to {JSON_OUTPUT_PATH}")

# --------------------------------------------------
# CONSOLE REPORT
# --------------------------------------------------
def print_findings(findings):
    print("\n=== CloudSentinel — AWS Security Posture Assessment ===\n")
    if not findings:
        print("No findings detected.")
        return

    for f in findings:
        print(f"Rule ID        : {f['finding_code']}")
        print(f"Title          : {f['title']}")
        print(f"Resource       : {f['resource']}")
        print(f"Status         : {f['compliance_status']}")
        print(f"Severity       : {f['severity']}")
        print(f"Risk           : {f['risk']}")
        print(f"CIS Mapping    : {', '.join(f['cis_mapping'])}")
        print(f"Details        : {f['description']}")
        print(f"Recommendation : {f['remediation']}")
        print("-" * 60)

    summary = summarize_findings(findings)
    print(f"\nTotal Findings : {len(findings)}")
    for sev, count in summary.items():
        print(f"  {sev:<12}: {count}")

# --------------------------------------------------
# ENTRY POINT
# --------------------------------------------------
if __name__ == "__main__":
    findings = run_scan()
    print_findings(findings)
    save_findings_to_db(findings)
    save_findings_to_json(findings)
