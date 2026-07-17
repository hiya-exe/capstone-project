import sys
import boto3
import db  # MySQL connection wrapper (see db.py)
import json
from datetime import datetime
from botocore.exceptions import ClientError

from scanner.checks.ec2_checks import run_ec2_checks
from scanner.checks.iam_checks import run_iam_checks
from scanner.checks.rds_checks import run_rds_checks
from scanner.checks.ebs_checks import run_ebs_checks
from scanner.checks.s3_checks import run_s3_checks
from scanner.checks.sg_checks import run_sg_checks
from scanner.checks.vpc_checks import run_vpc_checks
from scanner.checks.kms_checks import run_kms_checks
from scanner.profiles import get_profile, GENERAL_PROFILE, validate_profiles
from scanner.db_profiles import adjust_severity, get_engine_note

JSON_OUTPUT_PATH = "findings.json"
AWS_PROFILE = "default"
AWS_REGION = "ca-central-1"
BUSINESS_PROFILE = sys.argv[1] if len(sys.argv) > 1 else GENERAL_PROFILE

RULES = {
    "EC2-001": {
        "title": "Public IP + Open Admin Port",
        "severity": "Critical",
        "user_impact": "Anyone on the internet can try to log in to this server right now.",
        "risk": "This server has a public IP and its security group lets the whole internet reach an admin port like SSH or RDP. Automated bots will hammer this port around the clock with stolen passwords and keys. One weak credential gives an attacker full control of the server, from which they can run commands, install malware, steal data, and pivot deeper into your VPC.",
        "remediation": "Limit SSH/RDP to specific admin IP addresses, or remove direct exposure entirely by using a VPN, bastion host, or AWS Systems Manager Session Manager.",
        "cis_mapping": "CIS 4.1, CIS 12.1",
    },
    "EC2-002": {
        "title": "Unnecessary Public IP",
        "severity": "High",
        "user_impact": "This server is exposed to the internet for no clear reason.",
        "risk": "A public IP makes this instance a visible target. Attackers constantly scan public addresses, probe open ports, and look for anything exploitable. If the server only talks to internal services or a database, the public IP adds attack surface with zero benefit.",
        "remediation": "Move the instance to a private subnet without a public IP. Use NAT, a load balancer, or internal services so it can still reach what it needs without being directly reachable.",
        "cis_mapping": "CIS 4.1, CIS 12.1",
    },
    "EC2-003": {
        "title": "Unencrypted EBS Volume Attached to EC2",
        "severity": "High",
        "user_impact": "Anyone who copies this server's disk can read everything on it.",
        "risk": "A disk attached to this server is not encrypted. Anyone who obtains the volume or one of its snapshots can read the data directly: databases, logs, config files, credentials. Encryption at rest is the basic control that makes a leaked or copied disk useless to an attacker.",
        "remediation": "Create an encrypted copy of the volume (snapshot, encrypted copy, swap) and enable 'EBS encryption by default' so new volumes start encrypted.",
        "cis_mapping": "CIS 3.4",
    },
    "EC2-004": {
        "title": "Security Group Open to Internet on Sensitive Ports",
        "severity": "High",
        "user_impact": "A firewall rule lets the whole internet reach a sensitive port.",
        "risk": "A security group allows 0.0.0.0/0 or ::/0 on a sensitive port (or on all ports). Every open port is a chance that something vulnerable is listening behind it. Wide-open rules are usually written in a hurry and forgotten, and they invite brute-force attacks and give attackers a foothold if any exposed service is compromised.",
        "remediation": "Replace the rule with specific source IPs or ranges, and open only the ports the application actually needs.",
        "cis_mapping": "CIS 4.1, CIS 12.1",
    },
    "IAM-001": {
        "title": "IAM Policy with Wildcard Permissions",
        "severity": "Critical",
        "user_impact": "If these credentials leak, the attacker can do almost anything in your account.",
        "risk": "Policies attached to your users allow '*' (any action) or '*' (any resource). A wildcard turns a normal account into a master key: stolen credentials mean near-total account control, and even an honest mistake by that user can cause account-wide damage because nothing limits what they can touch.",
        "remediation": "Replace wildcard policies with policies that name only the specific services and actions needed. Use separate roles for different tasks instead of one super-powerful identity.",
        "cis_mapping": "CIS 6.1",
    },
    "IAM-002": {
        "title": "Console User Without MFA",
        "severity": "High",
        "user_impact": "One leaked password equals a full console login for these users.",
        "risk": "These users can sign in to the AWS console with only a password. Passwords get phished, reused, and leaked; without MFA, any leak is a full account takeover. With MFA, the same leak is harmless. For admin and developer accounts, this is one of the cheapest, highest-impact fixes available.",
        "remediation": "Require an MFA device for every human IAM user, starting with administrators. Keep a strong password policy, but treat MFA as mandatory on top of it.",
        "cis_mapping": "CIS 6.3",
    },
    "IAM-003": {
        "title": "Stale Access Keys",
        "severity": "Medium",
        "user_impact": "Forgotten keys are still live and could be used silently by anyone who finds them.",
        "risk": "Active access keys have not been rotated or used in over 90 days. Old keys leak through code repos, logs, and screenshots, and because nobody is watching them, an attacker can use them quietly for months. An unused-but-active key is pure risk with no benefit.",
        "remediation": "Rotate access keys on a schedule (for example every 90 days), delete keys that are not used, and prefer IAM roles over long-lived keys for applications.",
        "cis_mapping": "CIS 6.2",
    },
    "IAM-004": {
        "title": "Root Account Usage or Weak Protection",
        "severity": "Critical",
        "user_impact": "If root is compromised, the entire account is lost — no policy can stop it.",
        "risk": "The root account has unlimited power and cannot be restricted by IAM policies. Signs of day-to-day root usage, missing MFA, or active root access keys mean a single compromise hands over the entire account: data, billing, everything. Root should be locked away with MFA and used only for the rare tasks that genuinely require it.",
        "remediation": "Enable MFA on the root account, delete any root access keys, store the credentials safely, and do all regular work through IAM users or roles.",
        "cis_mapping": "CIS 1.4, CIS 1.7",
    },
    "RDS-001": {
        "title": "Publicly Accessible RDS Database",
        "severity": "Critical",
        "user_impact": "Anyone on the internet can attempt to connect directly to your database.",
        "risk": "This database is set to publicly accessible. The database is usually the single most valuable target in a system, and public exposure lets attackers scan the port, brute-force credentials, and throw engine exploits at it directly — no other compromise required first.",
        "remediation": "Set PubliclyAccessible to false and place the database in a private subnet. Allow access only from application servers, a bastion host, or a VPN, never from 0.0.0.0/0.",
        "cis_mapping": "CIS 4.1",
    },
    "RDS-002": {
        "title": "RDS Storage Encryption Disabled",
        "severity": "High",
        "user_impact": "A leaked or mis-shared snapshot exposes every record in this database.",
        "risk": "The database storage, and therefore its snapshots, is not encrypted. If a snapshot is shared by mistake, copied, or leaked, all of its contents can be read directly: customer data, credentials, internal secrets. Encryption at rest is a standard expectation and costs almost nothing to enable on new databases.",
        "remediation": "Create an encrypted copy (snapshot, encrypted snapshot copy, restore) and make encryption the default for all new databases.",
        "cis_mapping": "CIS 3.4",
    },
    "RDS-003": {
        "title": "Weak RDS Backup Retention",
        "severity": "Medium",
        "user_impact": "After ransomware or an accidental delete, there may be no clean copy to restore.",
        "risk": "Automatic backups are disabled or kept for only a few days. When ransomware, an accidental delete, or a slow data-corruption bug hits, the backup window is the difference between a quick restore and permanent data loss — and a short window can close before the problem is even noticed.",
        "remediation": "Set the backup retention period to at least 7 to 14 days (or per internal policy), with longer retention for important production databases.",
        "cis_mapping": "CIS 8.1",
    },
    "RDS-004": {
        "title": "Auto Minor Version Upgrade Disabled",
        "severity": "Medium",
        "user_impact": "Known security holes in the database engine will stay unpatched.",
        "risk": "Automatic minor version upgrades are disabled. Minor versions are where security patches ship; with auto-upgrade off and no manual patching process, the database keeps running with publicly known vulnerabilities — exactly what attackers scan for.",
        "remediation": "Enable auto minor version upgrades where possible. If manual control is required, document a clear patching schedule and follow it.",
        "cis_mapping": "CIS 7.1",
    },
    "EBS-001": {
        "title": "Unencrypted EBS Volume",
        "severity": "High",
        "user_impact": "Any copy of this disk is fully readable by whoever holds it.",
        "risk": "This storage volume is not encrypted. If the volume or any snapshot of it is copied to another account or leaks through a backup, the raw data is readable by whoever holds it. Encryption makes that copy worthless to an attacker and is now a standard expectation for serious workloads.",
        "remediation": "Encrypt important volumes via snapshot-copy-restore, and enable account-level 'EBS encryption by default' so new volumes are created encrypted automatically.",
        "cis_mapping": "CIS 3.4",
    },
    "EBS-002": {
        "title": "EBS Encryption by Default Disabled",
        "severity": "Medium",
        "user_impact": "Every new volume depends on someone remembering to tick the encryption box.",
        "risk": "The account-level setting that automatically encrypts new volumes is turned off. This does not expose existing data, but it guarantees future mistakes: one forgotten checkbox creates the next unencrypted-volume finding. Secure defaults remove the human error from the equation.",
        "remediation": "Enable 'EBS encryption by default' in the EC2 account settings so every new volume starts encrypted without extra steps.",
        "cis_mapping": "CIS 3.4",
    },
    "EBS-003": {
        "title": "EBS Snapshot Shared Externally",
        "severity": "High",
        "user_impact": "External AWS accounts can read this snapshot's data at any time.",
        "risk": "A snapshot is shared with one or more external AWS account IDs. Shared snapshots are a common, quiet data-leak path: shared once for a one-off task and then forgotten. If the snapshot is unencrypted, every external account on the list can read its full contents whenever they want.",
        "remediation": "Remove sharing that is not documented and needed, share only with specific approved accounts for a clear purpose, and keep sensitive snapshots encrypted.",
        "cis_mapping": "CIS 3.4, CIS 13.1",
    },
    "EBS-004": {
        "title": "Public EBS Snapshot",
        "severity": "Critical",
        "user_impact": "Any AWS account in the world can copy this snapshot right now.",
        "risk": "A snapshot is marked public. Attackers actively browse public snapshots looking for credentials, application data, and source code. A public snapshot of real data is not a theoretical risk — it is an active data leak happening right now.",
        "remediation": "Make the snapshot private immediately. If public snapshots are ever needed for demos, use only sanitized test data and label them clearly.",
        "cis_mapping": "CIS 3.4, CIS 13.1",
    },
    "S3-001": {
        "title": "S3 Block Public Access Not Fully Enabled",
        "severity": "High",
        "user_impact": "One mis-written bucket policy could expose everything in this bucket.",
        "risk": "The bucket's Block Public Access protections are not all enabled (or are missing). Public S3 buckets are behind many of the largest real-world data breaches. Block Public Access is the safety net that stops a single misconfigured policy or ACL from exposing the entire bucket.",
        "remediation": "Enable all four Block Public Access settings on the bucket, and enable the account-level setting as well.",
        "cis_mapping": "CIS 3.3",
    },
    "S3-002": {
        "title": "S3 Default Encryption Not Configured",
        "severity": "High",
        "user_impact": "New objects in this bucket may be stored without encryption.",
        "risk": "Without a default encryption setting, objects can be uploaded unencrypted. If the bucket is ever exposed, its contents are immediately readable. Encryption at rest is a baseline expectation for any bucket holding sensitive data.",
        "remediation": "Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket so every new object is encrypted automatically.",
        "cis_mapping": "CIS 3.4",
    },
    "S3-003": {
        "title": "S3 Bucket Versioning Disabled",
        "severity": "Medium",
        "user_impact": "Deleted or overwritten objects in this bucket cannot be recovered.",
        "risk": "Without versioning, a single accidental deletion or overwrite permanently destroys the data. Ransomware that overwrites objects has the same effect. Versioning is the primary defence against data-loss events in S3.",
        "remediation": "Enable versioning on the bucket. Pair it with lifecycle rules to manage older versions and control storage costs.",
        "cis_mapping": "CIS 8.1",
    },
    "S3-004": {
        "title": "S3 Access Logging Disabled",
        "severity": "Low",
        "user_impact": "Requests to this bucket are not being logged.",
        "risk": "Without access logs there is no record of who accessed or modified objects. After a breach or data leak, logs are the primary source of evidence. Without them, investigation is severely limited.",
        "remediation": "Enable S3 server access logging and direct logs to a separate, protected bucket with appropriate lifecycle rules.",
        "cis_mapping": "CIS 8.5",
    },
    "S3-005": {
        "title": "S3 Bucket Policy Allows Public Principal",
        "severity": "Critical",
        "user_impact": "Anyone on the internet may be able to access this bucket's contents.",
        "risk": "The bucket policy uses a wildcard principal ('*' or AWS: '*'), which can grant read, write, or list access to unauthenticated users. This is one of the most common causes of large-scale S3 data exposures.",
        "remediation": "Replace wildcard principals with specific IAM roles or accounts. Apply least-privilege permissions and review the policy with AWS IAM Access Analyzer.",
        "cis_mapping": "CIS 3.3, CIS 13.1",
    },
    "SG-001": {
        "title": "Security Group: SSH Open to Internet",
        "severity": "Critical",
        "user_impact": "Any machine on the internet can attempt to log in over SSH right now.",
        "risk": "Port 22 is reachable from 0.0.0.0/0. Automated bots continuously scan the internet for open SSH ports and attempt credential-stuffing attacks. One weak or reused password gives an attacker full shell access.",
        "remediation": "Restrict the SSH rule to specific trusted IP ranges. For production systems, remove public SSH entirely and use AWS Systems Manager Session Manager or a VPN instead.",
        "cis_mapping": "CIS 4.1, CIS 12.1",
    },
    "SG-002": {
        "title": "Security Group: RDP Open to Internet",
        "severity": "Critical",
        "user_impact": "Any machine on the internet can attempt to log in over RDP right now.",
        "risk": "Port 3389 is reachable from 0.0.0.0/0. RDP is a primary vector for ransomware operators who brute-force credentials or exploit RDP vulnerabilities. Exposure creates a direct path to remote code execution.",
        "remediation": "Restrict the RDP rule to specific trusted IP ranges. For production systems, remove public RDP and use a VPN or AWS Systems Manager Session Manager instead.",
        "cis_mapping": "CIS 4.1, CIS 12.1",
    },
    "SG-003": {
        "title": "Security Group: All Inbound Traffic Open to Internet",
        "severity": "Critical",
        "user_impact": "Every port on resources using this group is reachable from the internet.",
        "risk": "An all-traffic inbound rule (protocol -1) from 0.0.0.0/0 exposes every port and service running on attached resources. This is the broadest possible exposure and should never be used in a production environment.",
        "remediation": "Remove the all-traffic inbound rule. Define explicit rules for only the ports and protocols the application actually requires, with the most restrictive source ranges possible.",
        "cis_mapping": "CIS 4.1, CIS 12.1",
    },
    "SG-004": {
        "title": "Security Group: Unrestricted Outbound Traffic",
        "severity": "Medium",
        "user_impact": "Compromised resources can freely communicate outbound to any internet destination.",
        "risk": "An all-traffic outbound rule (protocol -1) to 0.0.0.0/0 means a compromised workload can exfiltrate data or phone home to a command-and-control server without restriction.",
        "remediation": "Restrict outbound rules to known required destinations and ports. Use VPC endpoints for AWS services to eliminate unnecessary internet egress.",
        "cis_mapping": "CIS 12.1",
    },
    "SG-005": {
        "title": "Unused Security Group",
        "severity": "Low",
        "user_impact": "Stale security groups add clutter and can be accidentally reused.",
        "risk": "Security groups not attached to any resource accumulate over time. They can contain overly permissive rules that were forgotten, and reuse without review introduces unintended exposure.",
        "remediation": "Review and remove unused security groups. Apply consistent naming and tagging to help track ownership and intended use.",
        "cis_mapping": "CIS 12.1",
    },
    "VPC-001": {
        "title": "VPC Flow Logs Disabled",
        "severity": "Medium",
        "user_impact": "Network traffic in this VPC is not being recorded.",
        "risk": "Without Flow Logs, there is no record of accepted or rejected connections inside the VPC. Incident response and forensic investigations are severely limited — suspicious lateral movement or data exfiltration may go completely undetected.",
        "remediation": "Enable VPC Flow Logs for every VPC and deliver records to CloudWatch Logs or S3. Monitor for rejected connections and unexpected traffic patterns.",
        "cis_mapping": "CIS 8.5",
    },
    "VPC-002": {
        "title": "Route Table Has Default Route to Internet Gateway",
        "severity": "Medium",
        "user_impact": "Subnets using this route table have direct internet connectivity.",
        "risk": "A default route (0.0.0.0/0) pointing to an Internet Gateway makes associated subnets public. Resources in these subnets are internet-reachable when they have a public IP and permissive security groups. Sensitive workloads placed here by mistake are directly exposed.",
        "remediation": "Confirm only intentionally public subnets use this route table. Move databases and internal services to private subnets. Use a NAT Gateway for outbound-only internet access from private subnets.",
        "cis_mapping": "CIS 4.1, CIS 12.1",
    },
    "VPC-003": {
        "title": "Subnet Auto-Assigns Public IPv4 Addresses",
        "severity": "Medium",
        "user_impact": "Every instance launched in this subnet automatically gets a public IP.",
        "risk": "Auto-assignment of public IPs means new resources become internet-reachable by default. A permissive security group — even a temporary one — immediately exposes the instance. The risk is compounded because it happens silently without any explicit action.",
        "remediation": "Disable MapPublicIpOnLaunch on subnets that are not intentionally public. Reserve public subnets for load balancers and bastion hosts only.",
        "cis_mapping": "CIS 4.1, CIS 12.1",
    },
    "KMS-001": {
        "title": "KMS Key Rotation Disabled",
        "severity": "Medium",
        "user_impact": "If this key is ever compromised, all data it protects is at risk indefinitely.",
        "risk": "Automatic key rotation is off. Without rotation, the same key material is used indefinitely. If it is ever extracted or compromised, all data encrypted with it is at risk for the full lifetime of the key. Annual rotation limits that window.",
        "remediation": "Enable automatic annual rotation for the key. Verify that dependent services handle rotation transparently before enabling it.",
        "cis_mapping": "CIS 3.7",
    },
    "KMS-002": {
        "title": "KMS Key Policy Is Overly Permissive",
        "severity": "High",
        "user_impact": "Any principal may be able to use or administer this encryption key.",
        "risk": "The key policy contains a wildcard principal, action, or resource. This can grant unintended identities the ability to encrypt, decrypt, or administer the key. A compromised identity with broad key access can read all data the key protects.",
        "remediation": "Remove wildcard principals and actions. Grant only the specific roles and users that need access, and use conditions (encryption context, VPC endpoints) to further restrict usage.",
        "cis_mapping": "CIS 3.7, CIS 6.1",
    },
    "KMS-003": {
        "title": "KMS Key Pending Deletion",
        "severity": "High",
        "user_impact": "If this key is still in use, deleting it will make encrypted data permanently unrecoverable.",
        "risk": "The key is scheduled for deletion. If any data — backups, secrets, volumes, or S3 objects — is still encrypted with it, deletion will make that data permanently inaccessible. There is no recovery after a KMS key is deleted.",
        "remediation": "Cancel the deletion if the key is still in use. Identify and re-encrypt dependent data using a new key before scheduling deletion again.",
        "cis_mapping": "CIS 3.7",
    },
    "KMS-004": {
        "title": "KMS Key Is Disabled",
        "severity": "Medium",
        "user_impact": "Services relying on this key may fail to encrypt or decrypt data.",
        "risk": "The key is disabled. Any service or resource that needs to encrypt or decrypt using this key will fail until it is re-enabled. Disabling a key in active use can cause application outages and data-access failures.",
        "remediation": "Re-enable the key if it is still needed, after confirming which services depend on it. If it is being retired, migrate dependent data to a new key before disabling.",
        "cis_mapping": "CIS 3.7",
    },
    "KMS-005": {
        "title": "KMS Key Has No Alias",
        "severity": "Low",
        "user_impact": "This key is identified only by its ID, making it easy to confuse or misuse.",
        "risk": "Customer-managed keys without aliases are difficult to identify in policies, audit logs, and the console. Operational mistakes — using the wrong key, failing to track ownership — are more likely when keys have no human-readable name.",
        "remediation": "Create a descriptive alias (e.g. alias/prod-rds-encryption-key). Standardise a naming convention and maintain a key inventory for governance.",
        "cis_mapping": "CIS 3.7",
    },
    "LOG-001": {
        "title": "No CloudTrail Trail Configured",
        "severity": "High",
        "user_impact": "If something goes wrong, there is no record of who did what.",
        "risk": "The account has no CloudTrail trail recording API activity. Without it there is no audit trail: a deleted resource, a suspicious login, or misuse of credentials cannot be investigated. Logging is the foundation that every other security control depends on.",
        "remediation": "Create a multi-region CloudTrail trail that delivers logs to a private, encrypted S3 bucket.",
        "cis_mapping": "CIS 8.5",
    },
}

validate_profiles(RULES.keys())

def now_iso():
    return datetime.now().astimezone().isoformat()

def get_account_id():
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]

def infer_service_from_rule(rule_id):
    if rule_id.startswith("EC2"):
        return "EC2"
    if rule_id.startswith("S3"):
        return "S3"
    if rule_id.startswith("LOG"):
        return "CloudTrail"
    if rule_id.startswith("IAM"):
        return "IAM"
    if rule_id.startswith("RDS"):
        return "RDS"
    if rule_id.startswith("EBS"):
        return "EBS"
    if rule_id.startswith("SG"):
        return "SG"
    if rule_id.startswith("VPC"):
        return "VPC"
    if rule_id.startswith("KMS"):
        return "KMS"
    return "Unknown"

def build_arn(service, resource):
    account_id = get_account_id()
    if service == "EC2":
        return f"arn:aws:ec2:{AWS_REGION}:{account_id}:instance/{resource}"
    if service == "S3":
        return f"arn:aws:s3:::{resource}"
    if service == "CloudTrail":
        return f"arn:aws:cloudtrail:{AWS_REGION}:{account_id}:trail/{resource}"
    if service == "IAM":
        return f"arn:aws:iam::{account_id}:user/{resource}"
    if service == "RDS":
        return f"arn:aws:rds:{AWS_REGION}:{account_id}:db:{resource}"
    if service == "EBS":
        return f"arn:aws:ec2:{AWS_REGION}:{account_id}:volume/{resource}"
    if service == "SG":
        return f"arn:aws:ec2:{AWS_REGION}:{account_id}:security-group/{resource}"
    if service == "VPC":
        return f"arn:aws:ec2:{AWS_REGION}:{account_id}:vpc/{resource}"
    if service == "KMS":
        return f"arn:aws:kms:{AWS_REGION}:{account_id}:key/{resource}"
    return None

def compute_severity(rule_id, profile_name, environment=None):
    """Pure function: (rule, sector profile, environment tier) -> severity.

    Reused both at scan time (add_finding, below) and at read time (see
    app.py's /api/findings `profile` param) so a stored scan's findings can
    be re-weighted under a different business profile without re-scanning
    AWS — the profile/environment axes are a pure relabeling of the same
    underlying facts, not something that needs fresh AWS data.
    """
    rule = RULES[rule_id]
    profile = get_profile(profile_name)
    override = profile["severity_overrides"].get(rule_id)
    severity = override if override is not None else rule["severity"]
    if environment is not None:
        # `override` doubles as the floor: if this profile flags the rule as
        # sector-critical, the environment discount can't erode it below
        # that regulatory-mandated severity.
        severity = adjust_severity(rule_id, severity, environment, floor=override)
    return severity

def add_finding(findings, rule_id, resource, risk, evidence=None, service=None, db_context=None):
    rule = RULES[rule_id]
    profile = get_profile(BUSINESS_PROFILE)
    business_mapping = profile["framework_mapping"].get(rule_id)

    engine = None
    environment = None
    engine_note = None
    if db_context:
        environment = db_context.get("environment")
        engine = db_context.get("engine")
        engine_note = get_engine_note(rule_id, engine)

    severity = compute_severity(rule_id, BUSINESS_PROFILE, environment)

    findings.append({
        "finding_code": rule_id,
        "title": rule["title"],
        "resource": resource,
        "description": risk,
        "evidence": evidence,
        "risk": rule["risk"],
        "severity": severity,
        "compliance_status": "FAIL",
        "remediation": rule["remediation"],
        "cis_mapping": rule["cis_mapping"],
        "business_framework": profile["framework"],
        "business_mapping": business_mapping,
        "db_engine": engine,
        "db_environment": environment,
        "db_engine_note": engine_note,
        "service": service or infer_service_from_rule(rule_id),
        "detected_at": now_iso()
    })

def summarize_findings(findings):
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        if f["severity"] in summary:
            summary[f["severity"]] += 1
    return summary

def check_cloudtrail(findings):
    try:
        cloudtrail = boto3.client("cloudtrail", region_name=AWS_REGION)
        response = cloudtrail.describe_trails()
        if not response.get("trailList"):
            add_finding(findings, "LOG-001", "AWS Account", "No CloudTrail trail is configured.", service="CloudTrail")
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code in ("AccessDeniedException", "UnauthorizedOperation"):
            print(f"[SKIP] CloudTrail check skipped — insufficient permissions: {error_code}")
        else:
            print(f"[WARN] CloudTrail check failed: {error_code}")

def check_iam(findings):
    run_iam_checks(findings, add_finding)

def check_ec2(findings):
    run_ec2_checks(findings, add_finding)

def check_rds(findings):
    run_rds_checks(findings, add_finding)

def check_ebs(findings):
    run_ebs_checks(findings, add_finding)

def check_s3(findings):
    run_s3_checks(findings, add_finding)

def check_sg(findings):
    run_sg_checks(findings, add_finding)

def check_vpc(findings):
    run_vpc_checks(findings, add_finding)

def check_kms(findings):
    run_kms_checks(findings, add_finding)

def run_scan():
    findings = []
    check_ec2(findings)
    check_s3(findings)
    check_cloudtrail(findings)
    check_iam(findings)
    check_rds(findings)
    check_ebs(findings)
    check_sg(findings)
    check_vpc(findings)
    check_kms(findings)
    return findings

def get_or_create_cis_control(cursor, control_code):
    cursor.execute("SELECT cis_id FROM cis_controls WHERE control_code = ?", (control_code,))
    row = cursor.fetchone()
    if row:
        return row["cis_id"]
    cursor.execute("INSERT INTO cis_controls (cis_version, control_code, control_title) VALUES (?, ?, ?)", ("CIS v8", control_code, control_code))
    return cursor.lastrowid

def insert_scan(cursor, account_id):
    ts = now_iso()
    cursor.execute("INSERT INTO scans (aws_profile, aws_account_id, region, service, scan_type, started_at, completed_at, status, business_profile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (AWS_PROFILE, account_id, AWS_REGION, "Multi-Service", "PoC Manual Scan", ts, ts, "completed", BUSINESS_PROFILE))
    return cursor.lastrowid

def insert_resource(cursor, scan_id, finding):
    cursor.execute("INSERT INTO resources (scan_id, aws_resource_id, resource_name, resource_type, service, region, arn) VALUES (?, ?, ?, ?, ?, ?, ?)", (scan_id, finding["resource"], finding["resource"], finding["service"], finding["service"], AWS_REGION, build_arn(finding["service"], finding["resource"])))
    return cursor.lastrowid

def insert_finding(cursor, scan_id, resource_id, finding):
    cursor.execute(
        "INSERT INTO findings (scan_id, resource_id, finding_code, title, description, severity, compliance_status, remediation, evidence, detected_at, business_framework, business_mapping, db_engine, db_environment, db_engine_note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (scan_id, resource_id, finding["finding_code"], finding["title"], finding["description"], finding["severity"], finding["compliance_status"], finding["remediation"], finding.get("evidence"), finding["detected_at"], finding.get("business_framework"), finding.get("business_mapping"), finding.get("db_engine"), finding.get("db_environment"), finding.get("db_engine_note"))
    )
    return cursor.lastrowid

def insert_finding_cis_mappings(cursor, finding_id, cis_controls):
    for control_code in cis_controls.split(", "):
        cis_id = get_or_create_cis_control(cursor, control_code.strip())
        cursor.execute("INSERT INTO finding_cis_mappings (finding_id, cis_id) VALUES (?, ?)", (finding_id, cis_id))

def save_findings_to_db(findings):
    conn = db.connect()
    cursor = conn.cursor()
    account_id = get_account_id()
    scan_id = insert_scan(cursor, account_id)
    for finding in findings:
        resource_id = insert_resource(cursor, scan_id, finding)
        finding_id = insert_finding(cursor, scan_id, resource_id, finding)
        insert_finding_cis_mappings(cursor, finding_id, finding["cis_mapping"])
    try:
        conn.commit()
    finally:
        conn.close()
    print(f"Findings saved to MySQL database (scan_id={scan_id})")

def save_findings_to_json(findings):
    output = {
        "scan_time": now_iso(),
        "aws_profile": AWS_PROFILE,
        "business_profile": BUSINESS_PROFILE,
        "region": AWS_REGION,
        "total_findings": len(findings),
        "summary": summarize_findings(findings),
        "findings": findings
    }
    with open(JSON_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    print(f"Findings exported to {JSON_OUTPUT_PATH}")

def print_findings(findings):
    print("\n=== AWS Security Posture Assessment ===\n")
    if not findings:
        print("No findings detected.")
        return
    for f in findings:
        print(f"Rule ID : {f['finding_code']}")
        print(f"Title : {f['title']}")
        print(f"Resource : {f['resource']}")
        print(f"Status : {f['compliance_status']}")
        print(f"Severity : {f['severity']}")
        print(f"Risk : {f['risk']}")
        print(f"CIS Mapping : {', '.join(f['cis_mapping'])}")
        print(f"Details : {f['description']}")
        print(f"Recommendation: {f['remediation']}")
        print("-" * 60)
    summary = summarize_findings(findings)
    print(f"\nTotal Findings: {len(findings)}")
    for sev, count in summary.items():
        print(f" {sev:<12}: {count}")

if __name__ == "__main__":
    findings = run_scan()
    print_findings(findings)
    save_findings_to_db(findings)
    save_findings_to_json(findings)