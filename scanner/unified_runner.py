"""
Unified AWS scanner runner for the capstone project.

Purpose:
- Runs all service check modules from one entry point.
- Integrates EC2, IAM, RDS, EBS, S3, VPC, Security Groups, and KMS checks.
- Prevents one failed service check from crashing the full scan.
- Writes a combined JSON output that can be used by the Flask dashboard/backend.

"Integrate all checks into one system and ensure it can run without errors."
"""

import json
import sys
import inspect
import traceback
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "output"
OUTPUT_FILE = OUTPUT_DIR / "unified_scan_results.json"

# Allows this file to run from project root or from inside scanner/
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def now_iso():
    return datetime.utcnow().isoformat() + "Z"


def import_check(module_name, function_name):
    """
    Imports a service check function from scanner/checks.
    This keeps imports centralized and makes failures easier to identify.
    """
    try:
        module = __import__(f"scanner.checks.{module_name}", fromlist=[function_name])
        return getattr(module, function_name)
    except Exception as exc:
        raise ImportError(f"Could not import {function_name} from {module_name}: {exc}") from exc


def infer_service_from_rule(rule_id):
    if rule_id.startswith("EC2"):
        return "EC2"
    if rule_id.startswith("IAM"):
        return "IAM"
    if rule_id.startswith("RDS"):
        return "RDS"
    if rule_id.startswith("EBS"):
        return "EBS"
    if rule_id.startswith("S3"):
        return "S3"
    if rule_id.startswith("VPC"):
        return "VPC"
    if rule_id.startswith("SG"):
        return "Security Groups"
    if rule_id.startswith("KMS"):
        return "KMS"
    if rule_id.startswith("LOG"):
        return "CloudTrail"
    return "Unknown"


def default_severity(rule_id):
    """
    Gives a safe default severity when a check file does not pass one directly.
    This keeps the dashboard output consistent.
    """
    critical_prefixes = ("SG-001", "SG-002", "SG-003", "RDS-001", "EBS-004", "S3-005")
    high_prefixes = ("EC2", "IAM", "S3", "RDS", "EBS", "KMS-002")

    if rule_id in critical_prefixes:
        return "Critical"

    if rule_id.startswith(high_prefixes):
        return "High"

    return "Medium"


def default_cis_mapping(service):
    mappings = {
        "EC2": "CIS 4.1, CIS 12.1",
        "IAM": "CIS 6.1, CIS 6.3",
        "RDS": "CIS 3.4, CIS 4.1",
        "EBS": "CIS 3.4",
        "S3": "CIS 3.3, CIS 3.4",
        "VPC": "CIS 4.1, CIS 8.5, CIS 12.1",
        "Security Groups": "CIS 4.1, CIS 12.1",
        "KMS": "CIS 3.7",
        "CloudTrail": "CIS 8.5",
    }
    return mappings.get(service, "CIS mapping pending")


def add_finding(
    findings,
    rule_id,
    resource,
    description="",
    evidence=None,
    service=None,
    severity=None,
    remediation=None,
    cis_mapping=None,
    title=None,
):
    """
    Shared finding builder used by all service checks.

    It supports the style used by the existing check files:
    add_finding(findings, rule_id, resource, description, evidence, service)

    It also normalizes output for the dashboard by including both old/new field names:
    - finding_code and rule_id
    - compliance_status and status
    """
    service_name = service or infer_service_from_rule(rule_id)

    if isinstance(evidence, list):
        evidence_text = "; ".join(str(item) for item in evidence)
    elif evidence is None:
        evidence_text = "Evidence not provided by check module."
    else:
        evidence_text = str(evidence)

    finding = {
        "finding_code": rule_id,
        "rule_id": rule_id,
        "title": title or f"{service_name} finding: {rule_id}",
        "service": service_name,
        "resource": str(resource),
        "description": description or "No description provided.",
        "evidence": evidence_text,
        "severity": severity or default_severity(rule_id),
        "compliance_status": "FAIL",
        "status": "FAIL",
        "remediation": remediation or "Review the affected AWS resource and apply least privilege, encryption, logging, or restricted access based on the finding.",
        "cis_mapping": cis_mapping or default_cis_mapping(service_name),
        "detected_at": now_iso(),
    }

    findings.append(finding)


SERVICES = [
    {
        "name": "EC2",
        "module": "ec2_checks",
        "function": "run_ec2_checks",
    },
    {
        "name": "IAM",
        "module": "iam_checks",
        "function": "run_iam_checks",
    },
    {
        "name": "RDS",
        "module": "rds_checks",
        "function": "run_rds_checks",
    },
    {
        "name": "EBS",
        "module": "ebs_checks",
        "function": "run_ebs_checks",
    },
    {
        "name": "S3",
        "module": "s3_checks",
        "function": "run_s3_checks",
    },
    {
        "name": "VPC",
        "module": "vpc_checks",
        "function": "run_vpc_checks",
    },
    {
        "name": "Security Groups",
        "module": "sg_checks",
        "function": "run_sg_checks",
    },
    {
        "name": "KMS",
        "module": "kms_checks",
        "function": "run_kms_checks",
    },
]


def call_check_function(check_function, findings):
    """
    Calls check functions even if team members used slightly different function styles.
    Supports:
    - run_x_checks(findings, add_finding)
    - run_x_checks(findings)
    - run_x_checks()
    """
    signature = inspect.signature(check_function)
    param_count = len(signature.parameters)

    if param_count >= 2:
        result = check_function(findings, add_finding)
    elif param_count == 1:
        result = check_function(findings)
    else:
        result = check_function()

    if isinstance(result, list):
        findings.extend(result)


def run_service(service_config, findings):
    service_name = service_config["name"]
    before_count = len(findings)

    try:
        check_function = import_check(service_config["module"], service_config["function"])
        call_check_function(check_function, findings)

        added_count = len(findings) - before_count

        return {
            "service": service_name,
            "status": "completed",
            "findings_added": added_count,
            "error": None,
        }

    except Exception as exc:
        return {
            "service": service_name,
            "status": "skipped_with_error",
            "findings_added": 0,
            "error": {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(limit=2),
            },
        }


def summarize_by_severity(findings):
    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")
        summary[severity] = summary.get(severity, 0) + 1

    return summary


def summarize_by_service(findings):
    summary = {}

    for finding in findings:
        service = finding.get("service", "Unknown")
        summary[service] = summary.get(service, 0) + 1

    return summary


def run_unified_scan():
    findings = []
    service_results = []

    print("\n=== Unified AWS Security Scanner ===")
    print("Running all service checks from one entry point...\n")

    for service_config in SERVICES:
        result = run_service(service_config, findings)
        service_results.append(result)

        if result["status"] == "completed":
            print(f"[OK] {result['service']}: {result['findings_added']} finding(s) added")
        else:
            print(f"[SKIP] {result['service']}: {result['error']['type']} - {result['error']['message']}")

    output = {
        "scan_time": now_iso(),
        "runner": "scanner/unified_runner.py",
        "total_services_attempted": len(SERVICES),
        "services_completed": sum(1 for item in service_results if item["status"] == "completed"),
        "services_skipped_with_error": sum(1 for item in service_results if item["status"] == "skipped_with_error"),
        "total_findings": len(findings),
        "summary_by_severity": summarize_by_severity(findings),
        "summary_by_service": summarize_by_service(findings),
        "service_results": service_results,
        "findings": findings,
    }

    return output


def save_output(output):
    OUTPUT_DIR.mkdir(exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(output, file, indent=4)

    print(f"\nUnified scan output saved to: {OUTPUT_FILE}")


def main():
    output = run_unified_scan()
    save_output(output)

    print("\n=== Unified Scan Summary ===")
    print(f"Services attempted: {output['total_services_attempted']}")
    print(f"Services completed: {output['services_completed']}")
    print(f"Services skipped with error: {output['services_skipped_with_error']}")
    print(f"Total findings: {output['total_findings']}")

    print("\nFindings by service:")
    for service, count in output["summary_by_service"].items():
        print(f"- {service}: {count}")

    print("\nFindings by severity:")
    for severity, count in output["summary_by_severity"].items():
        print(f"- {severity}: {count}")


if __name__ == "__main__":
    main()
