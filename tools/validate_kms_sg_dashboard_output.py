"""
KMS and Security Group dashboard output validator.

This script validates whether KMS and Security Group findings are ready
for the PoC dashboard. It checks that each finding has the fields needed
for the dashboard table and dropdown drill-down, including evidence,
CIS mapping, and remediation guidance.

This supports the following:
- Test and improve KMS + Security Group dashboard sections.
- Validate dropdown details, evidence, and suggested fixes.
- Confirm findings are clear enough for demo/report evidence.
"""

import json
from pathlib import Path
from datetime import datetime


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FINDINGS_FILE = PROJECT_ROOT / "findings.json"
REPORT_DIR = PROJECT_ROOT / "reports"
REPORT_FILE = REPORT_DIR / "kms_sg_dashboard_validation_report.md"


KMS_RULES = {"KMS-001", "KMS-002", "KMS-003", "KMS-004", "KMS-005"}
SG_RULES = {"SG-001", "SG-002", "SG-003", "SG-004", "SG-005"}

REQUIRED_FIELDS = [
    "rule_id",
    "service",
    "severity",
    "status",
    "resource",
    "description",
    "evidence",
    "remediation",
]

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}


def load_findings():
    if not FINDINGS_FILE.exists():
        raise FileNotFoundError(f"Could not find {FINDINGS_FILE}")

    with open(FINDINGS_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, list):
        raise ValueError("findings.json must contain a list of findings.")

    return data


def is_kms_sg_finding(finding):
    rule_id = finding.get("rule_id", "")
    service = str(finding.get("service", "")).lower()

    return (
        rule_id in KMS_RULES
        or rule_id in SG_RULES
        or "kms" in service
        or "security group" in service
    )


def validate_finding(finding):
    errors = []
    warnings = []

    rule_id = finding.get("rule_id", "UNKNOWN")

    for field in REQUIRED_FIELDS:
        if field not in finding:
            errors.append(f"Missing required dashboard field: {field}")
        elif finding[field] in ("", None, [], {}):
            errors.append(f"Required dashboard field is empty: {field}")

    if finding.get("severity") and finding.get("severity") not in VALID_SEVERITIES:
        warnings.append(f"Unexpected severity value: {finding.get('severity')}")

    cis_value = (
        finding.get("cis_mapping")
        or finding.get("cis_controls")
        or finding.get("benchmarks")
        or finding.get("mapping")
    )

    if not cis_value:
        errors.append("Missing CIS mapping/benchmark information.")

    evidence = str(finding.get("evidence", ""))
    remediation = str(finding.get("remediation", ""))

    if len(evidence.strip()) < 20:
        warnings.append("Evidence may be too short for dashboard dropdown detail.")

    if len(remediation.strip()) < 40:
        warnings.append("Remediation guidance may be too short for suggested fixes.")

    fix_words = ["enable", "disable", "restrict", "remove", "review", "rotate", "limit", "monitor"]
    if remediation and not any(word in remediation.lower() for word in fix_words):
        warnings.append("Remediation does not include clear action/fix wording.")

    return {
        "rule_id": rule_id,
        "service": finding.get("service", "UNKNOWN"),
        "errors": errors,
        "warnings": warnings,
        "passed": len(errors) == 0,
    }


def generate_report(results):
    REPORT_DIR.mkdir(exist_ok=True)

    passed = sum(1 for result in results if result["passed"])
    failed = len(results) - passed

    lines = [
        "# KMS and Security Group Dashboard Validation Report",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"- Total KMS/SG findings checked: {len(results)}",
        f"- Passed: {passed}",
        f"- Failed: {failed}",
        "",
        "## Validation checks performed",
        "",
        "- Required dashboard fields are present.",
        "- Evidence field is populated for dropdown detail.",
        "- Remediation/suggested fixes are clear enough for display.",
        "- CIS mapping or benchmark mapping exists.",
        "- Severity values are consistent.",
        "",
        "## Finding-level results",
        "",
    ]

    for result in results:
        status = "PASS" if result["passed"] else "FAIL"
        lines.append(f"### {result['rule_id']} - {result['service']} - {status}")
        lines.append("")

        if not result["errors"] and not result["warnings"]:
            lines.append("- No issues found.")
        else:
            for error in result["errors"]:
                lines.append(f"- ERROR: {error}")
            for warning in result["warnings"]:
                lines.append(f"- WARNING: {warning}")

        lines.append("")

    REPORT_FILE.write_text("\n".join(lines), encoding="utf-8")
    return REPORT_FILE


def main():
    findings = load_findings()
    kms_sg_findings = [finding for finding in findings if is_kms_sg_finding(finding)]

    if not kms_sg_findings:
        print("No KMS or Security Group findings found in findings.json.")
        return

    results = [validate_finding(finding) for finding in kms_sg_findings]
    report_path = generate_report(results)

    print("KMS/SG dashboard validation complete.")
    print(f"Findings checked: {len(results)}")
    print(f"Passed: {sum(1 for result in results if result['passed'])}")
    print(f"Failed: {sum(1 for result in results if not result['passed'])}")
    print(f"Report saved to: {report_path}")


if __name__ == "__main__":
    main()
