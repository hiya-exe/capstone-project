"""
Dashboard output validation tests for KMS and Security Group findings.

These tests are focused on the PoC dashboard layer rather than live AWS scanning.
The goal is to confirm that KMS and Security Group findings are formatted properly
for the dashboard dropdowns, including evidence, CIS mapping, and remediation guidance.

Week 6 goal:
- Test and improve the KMS and Security Groups dashboard sections.
- Confirm dropdown details include evidence and suggested fixes.
- Validate that findings are dashboard-ready before final demo integration.
"""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FINDINGS_FILE = PROJECT_ROOT / "findings.json"


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


KMS_RULES = {"KMS-001", "KMS-002", "KMS-003", "KMS-004", "KMS-005"}
SG_RULES = {"SG-001", "SG-002", "SG-003", "SG-004", "SG-005"}


def load_findings():
    assert FINDINGS_FILE.exists(), "findings.json was not found in the project root."

    with open(FINDINGS_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    assert isinstance(data, list), "findings.json should contain a list of findings."
    return data


def get_kms_sg_findings():
    findings = load_findings()

    kms_sg_findings = [
        finding for finding in findings
        if finding.get("rule_id") in KMS_RULES or finding.get("rule_id") in SG_RULES
    ]

    assert kms_sg_findings, "No KMS or Security Group findings were found in findings.json."
    return kms_sg_findings


def test_kms_sg_findings_have_required_dashboard_fields():
    """
    Confirms each KMS/SG finding has the core fields needed by the dashboard table
    and dropdown drill-down section.
    """
    findings = get_kms_sg_findings()

    for finding in findings:
        for field in REQUIRED_FIELDS:
            assert field in finding, f"{finding.get('rule_id')} is missing required field: {field}"
            assert finding[field] not in ("", None), f"{finding.get('rule_id')} has empty field: {field}"


def test_kms_sg_findings_have_valid_services():
    """
    Confirms findings are correctly labelled as KMS or Security Groups
    so the dashboard service filters/grouping work properly.
    """
    findings = get_kms_sg_findings()

    valid_services = {"KMS", "Security Groups", "Security Group", "EC2 Security Group"}

    for finding in findings:
        assert finding["service"] in valid_services, (
            f"{finding.get('rule_id')} has unexpected service value: {finding.get('service')}"
        )


def test_kms_sg_findings_include_cis_mapping():
    """
    Confirms each KMS/SG finding includes CIS mapping data for the benchmark page.
    The project may store this as 'cis_mapping', 'cis_controls', or inside a mapping field,
    so this test allows the common formats used in the PoC.
    """
    findings = get_kms_sg_findings()

    for finding in findings:
        cis_value = (
            finding.get("cis_mapping")
            or finding.get("cis_controls")
            or finding.get("mapping")
            or finding.get("benchmarks")
        )

        assert cis_value, f"{finding.get('rule_id')} is missing CIS mapping information."


def test_kms_sg_dropdown_content_is_detailed_enough():
    """
    Confirms the dropdown content is not just a one-line placeholder.
    Evidence and remediation should be detailed enough for the dashboard demo.
    """
    findings = get_kms_sg_findings()

    for finding in findings:
        evidence = str(finding.get("evidence", ""))
        remediation = str(finding.get("remediation", ""))

        assert len(evidence) >= 20, (
            f"{finding.get('rule_id')} evidence is too short for dashboard drill-down."
        )

        assert len(remediation) >= 40, (
            f"{finding.get('rule_id')} remediation guidance is too short."
        )

        fix_keywords = ["restrict", "enable", "remove", "review", "limit", "rotate", "monitor"]
        assert any(word in remediation.lower() for word in fix_keywords), (
            f"{finding.get('rule_id')} remediation does not include clear fix language."
        )


def test_kms_and_sg_rule_ids_follow_expected_format():
    """
    Confirms KMS/SG rule IDs follow the team's standard naming pattern.
    """
    findings = get_kms_sg_findings()

    for finding in findings:
        rule_id = finding.get("rule_id", "")

        assert rule_id.startswith(("KMS-", "SG-")), (
            f"Unexpected rule ID format: {rule_id}"
        )

        prefix, number = rule_id.split("-")
        assert prefix in {"KMS", "SG"}
        assert number.isdigit()
        assert len(number) == 3
