"""Shared test configuration.

These tests use moto to fake AWS entirely — no real AWS account, no
credentials, and no cost. Install dev dependencies first:

    pip install -r requirements-dev.txt

Run from the project root:

    pytest -v
"""

import os
import sys

# Make the project root importable so `from scanner.checks...` works
# regardless of where pytest is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The check modules target this region (default in the code). Everything the
# tests create must live in the same region or the checks won't see it.
TEST_REGION = "ca-central-1"

# Dummy credentials so boto3 never touches a real account or local config,
# and moto intercepts every call. Must be set before boto3 clients are made.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", TEST_REGION)
os.environ.setdefault("AWS_REGION", TEST_REGION)


def make_recorder():
    """Return (findings_list, add_finding) mimicking scanner.py's add_finding.

    Accepts both the original positional signature and the newer keyword
    arguments (status=..., severity=...), so the same tests work whether or
    not the PASS-tracking upgrade has been applied to the check modules.
    """
    findings = []

    def add_finding(flist, rule_id, resource, risk, evidence=None, service=None,
                    status="FAIL", severity=None, **kwargs):
        flist.append({
            "finding_code": rule_id,
            "resource": resource,
            "description": risk,
            "evidence": evidence,
            "service": service,
            "compliance_status": status,
            "severity": severity,
        })

    return findings, add_finding


def fails(findings, code=None):
    """All FAIL results, optionally filtered to one finding code."""
    rows = [f for f in findings if f["compliance_status"] == "FAIL"]
    if code is not None:
        rows = [f for f in rows if f["finding_code"] == code]
    return rows
