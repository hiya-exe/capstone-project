"""Unit tests for scanner/checks/rds_checks.py — all four RDS checks.

Uses moto to fake AWS: zero cost, no credentials, runs in seconds.

    pytest tests/test_rds_checks.py -v

Covered:
    RDS-001  Publicly accessible instance       
    RDS-002  Storage encryption disabled       
    RDS-003  Weak backup retention (< 7 days)  
    RDS-004  Auto minor version upgrade disabled
"""
import boto3
import pytest
from moto import mock_aws

from scanner.checks.rds_checks import run_rds_checks
from .conftest import TEST_REGION, make_recorder, fails


def _rds():
    return boto3.client("rds", region_name=TEST_REGION)


def _create_db(rds, db_id="capstone-test-db", *, public=False, encrypted=True,
               retention=7, auto_upgrade=True):
    """Create a mocked RDS instance; defaults describe a fully compliant DB."""
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Sup3rSecret!",
        AllocatedStorage=20,
        PubliclyAccessible=public,
        StorageEncrypted=encrypted,
        BackupRetentionPeriod=retention,
        AutoMinorVersionUpgrade=auto_upgrade,
    )


# ---------------------------------------------------------------------------
# RDS-001 — Publicly Accessible RDS Database
# ---------------------------------------------------------------------------

@mock_aws
def test_rds001_fires_for_public_instance():
    rds = _rds()
    _create_db(rds, "public-db", public=True)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    hits = fails(findings, "RDS-001")
    assert len(hits) == 1
    assert hits[0]["resource"] == "public-db"
    assert "PubliclyAccessible=True" in hits[0]["evidence"]


@mock_aws
def test_rds001_silent_for_private_instance():
    rds = _rds()
    _create_db(rds, "private-db", public=False)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    assert fails(findings, "RDS-001") == []


# ---------------------------------------------------------------------------
# RDS-002 — Storage Encryption Disabled
# ---------------------------------------------------------------------------

@mock_aws
def test_rds002_fires_for_unencrypted_storage():
    rds = _rds()
    _create_db(rds, "plain-db", encrypted=False)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    hits = fails(findings, "RDS-002")
    assert len(hits) == 1
    assert hits[0]["resource"] == "plain-db"
    assert "StorageEncrypted=False" in hits[0]["evidence"]


@mock_aws
def test_rds002_silent_for_encrypted_storage():
    rds = _rds()
    _create_db(rds, "encrypted-db", encrypted=True)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    assert fails(findings, "RDS-002") == []


# ---------------------------------------------------------------------------
# RDS-003 — Weak Backup Retention
# ---------------------------------------------------------------------------

@mock_aws
def test_rds003_fires_for_zero_retention():
    rds = _rds()
    _create_db(rds, "no-backup-db", retention=0)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    hits = fails(findings, "RDS-003")
    assert len(hits) == 1
    assert hits[0]["resource"] == "no-backup-db"
    assert "BackupRetentionPeriod=0" in hits[0]["evidence"]


@mock_aws
def test_rds003_fires_for_short_retention():
    rds = _rds()
    _create_db(rds, "short-backup-db", retention=3)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    assert len(fails(findings, "RDS-003")) == 1


@mock_aws
def test_rds003_silent_for_week_or_longer_retention():
    rds = _rds()
    _create_db(rds, "good-backup-db", retention=7)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    assert fails(findings, "RDS-003") == []


# ---------------------------------------------------------------------------
# RDS-004 — Auto Minor Version Upgrade Disabled
# ---------------------------------------------------------------------------

@mock_aws
def test_rds004_fires_when_auto_upgrade_disabled():
    rds = _rds()
    _create_db(rds, "no-patch-db", auto_upgrade=False)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    hits = fails(findings, "RDS-004")
    assert len(hits) == 1
    assert hits[0]["resource"] == "no-patch-db"
    assert "AutoMinorVersionUpgrade=False" in hits[0]["evidence"]


@mock_aws
def test_rds004_silent_when_auto_upgrade_enabled():
    rds = _rds()
    _create_db(rds, "patched-db", auto_upgrade=True)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    assert fails(findings, "RDS-004") == []


# ---------------------------------------------------------------------------
# Combined scenarios
# ---------------------------------------------------------------------------

@mock_aws
def test_worst_case_instance_triggers_all_four_checks():
    """One instance misconfigured in every way -> all four codes fire."""
    rds = _rds()
    _create_db(rds, "worst-db", public=True, encrypted=False,
               retention=0, auto_upgrade=False)

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    codes = sorted({f["finding_code"] for f in fails(findings)})
    assert codes == ["RDS-001", "RDS-002", "RDS-003", "RDS-004"]


@mock_aws
def test_compliant_instance_produces_no_failures():
    rds = _rds()
    _create_db(rds, "clean-db")  # defaults are fully compliant

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    assert fails(findings) == [], f"unexpected failures: {fails(findings)}"


@mock_aws
def test_no_instances_produces_no_failures():
    _rds()  # account exists, no databases

    findings, add = make_recorder()
    run_rds_checks(findings, add)

    assert fails(findings) == []
