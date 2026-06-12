"""Unit tests for scanner/checks/ebs_checks.py — all four EBS checks.

Uses moto to fake AWS: zero cost, no credentials, runs in seconds.

    pytest tests/test_ebs_checks.py -v

Covered:
    EBS-001  Unencrypted volume               
    EBS-002  Encryption-by-default disabled    
    EBS-003  Snapshot shared with external acct
    EBS-004  Public snapshot                 
"""

import boto3
import pytest
from moto import mock_aws

from scanner.checks.ebs_checks import run_ebs_checks
from .conftest import TEST_REGION, make_recorder, fails

AZ = f"{TEST_REGION}a"


def _ec2():
    return boto3.client("ec2", region_name=TEST_REGION)


# ---------------------------------------------------------------------------
# EBS-001 — Unencrypted EBS Volume
# ---------------------------------------------------------------------------

@mock_aws
def test_ebs001_fires_for_unencrypted_volume():
    ec2 = _ec2()
    vol = ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=False)

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    hits = fails(findings, "EBS-001")
    assert len(hits) == 1
    assert hits[0]["resource"] == vol["VolumeId"]
    assert "Encrypted=False" in hits[0]["evidence"]


@mock_aws
def test_ebs001_silent_for_encrypted_volume():
    ec2 = _ec2()
    ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=True)

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    assert fails(findings, "EBS-001") == []


@mock_aws
def test_ebs001_reports_each_unencrypted_volume():
    ec2 = _ec2()
    ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=False)
    ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=False)
    ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=True)

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    assert len(fails(findings, "EBS-001")) == 2


# ---------------------------------------------------------------------------
# EBS-002 — EBS Encryption by Default Disabled
# ---------------------------------------------------------------------------

@mock_aws
def test_ebs002_fires_when_encryption_by_default_off():
    _ec2()  # account exists; default state is disabled

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    hits = fails(findings, "EBS-002")
    assert len(hits) == 1
    assert "EbsEncryptionByDefault=False" in hits[0]["evidence"]


@mock_aws
def test_ebs002_silent_when_encryption_by_default_on():
    ec2 = _ec2()
    ec2.enable_ebs_encryption_by_default()

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    assert fails(findings, "EBS-002") == []


# ---------------------------------------------------------------------------
# EBS-003 — Snapshot Shared Externally
# ---------------------------------------------------------------------------

@mock_aws
def test_ebs003_fires_for_externally_shared_snapshot():
    ec2 = _ec2()
    vol = ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=False)
    snap = ec2.create_snapshot(VolumeId=vol["VolumeId"], Description="test share")
    ec2.modify_snapshot_attribute(
        SnapshotId=snap["SnapshotId"],
        Attribute="createVolumePermission",
        OperationType="add",
        UserIds=["111122223333"],
    )

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    hits = fails(findings, "EBS-003")
    assert len(hits) == 1
    assert hits[0]["resource"] == snap["SnapshotId"]
    assert "111122223333" in hits[0]["evidence"]


@mock_aws
def test_ebs003_silent_for_private_snapshot():
    ec2 = _ec2()
    vol = ec2.create_volume(AvailabilityZone=AZ, Size=8)
    ec2.create_snapshot(VolumeId=vol["VolumeId"], Description="private")

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    assert fails(findings, "EBS-003") == []


# ---------------------------------------------------------------------------
# EBS-004 — Public Snapshot
# ---------------------------------------------------------------------------

@mock_aws
def test_ebs004_fires_for_public_snapshot():
    ec2 = _ec2()
    vol = ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=False)
    snap = ec2.create_snapshot(VolumeId=vol["VolumeId"], Description="oops public")
    ec2.modify_snapshot_attribute(
        SnapshotId=snap["SnapshotId"],
        Attribute="createVolumePermission",
        OperationType="add",
        GroupNames=["all"],
    )

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    hits = fails(findings, "EBS-004")
    assert len(hits) == 1
    assert hits[0]["resource"] == snap["SnapshotId"]
    assert "Visibility=public" in hits[0]["evidence"]


@mock_aws
def test_ebs004_silent_for_private_snapshot():
    ec2 = _ec2()
    vol = ec2.create_volume(AvailabilityZone=AZ, Size=8)
    ec2.create_snapshot(VolumeId=vol["VolumeId"], Description="private")

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    assert fails(findings, "EBS-004") == []


# ---------------------------------------------------------------------------
# Clean account — nothing should FAIL
# ---------------------------------------------------------------------------

@mock_aws
def test_clean_account_produces_no_ebs_failures():
    ec2 = _ec2()
    ec2.enable_ebs_encryption_by_default()
    vol = ec2.create_volume(AvailabilityZone=AZ, Size=8, Encrypted=True)
    ec2.create_snapshot(VolumeId=vol["VolumeId"], Description="clean")

    findings, add = make_recorder()
    run_ebs_checks(findings, add)

    assert fails(findings) == [], f"unexpected failures: {fails(findings)}"
