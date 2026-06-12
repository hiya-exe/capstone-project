# Tests

Unit tests for the AWS Security Posture Assessment scanner's check modules.

All tests use [moto](https://github.com/getmoto/moto) to fake AWS in memory — **no real AWS account, no credentials, and no cost**. Each test creates deliberately misconfigured (or compliant) fake resources, runs the real check code against them, and asserts that the right finding fires (or stays silent).

## Running the tests

From the **project root**:

```bash
pip install -r requirements-dev.txt
pytest -v
```

Run a single file or test:

```bash
pytest tests/test_rds_checks.py -v
pytest tests/test_ebs_checks.py::test_ebs004_fires_for_public_snapshot -v
```

Tests also run automatically on every push and pull request via GitHub Actions (`.github/workflows/tests.yml`).

## Structure

| File | Purpose |
|---|---|
| `conftest.py` | Shared setup: dummy AWS credentials (so boto3 can never touch a real account), the test region, a `make_recorder()` helper that mimics `scanner.py`'s `add_finding`, and a `fails()` helper for filtering results. |
| `test_ebs_checks.py` | All four EBS checks (9 tests). |
| `test_rds_checks.py` | All four RDS checks (12 tests). |

## Coverage

Every check has at least one **positive** test (misconfiguration → finding fires, with the correct resource ID and evidence) and one **negative** test (compliant resource → no finding).

| Check | Fires when… | Tested scenarios |
|---|---|---|
| EBS-001 | A volume is unencrypted | unencrypted, encrypted, multiple volumes |
| EBS-002 | Encryption-by-default is off | off (account default), on |
| EBS-003 | A snapshot is shared with an external account | shared, private |
| EBS-004 | A snapshot is public | public, private |
| RDS-001 | An instance is publicly accessible | public, private |
| RDS-002 | Storage encryption is disabled | unencrypted, encrypted |
| RDS-003 | Backup retention < 7 days | 0 days, 3 days, 7 days |
| RDS-004 | Auto minor version upgrade is off | disabled, enabled |
| Combined | — | worst-case instance triggers all four RDS codes; clean account and empty account produce zero failures |

## How the tests work

```python
@mock_aws                                            # 1. fake AWS, in memory
def test_ebs001_fires_for_unencrypted_volume():
    ec2 = boto3.client("ec2", region_name=TEST_REGION)
    vol = ec2.create_volume(AvailabilityZone=AZ,     # 2. create a deliberately
                            Size=8, Encrypted=False) #    misconfigured resource
    findings, add = make_recorder()
    run_ebs_checks(findings, add)                    # 3. run the REAL check code
    hits = fails(findings, "EBS-001")
    assert len(hits) == 1                            # 4. assert the finding fired
    assert hits[0]["resource"] == vol["VolumeId"]    #    against the right resource
```

Assertions filter with `fails()` (FAIL results only), so the suite works whether or not the check modules emit PASS coverage rows.

## Adding a test for a new check

1. Create the misconfigured resource with the matching boto3 client inside a `@mock_aws` test.
2. Call the module's `run_*_checks(findings, add)` entry point.
3. Assert on `fails(findings, "<CODE>")`: count, `resource`, and a key fragment of `evidence`.
4. Add the mirror-image negative test with a compliant resource.

Keep resources in `TEST_REGION` (`ca-central-1`) — the check modules only scan that region.

## Troubleshooting

- **`ModuleNotFoundError: scanner.checks...`** — run pytest from the project root, and make sure `scanner/__init__.py` and `scanner/checks/__init__.py` exist.
- **Checks find nothing** — the resource was probably created in the wrong region; use `TEST_REGION` from `conftest.py`.
- **moto install issues** — the pinned versions in `requirements-dev.txt` (moto ≥ 5) use the unified `mock_aws` decorator; older moto 4 tutorials use `@mock_ec2`/`@mock_rds`, which won't match these tests.

## What these tests don't cover

They validate detection logic, not live AWS behavior (IAM permission errors, pagination at scale, throttling) and not the Flask dashboard or the SQLite layer. Live validation against a real free-tier account is documented separately in the AWS testing guide.
