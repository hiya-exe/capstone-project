import boto3
import csv
import io
from datetime import datetime, timezone
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"
KEY_ROTATION_DAYS = 90


def _get_credential_report(iam):
    try:
        iam.generate_credential_report()
    except ClientError:
        pass
    for _ in range(10):
        try:
            report = iam.get_credential_report()
            content = report.get("Content")
            if isinstance(content, bytes):
                return content.decode("utf-8")
            return content.read().decode("utf-8")
        except ClientError as e:
            if e.response["Error"]["Code"] in ("ReportInProgress", "ReportNotPresent"):
                import time
                time.sleep(2)
                continue
            raise
    return None


def _check_wildcard_policies(findings, add_finding):
    iam = boto3.client("iam", region_name=AWS_REGION)
    try:
        seen_policies = {}
        users = iam.list_users().get("Users", [])
        for user in users:
            username = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            for policy in attached:
                policy_arn = policy["PolicyArn"]
                policy_name = policy["PolicyName"]
                if policy_arn in seen_policies:
                    continue
                policy_detail = iam.get_policy(PolicyArn=policy_arn)
                version_id = policy_detail["Policy"]["DefaultVersionId"]
                version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                statements = version["PolicyVersion"]["Document"].get("Statement", [])
                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    if "*" in actions or "*" in resources:
                        seen_policies[policy_arn] = policy_name
                        break
        if seen_policies:
            policy_names = list(seen_policies.values())
            count = len(policy_names)
            reason = f"{count} IAM policy/policies use '*' in Action or Resource in Allow statements, creating overly broad permissions. If one of these identities is compromised, an attacker can perform far more actions than intended."
            evidence = "Policies with wildcards: " + ", ".join(policy_names)
            add_finding(findings, "IAM-001", f"{count} policy(s) with wildcards", reason, evidence, service="IAM")
    except ClientError as e:
        print(f"[SKIP] IAM wildcard check skipped: {e.response['Error']['Code']}")


def _check_users_without_mfa(findings, add_finding):
    iam = boto3.client("iam", region_name=AWS_REGION)
    try:
        users = iam.list_users().get("Users", [])
        users_without_mfa = []
        for user in users:
            username = user["UserName"]
            try:
                mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            except ClientError:
                mfa_devices = []
            if not mfa_devices:
                users_without_mfa.append(username)
        if users_without_mfa:
            count = len(users_without_mfa)
            user_list = ", ".join(users_without_mfa)
            reason = f"{count} IAM user(s) have no MFA configured. If a password is guessed or stolen, those accounts can be logged into with only one factor, which makes account takeover much easier."
            evidence = f"Users without MFA: {user_list}"
            add_finding(findings, "IAM-002", f"{count} user(s) without MFA", reason, evidence, service="IAM")
    except ClientError as e:
        print(f"[SKIP] IAM MFA check skipped: {e.response['Error']['Code']}")


def _check_stale_access_keys(findings, add_finding):
    iam = boto3.client("iam", region_name=AWS_REGION)
    now = datetime.now(timezone.utc)
    try:
        content = _get_credential_report(iam)
        if not content:
            return
        reader = csv.DictReader(io.StringIO(content))
        stale_keys = []
        for row in reader:
            username = row.get("user", "")
            if username == "<root_account>":
                continue
            for key_num in ("1", "2"):
                active = row.get(f"access_key_{key_num}_active", "false").lower() == "true"
                if not active:
                    continue
                last_rotated_str = row.get(f"access_key_{key_num}_last_rotated", "N/A")
                last_used_str = row.get(f"access_key_{key_num}_last_used_date", "N/A")
                stale = False
                rotated_info = last_rotated_str
                used_info = last_used_str
                if last_rotated_str not in ("N/A", "no_information", ""):
                    try:
                        last_rotated = datetime.fromisoformat(last_rotated_str.replace("Z", "+00:00"))
                        days_since_rotation = (now - last_rotated).days
                        if days_since_rotation > KEY_ROTATION_DAYS:
                            stale = True
                            rotated_info = f"{last_rotated_str} ({days_since_rotation} days ago)"
                    except ValueError:
                        pass
                if last_used_str not in ("N/A", "no_information", "") and not stale:
                    try:
                        last_used = datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
                        days_since_use = (now - last_used).days
                        if days_since_use > KEY_ROTATION_DAYS:
                            stale = True
                            used_info = f"{last_used_str} ({days_since_use} days since last use)"
                    except ValueError:
                        pass
                if stale:
                    stale_keys.append(f"User={username}, Key={key_num}, LastRotated={rotated_info}, LastUsed={used_info}")
        if stale_keys:
            count = len(stale_keys)
            reason = f"{count} active access key(s) have not been rotated or used in over {KEY_ROTATION_DAYS} days. Long-lived or forgotten keys are a common source of credential exposure through code repos, logs, or screenshots. If compromised, they can be used silently for a long time."
            evidence = "; ".join(stale_keys)
            add_finding(findings, "IAM-003", f"{count} stale access key(s)", reason, evidence, service="IAM")
    except ClientError as e:
        print(f"[SKIP] IAM stale access keys check skipped: {e.response['Error']['Code']}")


def _check_root_account_usage(findings, add_finding):
    iam = boto3.client("iam", region_name=AWS_REGION)
    try:
        content = _get_credential_report(iam)
        if not content:
            return
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            if row.get("user") != "<root_account>":
                continue
            mfa_active = row.get("mfa_active", "false").lower() == "true"
            key1_active = row.get("access_key_1_active", "false").lower() == "true"
            key2_active = row.get("access_key_2_active", "false").lower() == "true"
            password_last_used = row.get("password_last_used", "N/A")
            issues = []
            if not mfa_active:
                issues.append("MFA is NOT enabled on root account")
            if key1_active or key2_active:
                issues.append(f"Root account has active access keys (key1_active={key1_active}, key2_active={key2_active})")
            if password_last_used not in ("N/A", "no_information", "not_supported", ""):
                issues.append(f"Root account password was last used: {password_last_used}")
            if issues:
                reason = "The root account has unrestricted power over the entire AWS account and cannot be constrained by IAM policies. Using or leaving it unprotected is extremely dangerous. Compromise of the root account can lead to total account takeover."
                evidence = "Root account issues: " + "; ".join(issues)
                add_finding(findings, "IAM-004", "root account", reason, evidence, service="IAM")
            break
    except ClientError as e:
        print(f"[SKIP] IAM root account check skipped: {e.response['Error']['Code']}")


def run_iam_checks(findings, add_finding):
    _check_wildcard_policies(findings, add_finding)
    _check_users_without_mfa(findings, add_finding)
    _check_stale_access_keys(findings, add_finding)
    _check_root_account_usage(findings, add_finding)