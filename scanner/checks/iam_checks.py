
import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"

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

def run_iam_checks(findings, add_finding):
    _check_wildcard_policies(findings, add_finding)
    _check_users_without_mfa(findings, add_finding)
