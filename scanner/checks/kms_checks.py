import boto3
from botocore.exceptions import ClientError
import json

AWS_REGION = "ca-central-1"

# =============================================================================
# KMS CHECKS
# =============================================================================

def _check_kms_key_rotation(findings, add_finding):
    """
    KMS-001: Check if automatic key rotation is enabled on all customer managed keys.
    Rotation should be enabled to limit the risk of a compromised key being used indefinitely.
    CIS Mapping: CIS Controls v8 - 3.11
    NIST CSF: PR.DS-1
    """
    kms = boto3.client("kms", region_name=AWS_REGION)
    try:
        keys = kms.list_keys().get("Keys", [])
        keys_without_rotation = []

        for key in keys:
            key_id = key["KeyId"]
            try:
                # Only customer managed keys support rotation checks
                key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if key_metadata.get("KeyManager") != "CUSTOMER":
                    continue
                if key_metadata.get("KeyState") in ("PendingDeletion", "Disabled"):
                    continue

                rotation = kms.get_key_rotation_status(KeyId=key_id)
                if not rotation.get("KeyRotationEnabled", False):
                    alias = key_id
                    try:
                        aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                        if aliases:
                            alias = aliases[0].get("AliasName", key_id)
                    except ClientError:
                        pass
                    keys_without_rotation.append(alias)
            except ClientError:
                continue

        if keys_without_rotation:
            count = len(keys_without_rotation)
            reason = (
                f"{count} KMS customer managed key(s) do not have automatic key rotation enabled. "
                "Without rotation, a compromised key remains valid indefinitely, increasing the risk "
                "of unauthorized decryption of sensitive data."
            )
            evidence = "Keys without rotation enabled: " + ", ".join(keys_without_rotation)
            add_finding(
                findings, "KMS-001",
                f"{count} key(s) with rotation disabled",
                reason, evidence, service="KMS", severity="High"
            )
    except ClientError as e:
        print(f"[SKIP] KMS rotation check skipped: {e.response['Error']['Code']}")


def _check_kms_overly_permissive_policy(findings, add_finding):
    """
    KMS-002: Check if any KMS key policy grants wildcard (*) actions or principals.
    Overly broad key policies can allow unintended actors to encrypt/decrypt data.
    CIS Mapping: CIS Controls v8 - 6.1
    NIST CSF: PR.AC-4
    """
    kms = boto3.client("kms", region_name=AWS_REGION)
    try:
        keys = kms.list_keys().get("Keys", [])
        permissive_keys = []

        for key in keys:
            key_id = key["KeyId"]
            try:
                key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if key_metadata.get("KeyManager") != "CUSTOMER":
                    continue

                policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
                policy = json.loads(policy_str)
                statements = policy.get("Statement", [])

                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    principal = stmt.get("Principal", {})
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    # Flag if principal is * or actions contain kms:*
                    principal_is_wildcard = (
                        principal == "*" or
                        (isinstance(principal, dict) and principal.get("AWS") == "*")
                    )
                    action_is_wildcard = "kms:*" in actions or "*" in actions

                    if principal_is_wildcard or action_is_wildcard:
                        alias = key_id
                        try:
                            aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                            if aliases:
                                alias = aliases[0].get("AliasName", key_id)
                        except ClientError:
                            pass
                        permissive_keys.append(alias)
                        break

            except ClientError:
                continue

        if permissive_keys:
            count = len(permissive_keys)
            reason = (
                f"{count} KMS key(s) have overly permissive key policies using wildcard (*) principals "
                "or actions. This can allow any AWS identity or unintended users to perform all KMS "
                "operations including decryption of sensitive data."
            )
            evidence = "Keys with permissive policies: " + ", ".join(permissive_keys)
            add_finding(
                findings, "KMS-002",
                f"{count} key(s) with overly permissive policy",
                reason, evidence, service="KMS", severity="High"
            )
    except ClientError as e:
        print(f"[SKIP] KMS policy check skipped: {e.response['Error']['Code']}")


def _check_kms_keys_pending_deletion(findings, add_finding):
    """
    KMS-003: Check if any KMS keys are scheduled for deletion (PendingDeletion state).
    Keys pending deletion may still be needed to decrypt existing data.
    CIS Mapping: CIS Controls v8 - 3.1
    NIST CSF: PR.DS-1
    """
    kms = boto3.client("kms", region_name=AWS_REGION)
    try:
        keys = kms.list_keys().get("Keys", [])
        pending_keys = []

        for key in keys:
            key_id = key["KeyId"]
            try:
                key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if key_metadata.get("KeyManager") != "CUSTOMER":
                    continue
                if key_metadata.get("KeyState") == "PendingDeletion":
                    alias = key_id
                    try:
                        aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                        if aliases:
                            alias = aliases[0].get("AliasName", key_id)
                    except ClientError:
                        pass
                    deletion_date = key_metadata.get("DeletionDate", "Unknown")
                    pending_keys.append(f"{alias} (scheduled: {deletion_date})")
            except ClientError:
                continue

        if pending_keys:
            count = len(pending_keys)
            reason = (
                f"{count} KMS key(s) are scheduled for deletion. If these keys are still used to "
                "protect existing data, deleting them will make that data permanently inaccessible. "
                "Deletion should be reviewed and confirmed before proceeding."
            )
            evidence = "Keys pending deletion: " + ", ".join(pending_keys)
            add_finding(
                findings, "KMS-003",
                f"{count} key(s) pending deletion",
                reason, evidence, service="KMS", severity="Medium"
            )
    except ClientError as e:
        print(f"[SKIP] KMS pending deletion check skipped: {e.response['Error']['Code']}")


def _check_kms_disabled_keys(findings, add_finding):
    """
    KMS-004: Check if any customer managed KMS keys are in a disabled state.
    Disabled keys cannot be used for cryptographic operations and may indicate
    misconfiguration or forgotten keys that should be cleaned up.
    CIS Mapping: CIS Controls v8 - 3.1
    NIST CSF: PR.DS-1
    """
    kms = boto3.client("kms", region_name=AWS_REGION)
    try:
        keys = kms.list_keys().get("Keys", [])
        disabled_keys = []

        for key in keys:
            key_id = key["KeyId"]
            try:
                key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if key_metadata.get("KeyManager") != "CUSTOMER":
                    continue
                if key_metadata.get("KeyState") == "Disabled":
                    alias = key_id
                    try:
                        aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                        if aliases:
                            alias = aliases[0].get("AliasName", key_id)
                    except ClientError:
                        pass
                    disabled_keys.append(alias)
            except ClientError:
                continue

        if disabled_keys:
            count = len(disabled_keys)
            reason = (
                f"{count} KMS customer managed key(s) are currently disabled. Disabled keys cannot "
                "be used to encrypt or decrypt data. Any resources relying on these keys will fail "
                "until the keys are re-enabled or replaced."
            )
            evidence = "Disabled keys: " + ", ".join(disabled_keys)
            add_finding(
                findings, "KMS-004",
                f"{count} disabled KMS key(s) found",
                reason, evidence, service="KMS", severity="Medium"
            )
    except ClientError as e:
        print(f"[SKIP] KMS disabled key check skipped: {e.response['Error']['Code']}")


def _check_kms_keys_missing_alias(findings, add_finding):
    """
    KMS-005: Check if any customer managed KMS keys are missing an alias.
    Keys without aliases are harder to identify and manage, increasing the
    risk of accidental misuse or deletion.
    CIS Mapping: CIS Controls v8 - 1.1
    NIST CSF: ID.AM-1
    """
    kms = boto3.client("kms", region_name=AWS_REGION)
    try:
        keys = kms.list_keys().get("Keys", [])
        keys_without_alias = []

        for key in keys:
            key_id = key["KeyId"]
            try:
                key_metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                if key_metadata.get("KeyManager") != "CUSTOMER":
                    continue
                if key_metadata.get("KeyState") in ("PendingDeletion",):
                    continue

                aliases = kms.list_aliases(KeyId=key_id).get("Aliases", [])
                if not aliases:
                    keys_without_alias.append(key_id)
            except ClientError:
                continue

        if keys_without_alias:
            count = len(keys_without_alias)
            reason = (
                f"{count} KMS customer managed key(s) have no alias assigned. Keys without aliases "
                "are difficult to identify by name, making key management and auditing harder and "
                "increasing the risk of accidental misuse or deletion."
            )
            evidence = "Keys without alias: " + ", ".join(keys_without_alias)
            add_finding(
                findings, "KMS-005",
                f"{count} key(s) missing an alias",
                reason, evidence, service="KMS", severity="Low"
            )
    except ClientError as e:
        print(f"[SKIP] KMS alias check skipped: {e.response['Error']['Code']}")


# =============================================================================
# MAIN RUNNER
# =============================================================================

def run_kms_checks(findings, add_finding):
    """Run all KMS security checks."""
    _check_kms_key_rotation(findings, add_finding)
    _check_kms_overly_permissive_policy(findings, add_finding)
    _check_kms_keys_pending_deletion(findings, add_finding)
    _check_kms_disabled_keys(findings, add_finding)
    _check_kms_keys_missing_alias(findings, add_finding)
