import boto3
from botocore.exceptions import ClientError

AWS_REGION = "ca-central-1"


def _build_alias_map(kms):
    alias_map = {}
    try:
        for a in kms.list_aliases().get("Aliases", []):
            kid = a.get("TargetKeyId")
            if kid:
                alias_map.setdefault(kid, []).append(a.get("AliasName"))
    except ClientError:
        pass
    return alias_map


def run_kms_checks(findings, add_finding):
    kms = boto3.client("kms", region_name=AWS_REGION)
    try:
        keys = kms.list_keys().get("Keys", [])
    except ClientError as e:
        print(f"[WARN] KMS checks skipped: {e.response['Error']['Code']}")
        return

    alias_map = _build_alias_map(kms)

    for k in keys:
        key_id = k.get("KeyId")
        if not key_id:
            continue
        try:
            meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        except ClientError:
            continue

        if meta.get("KeyManager") != "CUSTOMER":
            continue

        key_state = meta.get("KeyState", "Unknown")

        if key_state == "Disabled":
            reason = (
                "A customer-managed KMS key is disabled. Services or resources "
                "that depend on it may fail to encrypt or decrypt data, causing "
                "operational disruption."
            )
            evidence = f"KeyId={key_id}, KeyState=Disabled"
            add_finding(findings, "KMS-004", key_id, reason, evidence, service="KMS")

        if key_state == "PendingDeletion":
            reason = (
                "A customer-managed KMS key is scheduled for deletion. If it is still "
                "used to protect data, deletion will make that data permanently unrecoverable. "
                "Cancel deletion and migrate to a new key if it is still needed."
            )
            evidence = f"KeyId={key_id}, KeyState=PendingDeletion"
            add_finding(findings, "KMS-003", key_id, reason, evidence, service="KMS")

        try:
            rotation_enabled = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled")
            if rotation_enabled is False:
                reason = (
                    "Automatic key rotation is disabled for this customer-managed KMS key. "
                    "Long-lived keys increase the window of exposure if a key is ever compromised. "
                    "Annual rotation is a standard control for key hygiene."
                )
                evidence = f"KeyId={key_id}, KeyRotationEnabled=False"
                add_finding(findings, "KMS-001", key_id, reason, evidence, service="KMS")
        except ClientError:
            pass

        try:
            policy = kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "")
            if '"Principal":"*"' in policy or '"Action":"kms:*"' in policy or '"Resource":"*"' in policy:
                reason = (
                    "The KMS key policy contains a wildcard principal, action, or resource. "
                    "This grants overly broad access to the key, potentially allowing any "
                    "principal to perform encryption, decryption, or key administration."
                )
                evidence = f"KeyId={key_id}, PolicyWildcard=Principal/Action/Resource"
                add_finding(findings, "KMS-002", key_id, reason, evidence, service="KMS")
        except ClientError:
            pass

        if not alias_map.get(key_id):
            reason = (
                "This customer-managed KMS key has no alias. Keys without aliases "
                "are harder to identify and manage, increasing the risk of using the "
                "wrong key or losing track of key ownership."
            )
            evidence = f"KeyId={key_id}, AliasCount=0"
            add_finding(findings, "KMS-005", key_id, reason, evidence, service="KMS")
