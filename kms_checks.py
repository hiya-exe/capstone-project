import boto3
from botocore.exceptions import ClientError

# ------------------------------------------------------------
# KMS CHECKS (Detailed Descriptions + Bullet Remediation)
# Rule IDs: KMS-001 .. KMS-005
# ------------------------------------------------------------

def _build_desc(title_lines, evidence_lines, impact_lines, fix_lines):
    return "\n".join(
        ["Issue:"] + [f"• {x}" for x in title_lines] +
        ["", "Evidence:"] + [f"• {x}" for x in evidence_lines] +
        ["", "Why it matters:"] + [f"• {x}" for x in impact_lines] +
        ["", "Suggested fix:"] + [f"• {x}" for x in fix_lines]
    )

def _add(findings, add_finding, rule_id, resource_id, title_lines, evidence_lines, impact_lines, fix_lines):
    add_finding(
        rule_id=rule_id,
        resource=resource_id,
        description=_build_desc(title_lines, evidence_lines, impact_lines, fix_lines)
    )

def run_kms_checks(findings, add_finding, region):
    """
    Runs KMS checks and appends findings using the project's add_finding callback.

    Expected add_finding signature (typical):
      add_finding(rule_id: str, resource: str, description: str)
    """
    kms = boto3.client("kms", region_name=region)

    # List keys (customer + AWS managed); we’ll filter to customer managed where needed
    try:
        keys = kms.list_keys().get("Keys", [])
    except ClientError as e:
        # If KMS can't be queried, just exit quietly
        return

    # Build alias map (KeyId -> [aliases])
    alias_map = {}
    try:
        for a in kms.list_aliases().get("Aliases", []):
            kid = a.get("TargetKeyId")
            if kid:
                alias_map.setdefault(kid, []).append(a.get("AliasName"))
    except ClientError:
        pass

    for k in keys:
        key_id = k.get("KeyId")
        if not key_id:
            continue

        # Describe key
        try:
            meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        except ClientError:
            continue

        # Focus on customer-managed keys for governance checks
        if meta.get("KeyManager") != "CUSTOMER":
            continue

        key_state = meta.get("KeyState", "Unknown")

        # -------------------------
        # KMS-004: Key Disabled
        # -------------------------
        if key_state == "Disabled":
            _add(
                findings, add_finding, "KMS-004", key_id,
                title_lines=[
                    "A customer-managed KMS key is disabled.",
                    "Resources relying on it may fail to encrypt/decrypt."
                ],
                evidence_lines=[
                    f"KeyId: {key_id}",
                    f"KeyState: {key_state}"
                ],
                impact_lines=[
                    "Applications/services using this key may lose access to encrypted data.",
                    "Operational disruption can occur if the key is required for normal workloads."
                ],
                fix_lines=[
                    "Re-enable the key if it is still needed.",
                    "Confirm which resources depend on the key before changing state.",
                    "If retiring, migrate data to a replacement key first."
                ]
            )

        # -------------------------
        # KMS-003: Key Pending Deletion
        # -------------------------
        if key_state == "PendingDeletion":
            _add(
                findings, add_finding, "KMS-003", key_id,
                title_lines=[
                    "A customer-managed KMS key is pending deletion.",
                    "Deletion can permanently lock encrypted data if still in use."
                ],
                evidence_lines=[
                    f"KeyId: {key_id}",
                    f"KeyState: {key_state}"
                ],
                impact_lines=[
                    "If the key is deleted while still used, encrypted data may become unrecoverable.",
                    "Can cause application failures and data loss scenarios."
                ],
                fix_lines=[
                    "Review key usage and cancel deletion if still required.",
                    "Migrate encryption to a new key before deletion.",
                    "Document key lifecycle and ownership."
                ]
            )

        # -------------------------
        # KMS-001: Rotation Disabled
        # -------------------------
        # Only supported for customer-managed symmetric keys
        try:
            rotation = kms.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled")
            if rotation is False:
                _add(
                    findings, add_finding, "KMS-001", key_id,
                    title_lines=[
                        "Automatic key rotation is disabled for a customer-managed KMS key.",
                        "Rotation reduces long-term risk if a key is compromised."
                    ],
                    evidence_lines=[
                        f"KeyId: {key_id}",
                        "KeyRotationEnabled: False"
                    ],
                    impact_lines=[
                        "Long-lived keys increase exposure time if compromised.",
                        "Rotation supports stronger key hygiene and governance."
                    ],
                    fix_lines=[
                        "Enable automatic rotation for this key.",
                        "Validate dependent services after enabling rotation.",
                        "Apply a rotation standard across environments."
                    ]
                )
        except ClientError:
            # ignore keys that don't support rotation status calls
            pass

        # -------------------------
        # KMS-002: Overly Permissive Policy (basic signal)
        # -------------------------
        try:
            pol = kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "")
            # simple heuristic checks (PoC-friendly)
            if '"Principal":"*"' in pol or '"Action":"kms:*"' in pol or '"Resource":"*"' in pol:
                _add(
                    findings, add_finding, "KMS-002", key_id,
                    title_lines=[
                        "KMS key policy appears overly permissive (wildcards detected).",
                        "Policies should follow least privilege."
                    ],
                    evidence_lines=[
                        f"KeyId: {key_id}",
                        "Policy contains wildcard principal/action/resource (heuristic match)."
                    ],
                    impact_lines=[
                        "Broad access can allow unintended encryption/decryption or key administration.",
                        "Increases blast radius if an identity is compromised."
                    ],
                    fix_lines=[
                        "Remove wildcard principals/actions where possible.",
                        "Restrict to required roles/users only (least privilege).",
                        "Use conditions (encryption context, VPC endpoints) when appropriate."
                    ]
                )
        except ClientError:
            pass

        # -------------------------
        # KMS-005: Missing Alias
        # -------------------------
        aliases = alias_map.get(key_id, [])
        # ignore AWS-managed alias patterns; customer keys should have an alias for clarity
        if not aliases:
            _add(
                findings, add_finding, "KMS-005", key_id,
                title_lines=[
                    "Customer-managed KMS key has no alias.",
                    "Aliases help identify keys and reduce operational mistakes."
                ],
                evidence_lines=[
                    f"KeyId: {key_id}",
                    "Alias count: 0"
                ],
                impact_lines=[
                    "Harder to manage keys across environments.",
                    "Higher chance of using the wrong key in production."
                ],
                fix_lines=[
                    "Create an alias (e.g., alias/prod-app-storage-key).",
                    "Standardize naming and track key owners.",
                    "Maintain a key inventory for governance."
                ]
            )
