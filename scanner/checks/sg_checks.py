import boto3
from botocore.exceptions import ClientError

# ------------------------------------------------------------
# SECURITY GROUP CHECKS (Detailed Descriptions + Bullet Remediation)
# Rule IDs: SG-001 .. SG-005
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

def _is_world_open(ip_ranges):
    for r in ip_ranges or []:
        if r.get("CidrIp") == "0.0.0.0/0":
            return True
    return False

def run_sg_checks(findings, add_finding, region):
    """
    Runs SG checks and appends findings using the project's add_finding callback.

    Expected add_finding signature (typical):
      add_finding(rule_id: str, resource: str, description: str)
    """
    ec2 = boto3.client("ec2", region_name=region)

    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    except ClientError:
        return

    # Used SGs set (attached to any network interface)
    used_sg_ids = set()
    try:
        enis = ec2.describe_network_interfaces().get("NetworkInterfaces", [])
        for eni in enis:
            for g in eni.get("Groups", []):
                gid = g.get("GroupId")
                if gid:
                    used_sg_ids.add(gid)
    except ClientError:
        pass

    for sg in sgs:
        sg_id = sg.get("GroupId", "Unknown")
        sg_name = sg.get("GroupName", "Unknown")

        # SG-005 unused (not attached)
        if used_sg_ids and sg_id not in used_sg_ids:
            _add(
                findings, add_finding, "SG-005", sg_id,
                title_lines=[
                    "Security group appears unused (not attached to any network interface).",
                    "Unused security groups increase clutter and accidental reuse risk."
                ],
                evidence_lines=[
                    f"GroupId: {sg_id}",
                    f"GroupName: {sg_name}",
                    "Not found in attached ENI groups (PoC heuristic)."
                ],
                impact_lines=[
                    "Unused groups can be reused later without review.",
                    "Stale rules may be overly permissive and overlooked."
                ],
                fix_lines=[
                    "Remove unused security groups after verifying they’re not required.",
                    "Apply naming/owner tagging standards for SG lifecycle management.",
                    "Review rule hygiene periodically."
                ]
            )

        # inbound checks
        for perm in sg.get("IpPermissions", []):
            proto = perm.get("IpProtocol")
            fp = perm.get("FromPort")
            tp = perm.get("ToPort")
            ip_ranges = perm.get("IpRanges", [])

            # SG-003 all inbound (all traffic open)
            if proto == "-1" and _is_world_open(ip_ranges):
                _add(
                    findings, add_finding, "SG-003", sg_id,
                    title_lines=[
                        "Security group allows ALL inbound traffic from the internet.",
                        "This exposes all ports/protocols publicly."
                    ],
                    evidence_lines=[
                        f"GroupId: {sg_id}",
                        f"GroupName: {sg_name}",
                        "Inbound: ALL (-1) from 0.0.0.0/0"
                    ],
                    impact_lines=[
                        "Greatly increases risk of exploitation and unauthorized access.",
                        "Can expose admin services, databases, and internal apps."
                    ],
                    fix_lines=[
                        "Remove all-traffic inbound rules.",
                        "Allow only required ports and restrict sources to trusted CIDRs.",
                        "Separate public-facing and internal resources into different SGs."
                    ]
                )

            # SG-001 SSH open
            if fp == 22 and tp == 22 and _is_world_open(ip_ranges):
                _add(
                    findings, add_finding, "SG-001", sg_id,
                    title_lines=[
                        "Inbound SSH (port 22) is open to the public internet.",
                        "Administrative access should not be globally exposed."
                    ],
                    evidence_lines=[
                        f"GroupId: {sg_id}",
                        f"GroupName: {sg_name}",
                        "Inbound: TCP 22 from 0.0.0.0/0"
                    ],
                    impact_lines=[
                        "Common brute-force and credential-stuffing target.",
                        "Can lead to remote compromise if credentials are weak or reused."
                    ],
                    fix_lines=[
                        "Restrict SSH to trusted IP ranges only.",
                        "Use VPN or AWS SSM Session Manager instead of public SSH.",
                        "Remove 0.0.0.0/0 rules unless explicitly required."
                    ]
                )

            # SG-002 RDP open
            if fp == 3389 and tp == 3389 and _is_world_open(ip_ranges):
                _add(
                    findings, add_finding, "SG-002", sg_id,
                    title_lines=[
                        "Inbound RDP (port 3389) is open to the public internet.",
                        "RDP exposure is commonly abused by ransomware operators."
                    ],
                    evidence_lines=[
                        f"GroupId: {sg_id}",
                        f"GroupName: {sg_name}",
                        "Inbound: TCP 3389 from 0.0.0.0/0"
                    ],
                    impact_lines=[
                        "Enables brute-force and remote takeover attempts.",
                        "Increases likelihood of lateral movement once compromised."
                    ],
                    fix_lines=[
                        "Restrict RDP to trusted IP ranges only.",
                        "Use VPN/SSM instead of exposing RDP publicly.",
                        "Monitor authentication attempts and enforce strong controls."
                    ]
                )

        # outbound check SG-004 (unrestricted outbound)
        for perm in sg.get("IpPermissionsEgress", []):
            proto = perm.get("IpProtocol")
            ip_ranges = perm.get("IpRanges", [])
            if proto == "-1" and _is_world_open(ip_ranges):
                _add(
                    findings, add_finding, "SG-004", sg_id,
                    title_lines=[
                        "Security group allows unrestricted outbound traffic (all traffic to 0.0.0.0/0).",
                        "This allows broad egress to the internet."
                    ],
                    evidence_lines=[
                        f"GroupId: {sg_id}",
                        f"GroupName: {sg_name}",
                        "Outbound: ALL (-1) to 0.0.0.0/0"
                    ],
                    impact_lines=[
                        "If compromised, instances can exfiltrate data easily.",
                        "Can allow command-and-control traffic to malicious endpoints."
                    ],
                    fix_lines=[
                        "Restrict outbound rules to required destinations and ports.",
                        "Use VPC endpoints for AWS services to reduce internet egress.",
                        "Monitor outbound traffic for anomalies."
                    ]
                )
