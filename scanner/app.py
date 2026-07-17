from flask import Flask, render_template, send_file, redirect, url_for, jsonify, request, Response
import db  # MySQL connection wrapper (see db.py)
import subprocess
import os
import json
from datetime import datetime

app = Flask(__name__)

from scanner.profiles import PROFILES, GENERAL_PROFILE

import importlib.util as _importlib_util

_scanner_spec = _importlib_util.spec_from_file_location(
    "scanner_cli", os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.py")
)
scanner_cli = _importlib_util.module_from_spec(_scanner_spec)
_scanner_spec.loader.exec_module(scanner_cli)

SERVICE_CHECKS = {
    "EC2": scanner_cli.check_ec2,
    "IAM": scanner_cli.check_iam,
    "RDS": scanner_cli.check_rds,
    "EBS": scanner_cli.check_ebs,
    "S3": scanner_cli.check_s3,
    "SG": scanner_cli.check_sg,
    "VPC": scanner_cli.check_vpc,
    "KMS": scanner_cli.check_kms,
    "LOG": scanner_cli.check_cloudtrail,
}

# Single source of truth for multi-step attack chains: which ordered sets of
# finding codes, if all present on a scan, describe a real attack path. The
# dashboard template renders this list (injected as JSON) instead of keeping
# its own copy, so the Attack Path Analysis section and the severity-card
# callout can never drift apart.
ATTACK_CHAINS = [
    {
        "name": "Internet Breach to Data Exfiltration",
        "codes": ["EC2-001", "S3-001", "LOG-001"],
        "sev": "critical",
        "mitre": "Initial Access → Lateral Movement → Exfiltration",
        "desc": "An attacker brute-forces an exposed SSH/RDP port to gain a shell on an EC2 instance, then pivots to an S3 bucket missing public-access controls to exfiltrate data. No CloudTrail trail means the entire attack goes unrecorded.",
    },
    {
        "name": "SSH Breach with No Network Visibility",
        "codes": ["SG-001", "VPC-001", "LOG-001"],
        "sev": "critical",
        "mitre": "Initial Access → Defense Evasion",
        "desc": "SSH is open to the internet, VPC Flow Logs are disabled, and CloudTrail is absent. An attacker gains access through port 22, moves laterally inside the VPC, and leaves no network or API trail for investigators to follow.",
    },
    {
        "name": "Root Account Total Takeover",
        "codes": ["IAM-004", "IAM-001"],
        "sev": "critical",
        "mitre": "Privilege Escalation → Impact",
        "desc": "The root account lacks MFA or has active access keys, and wildcard IAM policies exist. A single credential leak hands an attacker unlimited, policy-unrestricted control of the entire AWS account — billing, data, and all resources.",
    },
    {
        "name": "Public Database Direct Breach",
        "codes": ["RDS-001", "RDS-002"],
        "sev": "critical",
        "mitre": "Initial Access → Collection",
        "desc": "A database is publicly accessible and its storage is unencrypted. An attacker can connect directly from the internet, brute-force credentials, and read every record. No intermediate host compromise is required.",
    },
    {
        "name": "Open Network + Blind Monitoring",
        "codes": ["SG-003", "VPC-001"],
        "sev": "critical",
        "mitre": "Initial Access → Defense Evasion",
        "desc": "A security group allows all inbound traffic from the internet while VPC Flow Logs are off. Any service on any port is reachable, and all resulting connections — including attacker traffic — are invisible to defenders.",
    },
    {
        "name": "Public Snapshot Data Leak",
        "codes": ["EBS-004", "EBS-001"],
        "sev": "critical",
        "mitre": "Collection → Exfiltration",
        "desc": "A snapshot is publicly accessible and the underlying volume is unencrypted. Any AWS account in the world can copy the snapshot right now and read the raw data — no credentials from the victim account required.",
    },
    {
        "name": "Stale Credential Silent Compromise",
        "codes": ["IAM-003", "IAM-001"],
        "sev": "high",
        "mitre": "Persistence → Privilege Escalation",
        "desc": "Active access keys have not been rotated in over 90 days, and they are attached to identities with wildcard policies. A key leaked through a code repository or log gives an attacker broad permissions and may go unnoticed for months.",
    },
    {
        "name": "Persistent Exposure Without Logging",
        "codes": ["EC2-002", "LOG-001"],
        "sev": "high",
        "mitre": "Persistence → Defense Evasion",
        "desc": "An EC2 instance has an unnecessary public IP and no CloudTrail trail is recording API calls. An attacker with access can operate persistently — creating resources, modifying policies — with no audit record to trigger alerts.",
    },
    {
        "name": "Identity Misuse via Weak Controls",
        "codes": ["IAM-001", "IAM-002"],
        "sev": "high",
        "mitre": "Privilege Escalation → Defense Evasion",
        "desc": "Wildcard IAM policies grant near-unlimited permissions, and the affected users have no MFA. A phished or guessed password becomes an immediate account-wide privilege escalation with no second factor to block it.",
    },
    {
        "name": "KMS Key Loss Causing Data Lockout",
        "codes": ["KMS-003", "EBS-001"],
        "sev": "high",
        "mitre": "Impact → Data Destruction",
        "desc": "A KMS key is pending deletion while unencrypted EBS volumes exist in the account. Deletion permanently destroys the key and any data it protects, while unencrypted volumes are already exposed — leaving the environment in an irrecoverable state.",
    },
    {
        "name": "Auto-Exposed Subnet with Open Security Group",
        "codes": ["VPC-003", "SG-001"],
        "sev": "medium",
        "mitre": "Initial Access",
        "desc": "A subnet automatically assigns public IPs to every new instance, and a security group allows SSH from the internet. Any workload deployed in this subnet is immediately reachable over SSH from anywhere, with no deliberate action from the operator.",
    },
]

def compute_chain_summary(findings):
    """Which attack chains are actually triggered by this scan's findings.

    Mirrors the old renderChains() JS logic exactly: a chain is "triggered"
    when every code in its ordered `codes` list is present among the scan's
    finding_codes, regardless of compliance_status (remediated findings still
    count — matching the dashboard's existing chain-list behavior so this
    summary never disagrees with the section it links to).
    """
    active_codes = {f["finding_code"] for f in findings}
    triggered = [c for c in ATTACK_CHAINS if all(code in active_codes for code in c["codes"])]
    critical_codes = {f["finding_code"] for f in findings if f["severity"] == "Critical"}
    return {
        "finding_count": len({code for c in triggered for code in c["codes"]}),
        "chain_count": len(triggered),
        "danger": any(c["codes"][-1] in critical_codes for c in triggered),
    }

JSON_PATH = "findings.json"

# Label/framework only (no severity_overrides/framework_mapping payload) for
# the dashboard's client-side profile-preview control.
PROFILE_META = {k: {"label": v["label"], "framework": v["framework"]} for k, v in PROFILES.items()}

def get_db_connection():
    return db.connect()

def calculate_score(summary):
    deduction = (
        summary.get("Critical", 0) * 30 +
        summary.get("High", 0) * 20 +
        summary.get("Medium", 0) * 10 +
        summary.get("Low", 0) * 5
    )
    score = max(0, 100 - deduction)
    if score >= 80:
        status = "Good"
    elif score >= 50:
        status = "Fair"
    else:
        status = "Poor"
    return score, status

def get_risk_delta(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 2")
    rows = cursor.fetchall()
    if len(rows) < 2:
        return None

    def fetch_summary(scan_id):
        cursor.execute("SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id = ? AND compliance_status != 'REMEDIATED' GROUP BY severity", (scan_id,))
        s = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for r in cursor.fetchall():
            s[r["severity"]] = r["count"]
        return s

    current = fetch_summary(rows[0]["scan_id"])
    previous = fetch_summary(rows[1]["scan_id"])
    curr_score, _ = calculate_score(current)
    prev_score, _ = calculate_score(previous)
    return {
        "current": current,
        "previous": previous,
        "delta": {sev: current[sev] - previous[sev] for sev in current},
        "score_change": curr_score - prev_score,
    }

def build_business_summary(conn, scan_id, override_profile=None):
    """Build the business-impact summary for a scan.

    Always recomputes severity/business_mapping live from each finding's
    (finding_code, db_environment) via scanner_cli.compute_severity, rather
    than reading the stored f.severity/f.business_mapping columns. This
    makes the "as scanned" case and the `override_profile` preview case go
    through the exact same code path — passing override_profile=None just
    means "use the profile the scan was actually run with".
    """
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_id, aws_account_id, region, started_at, completed_at, business_profile
        FROM scans WHERE scan_id = ?
    """, (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        return None

    profile_name = override_profile if override_profile in PROFILES else (scan["business_profile"] or GENERAL_PROFILE)
    profile = PROFILES[profile_name]
    is_preview = override_profile is not None and override_profile != (scan["business_profile"] or GENERAL_PROFILE)

    cursor.execute("""
        SELECT f.finding_code, f.title, f.db_environment, r.aws_resource_id AS resource
        FROM findings f
        LEFT JOIN resources r ON f.resource_id = r.resource_id
        WHERE f.scan_id = ? AND f.compliance_status != 'REMEDIATED'
    """, (scan_id,))
    finding_rows = cursor.fetchall()

    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    scored_findings = []
    for row in finding_rows:
        severity = scanner_cli.compute_severity(row["finding_code"], profile_name, row["db_environment"])
        if severity in summary:
            summary[severity] += 1
        scored_findings.append({
            "finding_code": row["finding_code"],
            "title": row["title"],
            "resource": row["resource"],
            "severity": severity,
            "business_mapping": profile["framework_mapping"].get(row["finding_code"]),
        })
    total_findings = sum(summary.values())
    score, status = calculate_score(summary)

    top_rank = {"Critical": 1, "High": 2}
    top_findings = sorted(
        (f for f in scored_findings if f["severity"] in top_rank),
        key=lambda f: top_rank[f["severity"]],
    )[:5]

    if status == "Good":
        posture_line = "Your environment is in a strong security position overall, with only minor issues remaining."
    elif status == "Fair":
        posture_line = "Your environment has a moderate risk profile: core controls are partially in place, but several gaps remain exploitable today."
    else:
        posture_line = "Your environment is in a high-risk state. Multiple significant security gaps are currently exploitable."

    framework = profile["framework"]
    impact_lines = []
    if summary["Critical"]:
        impact_lines.append(
            f"{summary['Critical']} Critical finding(s) — issues an attacker could exploit immediately "
            f"(open databases, exposed admin ports, unrestricted IAM access). Left unresolved, these create "
            f"direct exposure to data breach, ransomware, or full account takeover, with regulatory and "
            f"reputational consequences under {framework}."
        )
    if summary["High"]:
        impact_lines.append(
            f"{summary['High']} High finding(s) — these significantly widen the attack surface (missing "
            f"encryption, public network exposure). They are a common entry point in real-world breaches "
            f"even though they typically require a second step to fully exploit."
        )
    if summary["Medium"]:
        impact_lines.append(
            f"{summary['Medium']} Medium finding(s) — these weaken resilience and auditability (backup "
            f"retention, patching, logging gaps). They don't grant immediate access but slow down detection "
            f"and recovery when something does go wrong."
        )
    if summary["Low"]:
        impact_lines.append(
            f"{summary['Low']} Low finding(s) — housekeeping issues that add operational risk over time but "
            f"carry minimal immediate exposure."
        )
    if not impact_lines:
        impact_lines.append("No outstanding findings were detected on this scan.")

    recommended_actions = []
    if summary["Critical"]:
        recommended_actions.append("Remediate all Critical findings first — they are actively exploitable today and pose the most direct business risk.")
    if summary["Critical"] or summary["High"]:
        recommended_actions.append("Close public network exposure (open security groups, public RDS/S3) before addressing internal hardening items.")
        recommended_actions.append("Enable encryption at rest across EBS, RDS, S3, and KMS to limit damage if a resource is ever leaked or copied.")
    recommended_actions.append("Establish account-wide CloudTrail logging so any future incident can actually be investigated.")
    if summary["Medium"] or summary["Low"]:
        recommended_actions.append("Schedule the remaining Medium/Low findings into routine maintenance — they reduce long-term risk without urgent timelines.")

    benefit_statement = (
        f"Fixing the Critical and High findings is the highest-leverage action available right now: it "
        f"directly reduces breach likelihood, supports your {framework} compliance posture, and avoids the "
        f"downstream cost of incident response, regulatory fines, and lost customer trust that follow a real "
        f"exploit of these same gaps."
    )

    return {
        "scan_id": scan["scan_id"],
        "account_id": scan["aws_account_id"],
        "region": scan["region"],
        "completed_at": scan["completed_at"],
        "business_profile_label": profile["label"],
        "framework": framework,
        "is_preview": is_preview,
        "score": score,
        "status": status,
        "summary": summary,
        "total_findings": total_findings,
        "posture_line": posture_line,
        "impact_lines": impact_lines,
        "top_findings": top_findings,
        "recommended_actions": recommended_actions,
        "benefit_statement": benefit_statement,
    }

def render_business_summary_text(s):
    lines = []
    lines.append("AWS SECURITY POSTURE — BUSINESS IMPACT SUMMARY")
    lines.append("=" * 50)
    lines.append(f"Scan #{s['scan_id']}  |  Account {s['account_id']}  |  Region {s['region']}")
    lines.append(f"Completed: {s['completed_at']}")
    lines.append(f"Business Context: {s['business_profile_label']} ({s['framework']})")
    lines.append("")
    lines.append(f"Security Score: {s['score']}/100 ({s['status']})")
    lines.append(f"Total Findings: {s['total_findings']}  "
                 f"(Critical {s['summary']['Critical']}, High {s['summary']['High']}, "
                 f"Medium {s['summary']['Medium']}, Low {s['summary']['Low']})")
    lines.append("")
    lines.append("OVERVIEW")
    lines.append("-" * 50)
    lines.append(s["posture_line"])
    lines.append("")
    lines.append("BUSINESS IMPACT BY SEVERITY")
    lines.append("-" * 50)
    for line in s["impact_lines"]:
        lines.append(f"- {line}")
    lines.append("")
    if s["top_findings"]:
        lines.append("TOP FINDINGS REQUIRING ATTENTION")
        lines.append("-" * 50)
        for f in s["top_findings"]:
            mapping = f" [{f['business_mapping']}]" if f.get("business_mapping") else ""
            lines.append(f"- [{f['severity']}] {f['finding_code']} — {f['title']} (resource: {f['resource']}){mapping}")
        lines.append("")
    lines.append("RECOMMENDED ACTIONS")
    lines.append("-" * 50)
    for i, action in enumerate(s["recommended_actions"], 1):
        lines.append(f"{i}. {action}")
    lines.append("")
    lines.append("WHY THIS MATTERS TO THE BUSINESS")
    lines.append("-" * 50)
    lines.append(s["benefit_statement"])
    lines.append("")
    return "\n".join(lines)

@app.route("/api/business-summary")
def api_business_summary():
    override_profile = request.args.get("profile")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "No scan data found"}), 404
    summary = build_business_summary(conn, row["scan_id"], override_profile=override_profile)
    conn.close()
    return jsonify(summary)

@app.route("/download-business-report")
def download_business_report():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        return "No scan data found. Run a scan first.", 404
    summary = build_business_summary(conn, row["scan_id"])
    conn.close()
    report_text = render_business_summary_text(summary)
    return Response(
        report_text,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=business_summary_scan_{summary['scan_id']}.txt"},
    )

@app.route("/")
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT scan_id, aws_profile, aws_account_id, region, service,
           scan_type, started_at, completed_at, status, business_profile
    FROM scans ORDER BY scan_id DESC LIMIT 1
    """)
    latest_scan = cursor.fetchone()

    if not latest_scan:
        conn.close()
        return render_template(
            "dashboard.html",
            no_data=True,
            latest_scan=None,
            summary={"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            findings=[],
            security_score=0,
            security_status="N/A",
            total_findings=0,
            risk_delta=None,
            scan_history=[],
            services=[],
            severities=["Critical", "High", "Medium", "Low"],
            profiles=PROFILES,
            selected_profile=GENERAL_PROFILE,
            profile_meta=PROFILE_META,
            attack_chains=ATTACK_CHAINS,
            chain_summary=compute_chain_summary([]),
        )

    scan_id = latest_scan["scan_id"]

    cursor.execute("SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id = ? AND compliance_status != 'REMEDIATED' GROUP BY severity", (scan_id,))
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in cursor.fetchall():
        summary[row["severity"]] = row["count"]

    total_findings = sum(summary.values())
    security_score, security_status = calculate_score(summary)

    cursor.execute("""
    SELECT
        f.finding_id,
        f.finding_code,
        f.title,
        f.severity,
        f.compliance_status,
        f.remediation,
        f.description,
        f.detected_at,
        f.evidence,
        f.business_framework,
        f.business_mapping,
        f.db_engine,
        f.db_environment,
        f.db_engine_note,
        r.service,
        r.aws_resource_id AS resource,
        GROUP_CONCAT(c.control_code, ', ') AS cis_mapping
    FROM findings f
    LEFT JOIN resources r ON f.resource_id = r.resource_id
    LEFT JOIN finding_cis_mappings m ON f.finding_id = m.finding_id
    LEFT JOIN cis_controls c ON m.cis_id = c.cis_id
    WHERE f.scan_id = ?
    GROUP BY f.finding_id
    ORDER BY CASE f.severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        ELSE 5
    END, f.detected_at DESC
    """, (scan_id,))
    findings = cursor.fetchall()

    chain_summary = compute_chain_summary(findings)
    services = sorted({f["service"] for f in findings if f["service"]})
    severities = ["Critical", "High", "Medium", "Low"]
    risk_delta = get_risk_delta(conn)

    cursor.execute("""
    SELECT
        s.scan_id, s.started_at,
        SUM(CASE WHEN f.severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN f.severity = 'High' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN f.severity = 'Medium' THEN 1 ELSE 0 END) AS medium,
        SUM(CASE WHEN f.severity = 'Low' THEN 1 ELSE 0 END) AS low,
        COUNT(f.finding_id) AS total
    FROM scans s
    LEFT JOIN findings f ON s.scan_id = f.scan_id
    GROUP BY s.scan_id
    ORDER BY s.scan_id DESC LIMIT 10
    """)
    scan_history = [dict(r) for r in cursor.fetchall()]
    scan_history.reverse()
    conn.close()

    return render_template(
        "dashboard.html",
        no_data=False,
        latest_scan=latest_scan,
        summary=summary,
        findings=findings,
        security_score=security_score,
        security_status=security_status,
        total_findings=total_findings,
        risk_delta=risk_delta,
        scan_history=scan_history,
        services=services,
        severities=severities,
        profiles=PROFILES,
        selected_profile=latest_scan["business_profile"] or GENERAL_PROFILE,
        profile_meta=PROFILE_META,
        attack_chains=ATTACK_CHAINS,
        chain_summary=chain_summary,
    )

@app.route("/api/findings")
def api_findings():
    severity = request.args.get("severity", "all")
    service = request.args.get("service", "all")
    code = request.args.get("code", "all")
    # Optional: re-weight severity/mapping under a different business profile
    # than the one the scan was run with, without re-scanning AWS. See
    # scanner.compute_severity — profile/environment are a pure relabeling
    # of the same stored finding, so this only needs data already in the DB.
    preview_profile = request.args.get("profile")
    if preview_profile not in PROFILES:
        preview_profile = None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify([])
    scan_id = row["scan_id"]

    query = """
    SELECT f.finding_id, f.finding_code, f.title, f.severity,
           f.compliance_status, f.remediation, f.description,
           f.detected_at, f.evidence, f.business_framework, f.business_mapping,
           f.db_environment, r.service, r.aws_resource_id AS resource,
           GROUP_CONCAT(c.control_code, ', ') AS cis_mapping
    FROM findings f
    LEFT JOIN resources r ON f.resource_id = r.resource_id
    LEFT JOIN finding_cis_mappings m ON f.finding_id = m.finding_id
    LEFT JOIN cis_controls c ON m.cis_id = c.cis_id
    WHERE f.scan_id = ?
    """
    params = [scan_id]
    # When previewing under a different profile, severity is recomputed
    # after the query, so filtering on the stored f.severity column here
    # would filter against the wrong (pre-recompute) value.
    if severity != "all" and not preview_profile:
        query += " AND f.severity = ?"
        params.append(severity)
    if service != "all":
        query += " AND r.service = ?"
        params.append(service)
    if code != "all":
        query += " AND f.finding_code = ?"
        params.append(code)

    query += " GROUP BY f.finding_id"
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    if preview_profile:
        profile = PROFILES[preview_profile]
        for r in rows:
            r["severity"] = scanner_cli.compute_severity(r["finding_code"], preview_profile, r.get("db_environment"))
            r["business_framework"] = profile["framework"]
            r["business_mapping"] = profile["framework_mapping"].get(r["finding_code"])
        if severity != "all":
            rows = [r for r in rows if r["severity"] == severity]

    severity_rank = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    rows.sort(key=lambda r: severity_rank.get(r["severity"], 5))
    return jsonify(rows)

@app.route("/api/history")
def api_history():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT s.scan_id, s.started_at,
           SUM(CASE WHEN f.severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
           SUM(CASE WHEN f.severity = 'High' THEN 1 ELSE 0 END) AS high,
           SUM(CASE WHEN f.severity = 'Medium' THEN 1 ELSE 0 END) AS medium,
           SUM(CASE WHEN f.severity = 'Low' THEN 1 ELSE 0 END) AS low
    FROM scans s
    LEFT JOIN findings f ON s.scan_id = f.scan_id
    GROUP BY s.scan_id ORDER BY s.scan_id ASC LIMIT 20
    """)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route("/api/verify/<finding_id>", methods=["POST"])
def verify_finding(finding_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.finding_code, r.aws_resource_id AS resource
        FROM findings f
        LEFT JOIN resources r ON f.resource_id = r.resource_id
        WHERE f.finding_id = ?
    """, (finding_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Finding not found"}), 404

    finding_code = row["finding_code"]
    resource = row["resource"]
    prefix = finding_code.split("-")[0]
    check_fn = SERVICE_CHECKS.get(prefix)
    if not check_fn:
        return jsonify({"error": "No live check available for this finding type"}), 400

    fresh_findings = []
    try:
        check_fn(fresh_findings)
    except Exception as e:
        return jsonify({"error": f"Rescan failed: {e}"}), 502

    still_present = any(
        f["finding_code"] == finding_code and f["resource"] == resource
        for f in fresh_findings
    )
    return jsonify({
        "resolved": not still_present,
        "finding_code": finding_code,
        "resource": resource,
    })

@app.route("/api/remediate/<finding_id>", methods=["POST"])
def remediate_finding(finding_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE findings SET compliance_status = 'REMEDIATED' WHERE finding_id = ?", (finding_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "finding_id": finding_id})

@app.route("/api/reset-scans", methods=["POST"])
def reset_scans():
    conn = get_db_connection()
    cursor = conn.cursor()
    # TRUNCATE clears the rows and resets AUTO_INCREMENT back to 1 (the MySQL
    # equivalent of deleting rows + clearing sqlite_sequence). FK checks are
    # disabled briefly so the child tables can be truncated regardless of order.
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
    cursor.execute("TRUNCATE TABLE finding_cis_mappings")
    cursor.execute("TRUNCATE TABLE findings")
    cursor.execute("TRUNCATE TABLE resources")
    cursor.execute("TRUNCATE TABLE scans")
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/scan")
def run_scan():
    profile = request.args.get("profile", GENERAL_PROFILE)
    if profile not in PROFILES:
        profile = GENERAL_PROFILE
    subprocess.run(["python", "scanner.py", profile], check=False)
    return redirect(url_for("dashboard", scanned="1"))

@app.route("/download-summary")
def download_summary():
    if os.path.exists(JSON_PATH):
        return send_file(JSON_PATH, as_attachment=True)
    return "No summary report found. Run a scan first.", 404

@app.route("/export")
def export_filtered():
    severity = request.args.get("severity", "all")
    service = request.args.get("service", "all")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        return "No scan data found. Run a scan first.", 404
    scan_id = row["scan_id"]

    query = """
    SELECT f.finding_code, f.title, f.severity, f.compliance_status,
           f.remediation, f.description, f.detected_at, f.evidence,
           r.service, r.aws_resource_id AS resource
    FROM findings f
    LEFT JOIN resources r ON f.resource_id = r.resource_id
    WHERE f.scan_id = ?
    """
    params = [scan_id]
    if severity != "all":
        query += " AND f.severity = ?"
        params.append(severity)
    if service != "all":
        query += " AND r.service = ?"
        params.append(service)

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()

    export_data = {
        "exported_at": datetime.now().astimezone().isoformat(),
        "filters": {"severity": severity, "service": service},
        "total": len(rows),
        "findings": rows,
    }
    tmp_path = "/tmp/export_findings.json"
    with open(tmp_path, "w") as f:
        json.dump(export_data, f, indent=2)

    return send_file(tmp_path, as_attachment=True, download_name="findings_export.json")

@app.route("/download-scan-report/<int:scan_id>")
def download_scan_report(scan_id):
    """Business-summary text report for any past scan (not just the latest)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id FROM scans WHERE scan_id = ?", (scan_id,))
    if not cursor.fetchone():
        conn.close()
        return "Scan not found.", 404
    summary = build_business_summary(conn, scan_id)
    conn.close()
    report_text = render_business_summary_text(summary)
    return Response(
        report_text,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=business_summary_scan_{scan_id}.txt"},
    )

@app.route("/download-scan-json/<int:scan_id>")
def download_scan_json(scan_id):
    """Raw JSON export of any past scan, built from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_id, aws_profile, aws_account_id, region, service, scan_type,
               started_at, completed_at, status, business_profile
        FROM scans WHERE scan_id = ?
    """, (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        conn.close()
        return "Scan not found.", 404
    cursor.execute("""
        SELECT f.finding_code, f.title, f.severity, f.compliance_status,
               f.description, f.remediation, f.evidence, f.detected_at,
               f.business_framework, f.business_mapping,
               f.db_engine, f.db_environment, f.db_engine_note,
               r.service, r.aws_resource_id AS resource
        FROM findings f
        LEFT JOIN resources r ON f.resource_id = r.resource_id
        WHERE f.scan_id = ?
        ORDER BY CASE f.severity
                   WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                   WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END
    """, (scan_id,))
    findings = [dict(r) for r in cursor.fetchall()]
    conn.close()
    export_data = {
        "scan": dict(scan),
        "total_findings": len(findings),
        "findings": findings,
    }
    return Response(
        json.dumps(export_data, indent=2, default=str),
        mimetype="application/json; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_findings.json"},
    )

if __name__ == "__main__":
    app.run(debug=True)