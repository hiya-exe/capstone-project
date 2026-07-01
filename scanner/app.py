from flask import Flask, render_template, send_file, redirect, url_for, jsonify, request, Response
import sqlite3
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

DB_PATH = "capstone.db"
JSON_PATH = "findings.json"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

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
        cursor.execute("SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id = ? GROUP BY severity", (scan_id,))
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

def build_business_summary(conn, scan_id):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT scan_id, aws_account_id, region, started_at, completed_at, business_profile
        FROM scans WHERE scan_id = ?
    """, (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        return None

    profile = PROFILES.get(scan["business_profile"] or GENERAL_PROFILE, PROFILES[GENERAL_PROFILE])

    cursor.execute("SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id = ? GROUP BY severity", (scan_id,))
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for row in cursor.fetchall():
        summary[row["severity"]] = row["count"]
    total_findings = sum(summary.values())
    score, status = calculate_score(summary)

    cursor.execute("""
        SELECT f.finding_code, f.title, f.severity, r.aws_resource_id AS resource, f.business_mapping
        FROM findings f
        LEFT JOIN resources r ON f.resource_id = r.resource_id
        WHERE f.scan_id = ? AND f.severity IN ('Critical', 'High')
        ORDER BY CASE f.severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 END
        LIMIT 5
    """, (scan_id,))
    top_findings = [dict(r) for r in cursor.fetchall()]

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
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT scan_id FROM scans ORDER BY scan_id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "No scan data found"}), 404
    summary = build_business_summary(conn, row["scan_id"])
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
        )

    scan_id = latest_scan["scan_id"]

    cursor.execute("SELECT severity, COUNT(*) AS count FROM findings WHERE scan_id = ? GROUP BY severity", (scan_id,))
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
    )

@app.route("/api/findings")
def api_findings():
    severity = request.args.get("severity", "all")
    service = request.args.get("service", "all")
    code = request.args.get("code", "all")

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
           f.detected_at, f.evidence, r.service, r.aws_resource_id AS resource,
           GROUP_CONCAT(c.control_code, ', ') AS cis_mapping
    FROM findings f
    LEFT JOIN resources r ON f.resource_id = r.resource_id
    LEFT JOIN finding_cis_mappings m ON f.finding_id = m.finding_id
    LEFT JOIN cis_controls c ON m.cis_id = c.cis_id
    WHERE f.scan_id = ?
    """
    params = [scan_id]
    if severity != "all":
        query += " AND f.severity = ?"
        params.append(severity)
    if service != "all":
        query += " AND r.service = ?"
        params.append(service)
    if code != "all":
        query += " AND f.finding_code = ?"
        params.append(code)

    query += """
    GROUP BY f.finding_id
    ORDER BY CASE f.severity
        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4
        ELSE 5
    END
    """
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
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
        "exported_at": datetime.utcnow().isoformat(),
        "filters": {"severity": severity, "service": service},
        "total": len(rows),
        "findings": rows,
    }
    tmp_path = "/tmp/export_findings.json"
    with open(tmp_path, "w") as f:
        json.dump(export_data, f, indent=2)

    return send_file(tmp_path, as_attachment=True, download_name="findings_export.json")

if __name__ == "__main__":
    app.run(debug=True)