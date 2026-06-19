from flask import Flask, render_template, send_file, redirect, url_for, jsonify, request
import sqlite3
import subprocess
import os
import json
from datetime import datetime

app = Flask(__name__)

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

@app.route("/")
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT scan_id, aws_profile, aws_account_id, region, service,
           scan_type, started_at, completed_at, status
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
    subprocess.run(["python", "scanner.py"], check=False)
    return redirect(url_for("dashboard"))

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
