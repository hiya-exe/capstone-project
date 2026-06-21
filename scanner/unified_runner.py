import json
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime

DB_PATH = Path("capstone.db")
JSON_PATH = Path("findings.json")
BACKUP_PATH = Path("capstone_week7_backup.db")

now = datetime.now().isoformat()

if not DB_PATH.exists():
    raise FileNotFoundError("capstone.db was not found.")

if not JSON_PATH.exists():
    raise FileNotFoundError("findings.json was not found. Run week7_seed_all_services.py first.")

findings = json.load(open(JSON_PATH, "r", encoding="utf-8"))

# Backup first
shutil.copy(DB_PATH, BACKUP_PATH)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

def table_info(table_name):
    return cur.execute(f"PRAGMA table_info({table_name})").fetchall()

def pk_column(table_name):
    for col in table_info(table_name):
        if col[5] == 1:
            return col[1], col[2]
    return None, None

def fallback_value(col_name, col_type):
    name = col_name.lower()
    col_type = (col_type or "").upper()

    if "time" in name or "date" in name or name.endswith("_at"):
        return now
    if "status" in name:
        return "completed"
    if "count" in name or "total" in name:
        return len(findings)
    if "region" in name:
        return "ca-central-1"
    if "id" in name and "INT" in col_type:
        return 1
    if "INT" in col_type or "REAL" in col_type or "NUM" in col_type:
        return 0

    return "Week 7 all-service integration test"

def insert_dynamic(table_name, values):
    info = table_info(table_name)
    insert_cols = []
    insert_vals = []

    for col in info:
        col_name = col[1]
        col_type = col[2]
        not_null = col[3] == 1
        default_value = col[4]
        is_pk = col[5] == 1
        is_integer_pk = is_pk and "INT" in (col_type or "").upper()

        # Skip auto-increment integer primary keys
        if is_integer_pk:
            continue

        if col_name in values:
            insert_cols.append(col_name)
            insert_vals.append(values[col_name])
        elif not_null and default_value is None:
            insert_cols.append(col_name)
            insert_vals.append(fallback_value(col_name, col_type))

    if insert_cols:
        placeholders = ", ".join(["?"] * len(insert_cols))
        col_list = ", ".join(insert_cols)
        sql = f"INSERT INTO {table_name} ({col_list}) VALUES ({placeholders})"
        cur.execute(sql, insert_vals)
    else:
        cur.execute(f"INSERT INTO {table_name} DEFAULT VALUES")

    pk_name, pk_type = pk_column(table_name)

    if pk_name and pk_name in values and "INT" not in (pk_type or "").upper():
        return values[pk_name]

    return cur.lastrowid

def clean_list(value):
    if isinstance(value, list):
        return ", ".join(value)
    if value is None:
        return ""
    return str(value)

tables = [row[0] for row in cur.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()]

print("Tables found:", tables)
print("Scans columns:", [col[1] for col in table_info("scans")])
print("Resources columns:", [col[1] for col in table_info("resources")])
print("Findings columns:", [col[1] for col in table_info("findings")])

# Clear old demo data safely
cur.execute("PRAGMA foreign_keys = OFF")
for table in ["finding_cis_mappings", "findings", "resources", "scans"]:
    if table in tables:
        cur.execute(f"DELETE FROM {table}")

# Create scan row using only columns that exist
scan_id = insert_dynamic("scans", {
    "scan_id": "week7-all-services-scan",
    "started_at": now,
    "completed_at": now,
    "created_at": now,
    "updated_at": now,
    "status": "completed",
    "scan_status": "completed",
    "region": "ca-central-1",
    "account_id": "week7-test-account",
    "total_findings": len(findings),
    "findings_count": len(findings),
    "name": "Week 7 all-service integration test",
    "scan_name": "Week 7 all-service integration test"
})

print("Created scan_id:", scan_id)

def find_or_create_control(control_text, service):
    if "cis_controls" not in tables:
        return None

    control_cols = [col[1] for col in table_info("cis_controls")]
    pk_name, pk_type = pk_column("cis_controls")

    # Try to find existing control
    for possible_col in ["control_code", "control_id", "code", "cis_control", "control"]:
        if possible_col in control_cols:
            existing = cur.execute(
                f"SELECT {pk_name or possible_col} FROM cis_controls WHERE {possible_col} = ?",
                (control_text,)
            ).fetchone()
            if existing:
                return existing[0]
            break

    values = {
        "control_id": control_text,
        "control_code": control_text,
        "code": control_text,
        "cis_control": control_text,
        "control": control_text,
        "control_title": f"{control_text} mapped control",
        "title": f"{control_text} mapped control",
        "control_description": f"Auto-seeded Week 7 mapping for {service}",
        "description": f"Auto-seeded Week 7 mapping for {service}"
    }

    return insert_dynamic("cis_controls", values)

for finding in findings:
    service = finding.get("service", "Unknown")
    resource_name = finding.get("resource", "unknown-resource")
    rule_id = finding.get("finding_code") or finding.get("rule_id")

    # Create resource row
    resource_pk = insert_dynamic("resources", {
        "scan_id": scan_id,
        "service": service,
        "resource_id": resource_name,
        "resource_identifier": resource_name,
        "resource_name": resource_name,
        "name": resource_name,
        "resource_type": service,
        "type": service,
        "region": "ca-central-1",
        "account_id": "week7-test-account"
    })

    # Create finding row
    finding_pk = insert_dynamic("findings", {
        "scan_id": scan_id,
        "resource_id": resource_pk,
        "finding_code": rule_id,
        "rule_id": rule_id,
        "title": finding.get("title"),
        "description": finding.get("evidence"),
        "evidence": finding.get("evidence"),
        "severity": finding.get("severity", "HIGH"),
        "compliance_status": finding.get("compliance_status", finding.get("status", "FAIL")),
        "status": finding.get("status", "FAIL"),
        "remediation": finding.get("remediation"),
        "detected_at": now,
        "created_at": now,
        "updated_at": now,
        "service": service,
        "cis_mapping": clean_list(finding.get("cis_mapping") or finding.get("cis_controls"))
    })

    # Create CIS mappings if mapping table exists
    if "finding_cis_mappings" in tables:
        controls = finding.get("cis_mapping") or finding.get("cis_controls") or []
        if isinstance(controls, str):
            controls = [controls]

        for control in controls:
            control_pk = find_or_create_control(control, service)

            if control_pk is not None:
                insert_dynamic("finding_cis_mappings", {
                    "finding_id": finding_pk,
                    "control_id": control_pk,
                    "scan_id": scan_id
                })

conn.commit()

count = cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
print("Database findings count:", count)

print("Services seeded from findings.json:")
for service in sorted({finding.get("service", "Unknown") for finding in findings}):
    print(f"- {service}")

conn.close()

print("Done. capstone.db has been updated with Week 7 all-service findings.")
print(f"Backup saved as: {BACKUP_PATH}")
