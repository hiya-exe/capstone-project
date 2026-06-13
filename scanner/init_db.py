import sqlite3

DB_NAME = "capstone.db"

connection = sqlite3.connect(DB_NAME)
cursor = connection.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS scans (
    scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
    aws_profile TEXT,
    aws_account_id TEXT,
    region TEXT,
    service TEXT,
    scan_type TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS resources (
    resource_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    service TEXT,
    aws_resource_id TEXT,
    resource_name TEXT,
    region TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    resource_id INTEGER,
    finding_code TEXT,
    title TEXT,
    severity TEXT,
    compliance_status TEXT,
    remediation TEXT,
    description TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (resource_id) REFERENCES resources(resource_id)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS cis_controls (
    cis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    control_code TEXT UNIQUE,
    control_name TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS finding_cis_mappings (
    mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER,
    cis_id INTEGER,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id),
    FOREIGN KEY (cis_id) REFERENCES cis_controls(cis_id)
)
""")

connection.commit()
connection.close()

print("Database tables created successfully.")