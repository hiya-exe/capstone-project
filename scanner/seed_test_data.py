import sqlite3

DB_NAME = "capstone.db"

connection = sqlite3.connect(DB_NAME)
cursor = connection.cursor()

# Create a completed sample scan
cursor.execute("""
INSERT INTO scans (
    aws_profile,
    aws_account_id,
    region,
    service,
    scan_type,
    started_at,
    completed_at,
    status
)
VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
""", (
    "test-profile",
    "123456789012",
    "ca-central-1",
    "VPC,S3",
    "test",
    "completed"
))

scan_id = cursor.lastrowid

# Create sample AWS resources
resources = [
    (scan_id, "VPC", "subnet-0123456789abcdef0", "Public Test Subnet", "ca-central-1"),
    (scan_id, "VPC", "vpc-0123456789abcdef0", "Test VPC", "ca-central-1"),
    (scan_id, "S3", "sample-public-bucket", "Public Test Bucket", "ca-central-1"),
    (
        scan_id,
        "S3",
        "sample-versioning-disabled-bucket",
        "Versioning Test Bucket",
        "ca-central-1"
    )
]

cursor.executemany("""
INSERT INTO resources (
    scan_id,
    service,
    aws_resource_id,
    resource_name,
    region
)
VALUES (?, ?, ?, ?, ?)
""", resources)

cursor.execute(
    "SELECT resource_id, aws_resource_id FROM resources WHERE scan_id = ?",
    (scan_id,)
)

resource_ids = {
    aws_resource_id: resource_id
    for resource_id, aws_resource_id in cursor.fetchall()
}

# Create sample findings
findings = [
    (
        scan_id,
        resource_ids["subnet-0123456789abcdef0"],
        "VPC-001",
        "Public subnet exposed to the internet",
        "High",
        "Failed",
        "Move private resources to a private subnet, disable automatic public "
        "IP assignment, and review route-table and Security Group rules.",
        "The subnet route table contains a route to 0.0.0.0/0 through an "
        "Internet Gateway. Resources may become reachable from the internet."
    ),
    (
        scan_id,
        resource_ids["vpc-0123456789abcdef0"],
        "VPC-002",
        "VPC Flow Logs are disabled",
        "Medium",
        "Failed",
        "Enable VPC Flow Logs and deliver them to CloudWatch Logs or S3.",
        "No active VPC Flow Log was found. Suspicious network activity may be "
        "harder to investigate without traffic records."
    ),
    (
        scan_id,
        resource_ids["sample-public-bucket"],
        "S3-001",
        "S3 bucket allows public access",
        "Critical",
        "Failed",
        "Enable S3 Block Public Access, remove public ACLs, and restrict the "
        "bucket policy to approved IAM principals.",
        "The bucket policy or public access configuration permits public "
        "access. Unauthorized users may be able to access stored objects."
    ),
    (
        scan_id,
        resource_ids["sample-versioning-disabled-bucket"],
        "S3-002",
        "S3 bucket versioning is disabled",
        "Medium",
        "Failed",
        "Enable bucket versioning and configure lifecycle rules for older "
        "object versions.",
        "Bucket versioning is disabled. Deleted or overwritten objects may not "
        "be recoverable."
    )
]

cursor.executemany("""
INSERT INTO findings (
    scan_id,
    resource_id,
    finding_code,
    title,
    severity,
    compliance_status,
    remediation,
    description
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
""", findings)

# Create CIS controls
controls = [
    ("CIS 12.1", "Manage network infrastructure"),
    ("CIS 8.2", "Collect audit logs"),
    ("CIS 3.3", "Configure data access control lists"),
    ("CIS 2.1", "Establish and maintain a data management process")
]

cursor.executemany("""
INSERT INTO cis_controls (
    control_code,
    control_name
)
VALUES (?, ?)
""", controls)

cursor.execute("SELECT cis_id, control_code FROM cis_controls")
cis_ids = {
    control_code: cis_id
    for cis_id, control_code in cursor.fetchall()
}

cursor.execute("SELECT finding_id, finding_code FROM findings")
finding_ids = {
    finding_code: finding_id
    for finding_id, finding_code in cursor.fetchall()
}

mappings = [
    (finding_ids["VPC-001"], cis_ids["CIS 12.1"]),
    (finding_ids["VPC-002"], cis_ids["CIS 8.2"]),
    (finding_ids["S3-001"], cis_ids["CIS 3.3"]),
    (finding_ids["S3-002"], cis_ids["CIS 2.1"])
]

cursor.executemany("""
INSERT INTO finding_cis_mappings (
    finding_id,
    cis_id
)
VALUES (?, ?)
""", mappings)

connection.commit()
connection.close()

print("Sample VPC and S3 findings added successfully.")