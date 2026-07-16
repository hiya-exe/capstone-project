# AWS Security Posture Dashboard — Data Flow & Code Integration

## Data Flow Overview

The project follows this data flow:

```text
AWS Account
   ↓
Boto3 Security Checks
   ↓
scanner.py
   ↓
MySQL Database
   ↓
app.py Flask Backend
   ↓
dashboard.html
   ↓
User Dashboard

## Database Design and ER Diagram

The project uses a MySQL database named `cloud_security_posture_db` to store AWS scan information, discovered resources, security findings, CIS controls, and compliance mappings.

### Database Tables

- `scans` — stores information about each AWS security scan.
- `resources` — stores AWS resources discovered during a scan.
- `findings` — stores security issues, severity, evidence, and remediation guidance.
- `cis_controls` — stores CIS Controls v8 information.
- `finding_cis_mappings` — connects security findings to the applicable CIS controls.

### Database Relationships

- One scan can contain multiple resources.
- One scan can generate multiple findings.
- One resource can have multiple findings.
- One finding can map to multiple CIS controls.
- One CIS control can be associated with multiple findings.

### ER Diagram

[View the finalized ER Diagram](ER_DIAGRAM1.pdf)
