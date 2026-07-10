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
