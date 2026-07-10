"""Business-context profiles.

Each profile re-weights the same technical findings to reflect what a
specific industry actually cares about, and cites the compliance
framework that industry is regulated under instead of (or alongside)
the generic CIS mapping.
"""

GENERAL_PROFILE = "general"

PROFILES = {
    "general": {
        "label": "General / Startup Baseline",
        "framework": "CIS AWS Foundations Benchmark",
        "severity_overrides": {},
        "framework_mapping": {},
    },
    "healthcare": {
        "label": "Healthcare (HIPAA-regulated)",
        "framework": "HIPAA Security Rule",
        "severity_overrides": {
            "RDS-001": "Critical",
            "RDS-002": "Critical",
            "EBS-001": "Critical",
            "EBS-003": "Critical",
            "EBS-004": "Critical",
            "S3-001": "Critical",
            "S3-002": "Critical",
            "S3-005": "Critical",
            "KMS-002": "Critical",
            "LOG-001": "High",
            "SG-001": "Critical",
            "SG-002": "Critical",
        },
        "framework_mapping": {
            "RDS-001": "45 CFR 164.312(e) - Transmission Security",
            "RDS-002": "45 CFR 164.312(a)(2)(iv) - Encryption at Rest",
            "EBS-001": "45 CFR 164.312(a)(2)(iv) - Encryption at Rest",
            "EBS-003": "45 CFR 164.312(a)(1) - Access Control",
            "EBS-004": "45 CFR 164.312(a)(1) - Access Control",
            "S3-001": "45 CFR 164.312(a)(1) - Access Control",
            "S3-002": "45 CFR 164.312(a)(2)(iv) - Encryption at Rest",
            "S3-005": "45 CFR 164.312(a)(1) - Access Control",
            "KMS-002": "45 CFR 164.312(a)(2)(iv) - Encryption at Rest",
            "LOG-001": "45 CFR 164.312(b) - Audit Controls",
            "SG-001": "45 CFR 164.312(e) - Transmission Security",
            "SG-002": "45 CFR 164.312(e) - Transmission Security",
            "IAM-001": "45 CFR 164.312(a)(1) - Access Control",
            "IAM-002": "45 CFR 164.312(d) - Person or Entity Authentication",
            "IAM-004": "45 CFR 164.312(a)(1) - Access Control",
        },
    },
    "finance": {
        "label": "Financial Services (PCI-DSS scope)",
        "framework": "PCI-DSS v4.0",
        "severity_overrides": {
            "SG-001": "Critical",
            "SG-002": "Critical",
            "SG-003": "Critical",
            "VPC-002": "High",
            "VPC-003": "High",
            "LOG-001": "Critical",
            "IAM-002": "Critical",
            "IAM-003": "High",
            "RDS-001": "Critical",
            "S3-001": "Critical",
            "S3-005": "Critical",
        },
        "framework_mapping": {
            "SG-001": "PCI-DSS Req. 1.3 - Network Segmentation",
            "SG-002": "PCI-DSS Req. 1.3 - Network Segmentation",
            "SG-003": "PCI-DSS Req. 1.2 - Restrict Inbound/Outbound Traffic",
            "VPC-002": "PCI-DSS Req. 1.3 - Network Segmentation",
            "VPC-003": "PCI-DSS Req. 1.3 - Network Segmentation",
            "LOG-001": "PCI-DSS Req. 10 - Logging and Monitoring",
            "IAM-001": "PCI-DSS Req. 7 - Restrict Access by Need-to-Know",
            "IAM-002": "PCI-DSS Req. 8.4 - Multi-Factor Authentication",
            "IAM-003": "PCI-DSS Req. 8.3 - Credential Lifecycle Management",
            "IAM-004": "PCI-DSS Req. 7 - Restrict Access by Need-to-Know",
            "RDS-001": "PCI-DSS Req. 1.3 - Network Segmentation",
            "RDS-002": "PCI-DSS Req. 3.5 - Render Stored Cardholder Data Unreadable",
            "S3-001": "PCI-DSS Req. 1.3 - Network Segmentation",
            "S3-002": "PCI-DSS Req. 3.5 - Render Stored Cardholder Data Unreadable",
            "S3-005": "PCI-DSS Req. 1.3 - Network Segmentation",
        },
    },
    "government": {
        "label": "Government / Public Sector (FedRAMP)",
        "framework": "NIST 800-53 / FedRAMP",
        "severity_overrides": {
            "EBS-001": "Critical",
            "RDS-002": "Critical",
            "S3-002": "Critical",
            "KMS-001": "High",
            "KMS-002": "Critical",
            "LOG-001": "Critical",
            "VPC-001": "Critical",
            "IAM-001": "Critical",
            "IAM-002": "Critical",
            "IAM-004": "Critical",
        },
        "framework_mapping": {
            "EBS-001": "NIST 800-53 SC-28 - Protection of Information at Rest",
            "RDS-002": "NIST 800-53 SC-28 - Protection of Information at Rest",
            "S3-002": "NIST 800-53 SC-28 - Protection of Information at Rest",
            "KMS-001": "NIST 800-53 SC-12 - Cryptographic Key Establishment & Management",
            "KMS-002": "NIST 800-53 AC-3 - Access Enforcement",
            "LOG-001": "NIST 800-53 AU-2 - Audit Events",
            "VPC-001": "NIST 800-53 AU-2 - Audit Events",
            "IAM-001": "NIST 800-53 AC-6 - Least Privilege",
            "IAM-002": "NIST 800-53 IA-2 - Multi-Factor Authentication",
            "IAM-004": "NIST 800-53 AC-6 - Least Privilege",
            "SG-001": "NIST 800-53 SC-7 - Boundary Protection",
            "SG-002": "NIST 800-53 SC-7 - Boundary Protection",
            "SG-003": "NIST 800-53 SC-7 - Boundary Protection",
        },
    },
}


def get_profile(name):
    return PROFILES.get(name, PROFILES[GENERAL_PROFILE])
