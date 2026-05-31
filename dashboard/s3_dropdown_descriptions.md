# S3 Dashboard Dropdown Descriptions

S3 Findings
1. S3 Bucket Public Access Enabled

Issue:
The S3 bucket may allow public access through bucket policy, ACLs, or disabled Block Public Access settings.

Why it matters:
If this is not fixed, someone outside the organization could view, download, or copy files stored in the bucket. The organization could lose confidential documents, customer data, reports, backups, or internal project files. This could lead to privacy violations, reputational damage, loss of client trust, and possible legal or compliance issues.

Evidence to display:
Bucket name, public access block status, ACL result, bucket policy result, and whether public access is allowed.

Remediation:
Enable S3 Block Public Access, remove public bucket policies, avoid public ACLs, and only allow access to trusted users or roles.

CIS Controls Mapping:

CIS Control 3: Data Protection — This finding relates to protecting sensitive data from unauthorized exposure.
CIS Control 6: Access Control Management — This finding relates to ensuring only authorized users, roles, or services can access the bucket.
CIS Control 12: Network Infrastructure Management — This applies when public exposure is caused by poor cloud/network configuration.
2. S3 Default Encryption Disabled

Issue:
The S3 bucket does not have default server-side encryption enabled.

Why it matters:
If the bucket stores sensitive files and encryption is not enabled, the organization could lose control over private information if access is compromised. Exposed files may include customer records, financial files, logs, reports, project files, or business data. This can create privacy, compliance, and trust issues.

Evidence to display:
Bucket name and encryption configuration status.

Remediation:
Enable default server-side encryption using SSE-S3 or SSE-KMS.

CIS Controls Mapping:

CIS Control 3: Data Protection — Encryption supports protection of sensitive data at rest.
CIS Control 4: Secure Configuration of Enterprise Assets and Software — This finding checks whether the cloud resource is configured securely.
CIS Control 6: Access Control Management — If KMS is used, access to encryption keys should also be restricted to authorized users and roles.
3. S3 Bucket Logging Disabled

Issue:
Server access logging or CloudTrail data event logging is not enabled for the S3 bucket.

Why it matters:
If logging is disabled, the organization may not know who accessed the bucket, when it was accessed, or what actions were performed. If files are deleted, copied, or exposed, there may be no clear evidence to investigate the incident. This can delay response, make recovery harder, and reduce accountability.

Evidence to display:
Bucket name, logging configuration status, target logging bucket if available, and CloudTrail data event status if checked.

Remediation:
Enable S3 server access logging or CloudTrail data events for important buckets.

CIS Controls Mapping:

CIS Control 8: Audit Log Management — This directly relates to collecting, reviewing, and retaining logs that help detect, understand, or recover from attacks.
CIS Control 13: Network Monitoring and Defense — Logs support monitoring and investigation of suspicious activity.
CIS Control 17: Incident Response Management — Logging helps provide evidence during incident investigation and response.
4. S3 Versioning Disabled

Issue:
S3 bucket versioning is not enabled.

Why it matters:
If files are accidentally deleted, overwritten, or changed by an attacker, the organization may not be able to recover the original version. This could result in loss of important business documents, backups, application files, or evidence needed for an investigation.

Evidence to display:
Bucket name and versioning status.

Remediation:
Enable S3 versioning on important buckets, especially buckets storing critical or sensitive files.

CIS Controls Mapping:

CIS Control 3: Data Protection — Versioning supports recovery and protection of important data.
CIS Control 11: Data Recovery — Versioning helps restore files after accidental deletion, ransomware, or unauthorized changes.
CIS Control 17: Incident Response Management — Preserved versions can support investigation and recovery after an incident.
