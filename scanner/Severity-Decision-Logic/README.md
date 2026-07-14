# Severity Decision Logic

Part of the AWS Security Posture Assessment Tool. This explains how the scanner assigns a
severity to every finding, how business profiles change that severity, and the override
algorithm behind it.

## The two-layer model

Severity is produced in two distinct layers. The first is industry-neutral and answers a
purely technical question. The second is industry-specific and answers a legal question.
Keeping them separate is what lets the same finding carry different severities for different
organizations without any change to the underlying scan.

### Layer one, the default severity

Every check ships with a default severity set in the RULES table in scanner.py, based only on
the technical blast radius of the problem, independent of any industry.

- A publicly accessible database (RDS-001) is Critical because the database is the highest-value
  target and public exposure needs no prior compromise.
- A root account problem (IAM-004) is Critical because root can do anything to the account.
- Weak backup retention (RDS-003) is Medium because it is a resilience gap, not an active exposure.

These defaults follow the CIS AWS Foundations Benchmark, which is deliberately industry-neutral.

### Layer two, the business profile override

This layer answers how dangerous the finding is for the kind of data the organization is legally
responsible for. It is why the same finding can be High in one profile and Critical in another.

## The decision algorithm

When the scanner records a finding, it runs the following steps in order.

| Step | Action | What happens |
|---|---|---|
| Step 1 | Assign the default severity | The RULES table in scanner.py sets the finding's severity based on technical risk alone (the CIS baseline). |
| Step 2 | Load the active profile | The profile chosen by the user (General, Healthcare, Finance, or Government) is loaded from profiles.py. |
| Step 3 | Look up the finding ID in that profile | The tool checks whether the profile's severity_overrides dictionary contains an entry for this finding ID. |
| Step 4 | Apply the override, or keep the default | If an entry exists, the override severity replaces the default. If no entry exists, the default is kept unchanged. |
| Step 5 | Apply the environment shift (RDS only) | For RDS findings, staging or development environments lower the severity one or two levels. Production and unknown are left as is. |
| Step 6 | Attach the compliance mapping | The framework name and the specific control reference for that finding are attached from the profile so the dashboard can show the regulation. |

### Inputs the algorithm uses

- The finding ID (for example RDS-001, SG-001, LOG-001). This is the key used for every lookup.
- The default severity defined in the RULES table for that finding.
- The active business profile selected by the user before the scan.
- The profile's severity_overrides dictionary.
- The profile's framework_mapping dictionary.
- The environment tier (RDS only), inferred from AWS resource tags first, then from keywords in
  the instance name (prod, stag, dev, test), falling back to unknown.
- The database engine (RDS only), used to attach a remediation-cost note, not to change severity.

### An important detail about the override table

Not every entry in a profile's severity_overrides table actually raises the number. Some rules
(for example SG-001, which is already Critical at baseline) are listed with the same severity they
already have. They are kept in the table only so the profile's framework_mapping can attach a
specific compliance clause to that finding. So "listed in a profile" and "escalated by a profile"
are not the same thing — see severity-overrides.md, which lists only the true escalations.

## How each profile decides

### General, CIS Benchmark

No regulated data is assumed, so no overrides are applied. Every finding keeps its default
technical severity.

### Healthcare, HIPAA

HIPAA protects protected health information (PHI) and centers on two obligations: PHI must be
encrypted at rest and in transit, and access to PHI must be controlled and audited. The profile
escalates the findings that sit on the stores where PHI actually lives.

- RDS-002, S3-001, and S3-002 jump High to Critical — the database and buckets are where PHI is
  stored, so unencrypted or publicly reachable storage is a direct compliance risk.
- EBS-001 and EBS-003 (unencrypted volume, externally shared snapshot) escalate High to Critical
  under the same encryption and access-control mandate.
- KMS-002 (overly permissive key policy) escalates High to Critical because a loose key policy
  undermines the encryption HIPAA requires everywhere else.
- RDS-001 (public database) and SG-001/SG-002 (SSH/RDP open) are already Critical at baseline. The
  healthcare profile still lists them, but only to attach the HIPAA clause, not to raise severity.

### Finance, PCI-DSS

PCI-DSS protects cardholder data and is prescriptive: lock down the network (Req 1), authenticate
everyone who touches card data (Req 8), and log everything (Req 10). The profile escalates the
findings that are literal PCI violations.

- LOG-001 jumps High to Critical because Req 10 mandates an audit trail; no trail is itself a failure.
- IAM-002 jumps High to Critical and IAM-003 Medium to High, covering Req 8 MFA and key rotation.
- S3-001 jumps High to Critical (Req 1.3, no public path to cardholder data).
- VPC-002 and VPC-003 jump Medium to High, both under Req 1.3 network segmentation.
- SG-001, SG-002, SG-003, and RDS-001 are already Critical at baseline. Finance lists them to cite
  Req 1.2/1.3, not to change severity.

### Government, NIST 800-53 and FedRAMP

NIST 800-53 treats security as a checklist of controls that must exist. The question is whether a
required control is missing, so escalations cluster around encryption, audit, and access control.

- EBS-001, RDS-002, and S3-002 all jump High to Critical under SC-28 (protection of information at rest).
- KMS-002 jumps High to Critical (AC-3, access enforcement); KMS-001 jumps Medium to High (SC-12).
- LOG-001 jumps High to Critical and VPC-001 jumps Medium to Critical, both under AU-2 (audit events).
  VPC-001 is the only two-level jump in the whole system, reflecting how central network visibility
  is to FedRAMP.
- IAM-002 jumps High to Critical (IA-2, multi-factor authentication).
- IAM-001 and IAM-004 are already Critical at baseline; government lists them to cite AC-6 least privilege.

## Severity rule table

Every rule, its baseline severity, and the severity each profile resolves it to. `▲` marks a
one-level escalation above baseline; `▲▲` marks a two-level escalation.

| ID | What it checks | Baseline | General | Healthcare | Finance | Government |
|---|---|---|---|---|---|---|
| EC2-001 | Public IP + open admin port | Critical | Critical | Critical | Critical | Critical |
| EC2-002 | Unnecessary public IP | High | High | High | High | High |
| EC2-003 | Unencrypted EBS volume attached to EC2 | High | High | High | High | High |
| EC2-004 | Security group open to internet on sensitive ports | High | High | High | High | High |
| IAM-001 | IAM policy with wildcard permissions | Critical | Critical | Critical | Critical | Critical |
| IAM-002 | Console user without MFA | High | High | High | Critical ▲ | Critical ▲ |
| IAM-003 | Stale access keys | Medium | Medium | Medium | High ▲ | Medium |
| IAM-004 | Root account usage or weak protection | Critical | Critical | Critical | Critical | Critical |
| RDS-001 | Publicly accessible RDS database | Critical | Critical | Critical | Critical | Critical |
| RDS-002 | RDS storage encryption disabled | High | High | Critical ▲ | High | Critical ▲ |
| RDS-003 | Weak RDS backup retention | Medium | Medium | Medium | Medium | Medium |
| RDS-004 | Auto minor version upgrade disabled | Medium | Medium | Medium | Medium | Medium |
| EBS-001 | Unencrypted EBS volume | High | High | Critical ▲ | High | Critical ▲ |
| EBS-002 | EBS encryption by default disabled | Medium | Medium | Medium | Medium | Medium |
| EBS-003 | EBS snapshot shared externally | High | High | Critical ▲ | High | High |
| EBS-004 | Public EBS snapshot | Critical | Critical | Critical | Critical | Critical |
| S3-001 | S3 block public access not fully enabled | High | High | Critical ▲ | Critical ▲ | High |
| S3-002 | S3 default encryption not configured | High | High | Critical ▲ | High | Critical ▲ |
| S3-003 | S3 bucket versioning disabled | Medium | Medium | Medium | Medium | Medium |
| S3-004 | S3 access logging disabled | Low | Low | Low | Low | Low |
| S3-005 | S3 bucket policy allows public principal | Critical | Critical | Critical | Critical | Critical |
| SG-001 | Security group: SSH open to internet | Critical | Critical | Critical | Critical | Critical |
| SG-002 | Security group: RDP open to internet | Critical | Critical | Critical | Critical | Critical |
| SG-003 | Security group: all inbound open to internet | Critical | Critical | Critical | Critical | Critical |
| SG-004 | Security group: unrestricted outbound traffic | Medium | Medium | Medium | Medium | Medium |
| SG-005 | Unused security group | Low | Low | Low | Low | Low |
| VPC-001 | VPC flow logs disabled | Medium | Medium | Medium | Medium | Critical ▲▲ |
| VPC-002 | Route table default route to internet gateway | Medium | Medium | Medium | High ▲ | Medium |
| VPC-003 | Subnet auto-assigns public IPs | Medium | Medium | Medium | High ▲ | Medium |
| KMS-001 | KMS key rotation disabled | Medium | Medium | Medium | Medium | High ▲ |
| KMS-002 | KMS key policy is overly permissive | High | High | Critical ▲ | High | Critical ▲ |
| KMS-003 | KMS key pending deletion | High | High | High | High | High |
| KMS-004 | KMS key is disabled | Medium | Medium | Medium | Medium | Medium |
| KMS-005 | KMS key has no alias | Low | Low | Low | Low | Low |
| LOG-001 | No CloudTrail trail configured | High | High | High | Critical ▲ | Critical ▲ |

For the framework clause behind each escalation and the reasoning, see **Business Profile Severity Overrides**.

## The RDS environment shift

For RDS findings only, a second adjustment runs after the profile override.

| Detected environment | Severity shift |
|---|---|
| production | No change, stays at its level |
| staging | Drops one level, High becomes Medium |
| development | Drops two levels, High becomes Low |
| unknown | No change, treated as production to be safe |

## Why three frameworks give three answers

HIPAA is principle-based and centers on data exposure, so the tool escalates the storage findings
that could reveal PHI. PCI is requirement-based and centers on access and logging, so the tool
escalates literal rule violations. NIST is control-based and centers on completeness, so the tool
escalates any missing mandatory control — including the only two-level jump in the system, VPC-001.
