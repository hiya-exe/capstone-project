# Business Profile Severity Overrides

This document lists every case where a sector business profile raises a finding's severity
above its technical baseline, the compliance framework driving the change, and the reasoning.

Baselines come from the `RULES` table in `scanner.py`. Overrides and framework mappings come from
`scanner/profiles.py`. See [Severity Decision Logic](./Severity-Decision-Logic/README.md) for the full model and the
complete per-rule severity table.

## How to read this

The tool assigns severity in two layers. First, a technical baseline (industry-neutral, CIS-based).
Second, a business profile may raise that baseline based on the compliance framework the industry
is regulated under. This document covers only the second layer — the escalations.

## Escalations by profile

| Rule ID | Finding | Severity change | Profile | Framework / clause | Why |
|---|---|---|---|---|---|
| RDS-002 | RDS Storage Encryption Disabled | High → Critical | Healthcare | HIPAA 45 CFR 164.312(a)(2)(iv) — Encryption at Rest | Unencrypted PHI storage is a direct compliance violation, not just a hardening gap. |
| EBS-001 | Unencrypted EBS Volume | High → Critical | Healthcare | HIPAA 45 CFR 164.312(a)(2)(iv) — Encryption at Rest | Same encryption-at-rest mandate. A disk that could hold patient data must be encrypted. |
| EBS-003 | EBS Snapshot Shared Externally | High → Critical | Healthcare | HIPAA 45 CFR 164.312(a)(1) — Access Control | A snapshot shared outside the account is uncontrolled PHI access, not routine hygiene. |
| S3-001 | S3 Block Public Access Not Fully Enabled | High → Critical | Healthcare | HIPAA 45 CFR 164.312(a)(1) — Access Control | Any gap in public-access blocking is a direct path to PHI exposure. |
| S3-002 | S3 Default Encryption Not Configured | High → Critical | Healthcare | HIPAA 45 CFR 164.312(a)(2)(iv) — Encryption at Rest | New objects can land unencrypted, risking PHI the moment it is written. |
| KMS-002 | KMS Key Policy Is Overly Permissive | High → Critical | Healthcare | HIPAA 45 CFR 164.312(a)(2)(iv) — Encryption at Rest | A loose key policy undermines the encryption HIPAA requires everywhere else. |
| VPC-002 | Route Table Default Route to IGW | Medium → High | Finance | PCI-DSS Req. 1.3 — Network Segmentation | PCI scope depends on isolating cardholder-data networks. A stray public route threatens that isolation. |
| VPC-003 | Subnet Auto-Assigns Public IPs | Medium → High | Finance | PCI-DSS Req. 1.3 — Network Segmentation | Same segmentation boundary. Silent public exposure undermines it just as directly. |
| LOG-001 | No CloudTrail Trail Configured | High → Critical | Finance | PCI-DSS Req. 10 — Logging and Monitoring | PCI Req. 10 is one of the most heavily audited controls. No trail means no evidence for a mandated control. |
| IAM-002 | Console User Without MFA | High → Critical | Finance | PCI-DSS Req. 8.4 — Multi-Factor Authentication | PCI names MFA explicitly for cardholder-data-environment access. Missing it is a direct violation. |
| IAM-003 | Stale Access Keys | Medium → High | Finance | PCI-DSS Req. 8.3 — Credential Lifecycle Management | Unrotated keys are a named audit finding under PCI's credential-lifecycle requirement. |
| S3-001 | S3 Block Public Access Not Fully Enabled | High → Critical | Finance | PCI-DSS Req. 1.3 — Network Segmentation | Cardholder data must never be reachable through an unsegmented or public path. |
| EBS-001 | Unencrypted EBS Volume | High → Critical | Government | NIST 800-53 SC-28 — Protection of Info at Rest | FedRAMP baselines treat unencrypted storage as a hard control failure, not a recommendation. |
| RDS-002 | RDS Storage Encryption Disabled | High → Critical | Government | NIST 800-53 SC-28 — Protection of Info at Rest | Same SC-28 control applied to database storage. |
| S3-002 | S3 Default Encryption Not Configured | High → Critical | Government | NIST 800-53 SC-28 — Protection of Info at Rest | Same SC-28 control applied to object storage. |
| KMS-001 | KMS Key Rotation Disabled | Medium → High | Government | NIST 800-53 SC-12 — Key Establishment and Mgmt | FedRAMP expects active key lifecycle management, not set-once-and-forget. |
| KMS-002 | KMS Key Policy Is Overly Permissive | High → Critical | Government | NIST 800-53 AC-3 — Access Enforcement | A permissive key policy is read as an access-control failure, government's top concern. |
| LOG-001 | No CloudTrail Trail Configured | High → Critical | Government | NIST 800-53 AU-2 — Audit Events | Continuous audit trails are mandated for FedRAMP authorization. |
| VPC-001 | VPC Flow Logs Disabled | Medium → Critical | Government | NIST 800-53 AU-2 — Audit Events | Same audit-events control. The two-level jump reflects how central network visibility is to FedRAMP. |
| IAM-002 | Console User Without MFA | High → Critical | Government | NIST 800-53 IA-2 — Multi-Factor Auth | Federal systems require MFA as a baseline control. Any gap is treated as critical. |

## A note on the other listed overrides

Across the three profiles there are 33 `severity_overrides` entries. 20 of them actually raise a
finding's severity — those are the rows above. The other 13 set a severity equal to the baseline,
so they change nothing numerically. For example, Healthcare lists SG-001 as Critical, but SG-001
is already Critical at baseline.

Those 13 are redundant no-ops, kept only for explicitness. They are **not** what attaches the
compliance clause. The clause comes from each profile's separate `framework_mapping` dictionary,
which `add_finding` in `scanner.py` looks up independently of `severity_overrides`. Several rules
get a clause with no `severity_overrides` entry at all — for example, Healthcare maps IAM-001,
IAM-002, and IAM-004 to HIPAA clauses purely through `framework_mapping`.

## A note on RDS and the environment floor

For RDS findings, severity is adjusted once more after the profile override, based on the
environment tier (production, staging, development). Staging and development lower the severity,
reflecting that the same misconfiguration is less urgent on a throwaway instance. However, when a
profile marks a rule as sector-critical, that override acts as a floor: the environment discount
can never lower the severity below the level the regulation demands.

**Source:** `scanner/profiles.py` (`severity_overrides`, `framework_mapping`) and `scanner.py`
(`RULES` baseline severities, `add_finding`, `compute_severity`).
