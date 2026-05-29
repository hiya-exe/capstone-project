# Week 3 – KMS & Security Groups Service Checklist

This shows the initial checks we plan to implement for KMS and Security Groups.

---

## KMS

- KMS-001 – Key rotation disabled
- KMS-002 – Overly permissive key policy (wildcard principals/actions)
- KMS-003 – Key scheduled for deletion
- KMS-004 – Disabled keys
- KMS-005 – Keys missing an alias

---

## Security Groups

- SG-001 – SSH (port 22) open to internet (0.0.0.0/0)
- SG-002 – RDP (port 3389) open to internet (0.0.0.0/0)
- SG-003 – All inbound traffic allowed from internet
- SG-004 – Unrestricted outbound traffic to internet
- SG-005 – Unused security groups
