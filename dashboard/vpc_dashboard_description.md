#VPC findings
. Route Table Allows 0.0.0.0/0

Issue:
A route table contains a route to 0.0.0.0/0, which means traffic can be routed to the public internet through an internet gateway or similar target.

Why it matters:
If this route is attached to the wrong subnet, resources that should be private may become internet-accessible. The organization could expose servers, databases, or internal applications to attackers. This could lead to data theft, service disruption, unauthorized access, or attackers using the exposed system as an entry point into the cloud environment.

Evidence to display:
Route table ID, destination CIDR, gateway target, and associated subnet.

Remediation:
Review route table associations, keep private resources in private subnets, and only use public routes for resources that must be internet-facing.

CIS Controls Mapping:

CIS Control 4: Secure Configuration of Enterprise Assets and Software — This checks whether cloud network settings are configured securely.
CIS Control 12: Network Infrastructure Management — Route tables are part of cloud network infrastructure and should be managed securely.
CIS Control 13: Network Monitoring and Defense — Internet-facing routes should be monitored because they increase exposure.
2. Internet Gateway Attached to VPC

Issue:
The VPC has an internet gateway attached.

Why it matters:
An internet gateway is not always unsafe, but if it is combined with public route tables or weak security group rules, cloud resources may become reachable from the internet. Attackers could scan, target, or attempt unauthorized access to exposed resources. The organization may lose control over systems that were meant to remain internal.

Evidence to display:
VPC ID, internet gateway ID, attachment status, and related route tables.

Remediation:
Confirm whether the VPC actually needs internet access. Remove unused internet gateways and restrict public access through route tables and security groups.

CIS Controls Mapping:

CIS Control 4: Secure Configuration of Enterprise Assets and Software — Ensures cloud assets are not left in risky default or unnecessary configurations.
CIS Control 12: Network Infrastructure Management — Internet gateways are part of cloud network infrastructure and should be reviewed.
CIS Control 13: Network Monitoring and Defense — Internet-connected infrastructure should be monitored for exposure and suspicious traffic.
3. Public Subnet Detected

Issue:
A subnet appears to be public because it is associated with a route table that allows internet access.

Why it matters:
If sensitive resources are placed in a public subnet, they may be exposed to the internet. This can increase the chance of unauthorized access, data theft, malware installation, or service disruption. The organization could lose confidential data, system availability, and customer trust.

Evidence to display:
Subnet ID, route table association, internet gateway route, and resource placement if available.

Remediation:
Place sensitive resources such as databases and internal servers in private subnets. Use public subnets only for resources that need to face the internet, such as load balancers.

CIS Controls Mapping:

CIS Control 4: Secure Configuration of Enterprise Assets and Software — Public/private subnet design is part of secure cloud configuration.
CIS Control 12: Network Infrastructure Management — Subnet routing and segmentation are part of network infrastructure management.
CIS Control 13: Network Monitoring and Defense — Public-facing subnets should be monitored because they have higher exposure.
4. Default VPC in Use

Issue:
The account is using a default VPC instead of a custom-designed VPC.

Why it matters:
Default VPCs are convenient, but they may not follow the organization’s security design. If resources are deployed without proper subnet planning, they may accidentally become public or difficult to monitor. This can lead to weak network separation, poor access control, and higher risk of exposing cloud resources.

Evidence to display:
VPC ID, default VPC status, subnet list, and route table configuration.

Remediation:
Use a custom VPC with planned public and private subnets, controlled routing, and security group rules based on least privilege.

CIS Controls Mapping:

CIS Control 1: Inventory and Control of Enterprise Assets — The organization should know which cloud assets and VPCs exist.
CIS Control 4: Secure Configuration of Enterprise Assets and Software — Default configurations should be reviewed and hardened.
CIS Control 12: Network Infrastructure Management — VPCs, subnets, route tables, and gateways are part of cloud network infrastructure.
