# Week 3: S3 and VPC Security Checklist

## S3 checks that i researched and need to add later:
- Check if S3 Block Public Access is enabled.
- Check if the bucket policy allows public access.
- Check if Object Ownership is set to BucketOwnerEnforced.
- Check if bucket versioning is enabled.
- Check if server access logging is enabled.
- Check if default encryption is configured.

## VPC checks that i researched about and need to add later:
- Check if route tables expose private resources to the internet.
- Check if an Internet Gateway is attached to the VPC.
- Check if subnets are public or private.
- Check if security group rules allow overly open inbound access.
- Check if network ACLs have overly permissive rules.

## Purpose
This checklist will help decide which S3 and VPC misconfigurations can be included in the backend scanner and later shown on the dashboard.
