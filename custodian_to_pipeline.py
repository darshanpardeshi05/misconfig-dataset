#!/usr/bin/env python3
"""
Convert Custodian findings directly to pipeline.py input
Bypasses Prowler/ScoutSuite normalization issues
"""

import json
import subprocess
import sys
from pathlib import Path

# Map policy folder name to (misconfig_id, category, severity, keyword)
POLICY_MAP = {
    "01-s3-public-read-acl": (1, "Storage Exposure", "CRITICAL", "PublicRead"),
    "02-s3-public-read-write-acl": (2, "Storage Exposure", "CRITICAL", "PublicReadWrite"),
    "03-s3-block-public-access-disabled": (3, "Storage Exposure", "HIGH", "BlockPublicAccess disabled"),
    "04-ebs-snapshot-public": (4, "Storage Exposure", "CRITICAL", "EBS snapshot public"),
    "05-rds-snapshot-public": (5, "Storage Exposure", "CRITICAL", "RDS snapshot public"),
    "06-ecr-repository-public": (6, "Storage Exposure", "HIGH", "ECR public"),
    "07-ami-public": (7, "Storage Exposure", "CRITICAL", "AMI public"),
    "08-efs-public-mount": (8, "Storage Exposure", "HIGH", "EFS public mount"),
    "09-s3-bucket-policy-public": (9, "Storage Exposure", "CRITICAL", "Principal star"),
    "10-s3-object-public-acl": (10, "Storage Exposure", "HIGH", "S3 object public"),
    "11-iam-wildcard-action": (11, "IAM Over-Permission", "HIGH", "Action wildcard"),
    "12-iam-wildcard-resource": (12, "IAM Over-Permission", "HIGH", "Resource wildcard"),
    "13-iam-wildcard-both": (13, "IAM Over-Permission", "CRITICAL", "Action and Resource wildcard"),
    "14-iam-admin-role": (14, "IAM Over-Permission", "CRITICAL", "AdministratorAccess"),
    "15-iam-s3-full-access": (15, "IAM Over-Permission", "HIGH", "s3 full access"),
    "16-iam-ec2-full-access": (16, "IAM Over-Permission", "HIGH", "ec2 full access"),
    "17-iam-missing-mfa-root": (17, "IAM Over-Permission", "CRITICAL", "Root MFA missing"),
    "18-iam-missing-mfa-user": (18, "IAM Over-Permission", "HIGH", "User MFA missing"),
    "19-iam-inactive-user": (19, "IAM Over-Permission", "MEDIUM", "Inactive user"),
    "20-iam-old-access-key": (20, "IAM Over-Permission", "MEDIUM", "Old access key"),
    "21-iam-trust-policy-principal-star": (21, "IAM Over-Permission", "CRITICAL", "Principal star trust"),
    "22-lambda-execution-role-overly-permissive": (22, "IAM Over-Permission", "CRITICAL", "Lambda over permissive"),
    "23-sg-ssh-open-world": (23, "Network Oversights", "HIGH", "SSH open"),
    "24-sg-rdp-open-world": (24, "Network Oversights", "HIGH", "RDP open"),
    "25-sg-mysql-open-world": (25, "Network Oversights", "CRITICAL", "MySQL open"),
    "26-sg-postgres-open-world": (26, "Network Oversights", "CRITICAL", "PostgreSQL open"),
    "27-sg-redis-open-world": (27, "Network Oversights", "CRITICAL", "Redis open"),
    "28-sg-mongodb-open-world": (28, "Network Oversights", "CRITICAL", "MongoDB open"),
    "29-sg-all-ports-open": (29, "Network Oversights", "CRITICAL", "All ports open"),
    "30-vpc-flow-logs-disabled": (30, "Network Oversights", "MEDIUM", "Flow logs disabled"),
    "31-rds-publicly-accessible": (31, "Network Oversights", "CRITICAL", "RDS public"),
    "32-default-vpc-in-use": (32, "Network Oversights", "MEDIUM", "Default VPC"),
    "33-s3-encryption-disabled": (33, "Lack of Encryption", "MEDIUM", "Encryption disabled"),
    "34-s3-sse-not-enforced": (34, "Lack of Encryption", "MEDIUM", "SSE not enforced"),
    "35-ebs-encryption-disabled": (35, "Lack of Encryption", "HIGH", "EBS encryption"),
    "36-rds-encryption-disabled": (36, "Lack of Encryption", "HIGH", "RDS encryption"),
    "37-dynamodb-encryption-disabled": (37, "Lack of Encryption", "MEDIUM", "DynamoDB encryption"),
    "38-lambda-env-not-encrypted": (38, "Lack of Encryption", "HIGH", "Lambda env not encrypted"),
    "39-sqs-encryption-disabled": (39, "Lack of Encryption", "MEDIUM", "SQS encryption"),
    "40-sns-encryption-disabled": (40, "Lack of Encryption", "MEDIUM", "SNS encryption"),
    "41-efs-encryption-disabled": (41, "Lack of Encryption", "HIGH", "EFS encryption"),
    "42-redshift-encryption-disabled": (42, "Lack of Encryption", "HIGH", "Redshift encryption"),
    "43-ec2-auto-assign-public-ip": (43, "Insecure Defaults", "MEDIUM", "Auto-assign public IP"),
    "44-default-security-group-in-use": (44, "Insecure Defaults", "HIGH", "Default security group"),
    "45-ec2-default-credential-report-not-enabled": (45, "Insecure Defaults", "LOW", "Credential report not enabled"),
    "46-cloudtrail-disabled": (46, "Insecure Defaults", "HIGH", "CloudTrail disabled"),
    "47-config-recorder-disabled": (47, "Insecure Defaults", "HIGH", "Config recorder disabled"),
    "48-guardduty-disabled": (48, "Insecure Defaults", "HIGH", "GuardDuty disabled"),
    "49-s3-logging-disabled": (49, "Insecure Defaults", "MEDIUM", "S3 logging disabled"),
    "50-iam-user-without-password-policy": (50, "Insecure Defaults", "MEDIUM", "Password policy missing"),
}

def find_custodian_findings():
    """Find all Custodian results with non-empty resources.json"""
    custodian_dir = Path("/home/darshan/misconfig-dataset/custodian-results")
    findings = []
    
    for resources_file in custodian_dir.glob("*/*/resources.json"):
        try:
            with open(resources_file, 'r') as f:
                data = json.load(f)
            if data and len(data) > 0:
                folder_name = resources_file.parent.parent.name
                findings.append(folder_name)
        except:
            pass
    
    return findings

def main():
    print("=" * 60)
    print("CUSTODIAN TO PIPELINE - Phase 2 Simplified")
    print("=" * 60)
    
    findings = find_custodian_findings()
    
    if not findings:
        print("\nNo Custodian findings found. Run Custodian scans first.")
        print("Command: for policy in custodian-policies/*.yaml; do")
        print("           custodian run --output-dir custodian-results/$(basename $policy .yaml) $policy")
        print("         done")
        return
    
    print(f"\nFound {len(findings)} Custodian findings:")
    for f in findings:
        print(f"  - {f}")
    
    print("\n" + "=" * 60)
    print("RUNNING PHASE 3 PIPELINE FOR EACH FINDING")
    print("=" * 60)
    
    for folder in findings:
        if folder in POLICY_MAP:
            misconfig_id, category, severity, keyword = POLICY_MAP[folder]
            print(f"\n{'='*50}")
            print(f"Processing: {folder}")
            print(f"  Misconfig ID: {misconfig_id}")
            print(f"  Category: {category}")
            print(f"  Severity: {severity}")
            print(f"  Keyword: {keyword}")
            print(f"{'='*50}")
            
            result = subprocess.run(
                ['python3', 'pipeline.py', '--id', str(misconfig_id), category, severity, keyword],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("  Phase 3 (Detection) completed successfully")
                lines = result.stdout.split('\n')
                for line in lines[-5:]:
                    if line.strip():
                        print(f"    {line[:100]}")
            else:
                print(f"  Phase 3 failed: {result.stderr[:200]}")
        else:
            print(f"  No mapping found for {folder}")

if __name__ == "__main__":
    main()
