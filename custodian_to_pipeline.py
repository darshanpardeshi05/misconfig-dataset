#!/usr/bin/env python3
"""
Convert Custodian findings directly to pipeline.py input
Bypasses Prowler/ScoutSuite normalization issues
"""

import json
import subprocess
import sys
from pathlib import Path

# Map policy folder name to (category, severity, keyword)
POLICY_MAP = {
    "01-s3-public-read-acl": ("Storage Exposure", "CRITICAL", "PublicRead"),
    "02-s3-public-read-write-acl": ("Storage Exposure", "CRITICAL", "PublicReadWrite"),
    "03-s3-block-public-access-disabled": ("Storage Exposure", "HIGH", "BlockPublicAccess disabled"),
    "04-ebs-snapshot-public": ("Storage Exposure", "CRITICAL", "EBS snapshot public"),
    "05-rds-snapshot-public": ("Storage Exposure", "CRITICAL", "RDS snapshot public"),
    "06-ecr-repository-public": ("Storage Exposure", "HIGH", "ECR public"),
    "07-ami-public": ("Storage Exposure", "CRITICAL", "AMI public"),
    "08-efs-public-mount": ("Storage Exposure", "HIGH", "EFS public mount"),
    "09-s3-bucket-policy-public": ("Storage Exposure", "CRITICAL", "Principal star"),
    "10-s3-object-public-acl": ("Storage Exposure", "HIGH", "S3 object public"),
    "11-iam-wildcard-action": ("IAM Over-Permission", "HIGH", "Action wildcard"),
    "12-iam-wildcard-resource": ("IAM Over-Permission", "HIGH", "Resource wildcard"),
    "13-iam-wildcard-both": ("IAM Over-Permission", "CRITICAL", "Action and Resource wildcard"),
    "14-iam-admin-role": ("IAM Over-Permission", "CRITICAL", "AdministratorAccess"),
    "15-iam-s3-full-access": ("IAM Over-Permission", "HIGH", "s3 full access"),
    "16-iam-ec2-full-access": ("IAM Over-Permission", "HIGH", "ec2 full access"),
    "17-iam-missing-mfa-root": ("IAM Over-Permission", "CRITICAL", "Root MFA missing"),
    "18-iam-missing-mfa-user": ("IAM Over-Permission", "HIGH", "User MFA missing"),
    "19-iam-inactive-user": ("IAM Over-Permission", "MEDIUM", "Inactive user"),
    "20-iam-old-access-key": ("IAM Over-Permission", "MEDIUM", "Old access key"),
    "21-iam-trust-policy-principal-star": ("IAM Over-Permission", "CRITICAL", "Principal star trust"),
    "22-lambda-execution-role-overly-permissive": ("IAM Over-Permission", "CRITICAL", "Lambda over permissive"),
    "23-sg-ssh-open-world": ("Network Oversights", "HIGH", "SSH open"),
    "24-sg-rdp-open-world": ("Network Oversights", "HIGH", "RDP open"),
    "25-sg-mysql-open-world": ("Network Oversights", "CRITICAL", "MySQL open"),
    "26-sg-postgres-open-world": ("Network Oversights", "CRITICAL", "PostgreSQL open"),
    "27-sg-redis-open-world": ("Network Oversights", "CRITICAL", "Redis open"),
    "28-sg-mongodb-open-world": ("Network Oversights", "CRITICAL", "MongoDB open"),
    "29-sg-all-ports-open": ("Network Oversights", "CRITICAL", "All ports open"),
    "30-vpc-flow-logs-disabled": ("Network Oversights", "MEDIUM", "Flow logs disabled"),
    "31-rds-publicly-accessible": ("Network Oversights", "CRITICAL", "RDS public"),
    "32-default-vpc-in-use": ("Network Oversights", "MEDIUM", "Default VPC"),
    "33-s3-encryption-disabled": ("Lack of Encryption", "MEDIUM", "Encryption disabled"),
    "34-s3-sse-not-enforced": ("Lack of Encryption", "MEDIUM", "SSE not enforced"),
    "35-ebs-encryption-disabled": ("Lack of Encryption", "HIGH", "EBS encryption"),
    "36-rds-encryption-disabled": ("Lack of Encryption", "HIGH", "RDS encryption"),
    "37-dynamodb-encryption-disabled": ("Lack of Encryption", "MEDIUM", "DynamoDB encryption"),
    "38-lambda-env-not-encrypted": ("Lack of Encryption", "HIGH", "Lambda env not encrypted"),
    "39-sqs-encryption-disabled": ("Lack of Encryption", "MEDIUM", "SQS encryption"),
    "40-sns-encryption-disabled": ("Lack of Encryption", "MEDIUM", "SNS encryption"),
    "41-efs-encryption-disabled": ("Lack of Encryption", "HIGH", "EFS encryption"),
    "42-redshift-encryption-disabled": ("Lack of Encryption", "HIGH", "Redshift encryption"),
    "43-ec2-auto-assign-public-ip": ("Insecure Defaults", "MEDIUM", "Auto-assign public IP"),
    "44-default-security-group-in-use": ("Insecure Defaults", "HIGH", "Default security group"),
    "45-ec2-default-credential-report-not-enabled": ("Insecure Defaults", "LOW", "Credential report not enabled"),
    "46-cloudtrail-disabled": ("Insecure Defaults", "HIGH", "CloudTrail disabled"),
    "47-config-recorder-disabled": ("Insecure Defaults", "HIGH", "Config recorder disabled"),
    "48-guardduty-disabled": ("Insecure Defaults", "HIGH", "GuardDuty disabled"),
    "49-s3-logging-disabled": ("Insecure Defaults", "MEDIUM", "S3 logging disabled"),
    "50-iam-user-without-password-policy": ("Insecure Defaults", "MEDIUM", "Password policy missing"),
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
    
    # Find all Custodian findings
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
    print("RUNNING PIPELINE FOR EACH FINDING")
    print("=" * 60)
    
    for folder in findings:
        if folder in POLICY_MAP:
            category, severity, keyword = POLICY_MAP[folder]
            print(f"\n{'='*50}")
            print(f"Processing: {folder}")
            print(f"  Category: {category}")
            print(f"  Severity: {severity}")
            print(f"  Keyword: {keyword}")
            print(f"{'='*50}")
            
            # Run pipeline.py
            result = subprocess.run(
                ['python3', 'pipeline.py', category, severity, keyword],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("  ✓ Pipeline completed")
                # Show last few lines
                lines = result.stdout.split('\n')
                for line in lines[-10:]:
                    if line.strip():
                        print(f"    {line[:100]}")
            else:
                print(f"  ✗ Pipeline failed: {result.stderr[:200]}")
        else:
            print(f"⚠ No mapping found for {folder}")

if __name__ == "__main__":
    main()
