#!/usr/bin/env python3
"""
Universal Prowler to Text - Extracts category, severity, keyword for ALL 50 misconfigs
"""

import json
import sys
import re
from pathlib import Path

# Mapping table for ALL 50 misconfigurations
# Format: (search_pattern, category, severity, keyword, service_type)
PROWLER_MAP = [
    # S3 Misconfigurations (1-10, 33-34, 49)
    (r"bucket policy allowing cross account access", "Storage Exposure", "CRITICAL", "PublicRead", "s3"),
    (r"bucket ACLs enabled.*public", "Storage Exposure", "CRITICAL", "PublicRead", "s3"),
    (r"public read access", "Storage Exposure", "CRITICAL", "PublicRead", "s3"),
    (r"public read and write", "Storage Exposure", "CRITICAL", "PublicReadWrite", "s3"),
    (r"Block Public Access is not configured for the S3 Bucket", "Storage Exposure", "HIGH", "BlockPublicAccess disabled", "s3"),
    (r"S3 Bucket.*encryption.*disabled", "Lack of Encryption", "MEDIUM", "Encryption disabled", "s3"),
    (r"S3 Bucket.*server side encryption.*not configured", "Lack of Encryption", "MEDIUM", "Encryption disabled", "s3"),
    (r"EBS snapshot.*public", "Storage Exposure", "CRITICAL", "EBS snapshot public", "ebs"),
    (r"RDS snapshot.*public", "Storage Exposure", "CRITICAL", "RDS snapshot public", "rds"),
    (r"ECR repository.*public", "Storage Exposure", "HIGH", "ECR public", "ecr"),
    (r"AMI.*public", "Storage Exposure", "CRITICAL", "AMI public", "ami"),
    (r"EFS.*public", "Storage Exposure", "HIGH", "EFS public mount", "efs"),
    (r"object.*public.*ACL", "Storage Exposure", "HIGH", "S3 object public", "s3"),
    
    # IAM Misconfigurations (11-22, 50)
    (r"IAM policy.*Action.*\*.*allows ALL actions", "IAM Over-Permission", "HIGH", "Action wildcard", "iam"),
    (r"IAM policy.*Resource.*\*", "IAM Over-Permission", "HIGH", "Resource wildcard", "iam"),
    (r"AdministratorAccess.*attached", "IAM Over-Permission", "CRITICAL", "AdministratorAccess", "iam"),
    (r"s3:\*.*permission", "IAM Over-Permission", "HIGH", "s3 full access", "iam"),
    (r"ec2:\*.*permission", "IAM Over-Permission", "HIGH", "ec2 full access", "iam"),
    (r"Root.*MFA.*not enabled", "IAM Over-Permission", "CRITICAL", "Root MFA missing", "iam"),
    (r"User.*MFA.*not enabled", "IAM Over-Permission", "HIGH", "User MFA missing", "iam"),
    (r"Inactive IAM user", "IAM Over-Permission", "MEDIUM", "Inactive user", "iam"),
    (r"Access key.*older than 90 days", "IAM Over-Permission", "MEDIUM", "Old access key", "iam"),
    (r"Trust policy.*Principal.*\*", "IAM Over-Permission", "CRITICAL", "Principal star trust", "iam"),
    (r"Lambda.*role.*AdministratorAccess", "IAM Over-Permission", "CRITICAL", "Lambda over permissive", "iam"),
    (r"Password policy.*not.*enforced", "Insecure Defaults", "MEDIUM", "Password policy missing", "iam"),
    
    # Network Misconfigurations (23-32)
    (r"SSH.*0\.0\.0\.0/0", "Network Oversights", "HIGH", "SSH open", "ec2"),
    (r"RDP.*0\.0\.0\.0/0", "Network Oversights", "HIGH", "RDP open", "ec2"),
    (r"MySQL.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "MySQL open", "ec2"),
    (r"PostgreSQL.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "PostgreSQL open", "ec2"),
    (r"Redis.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "Redis open", "ec2"),
    (r"MongoDB.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "MongoDB open", "ec2"),
    (r"all ports.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "All ports open", "ec2"),
    (r"VPC Flow Logs disabled", "Network Oversights", "MEDIUM", "Flow logs disabled", "vpc"),
    (r"RDS.*publicly accessible", "Network Oversights", "CRITICAL", "RDS public", "rds"),
    (r"Default VPC.*in use", "Network Oversights", "MEDIUM", "Default VPC", "vpc"),
    
    # Encryption Misconfigurations (35-42)
    (r"EBS volume.*not encrypted", "Lack of Encryption", "HIGH", "EBS encryption", "ebs"),
    (r"RDS instance.*not encrypted", "Lack of Encryption", "HIGH", "RDS encryption", "rds"),
    (r"DynamoDB.*not encrypted", "Lack of Encryption", "MEDIUM", "DynamoDB encryption", "dynamodb"),
    (r"Lambda.*environment variables.*not encrypted", "Lack of Encryption", "HIGH", "Lambda env not encrypted", "lambda"),
    (r"SQS queue.*not encrypted", "Lack of Encryption", "MEDIUM", "SQS encryption", "sqs"),
    (r"SNS topic.*not encrypted", "Lack of Encryption", "MEDIUM", "SNS encryption", "sns"),
    (r"EFS.*not encrypted", "Lack of Encryption", "HIGH", "EFS encryption", "efs"),
    (r"Redshift.*not encrypted", "Lack of Encryption", "HIGH", "Redshift encryption", "redshift"),
    
    # Insecure Defaults (43-48)
    (r"EC2.*auto-assign public IP", "Insecure Defaults", "MEDIUM", "Auto-assign public IP", "ec2"),
    (r"default security group.*in use", "Insecure Defaults", "HIGH", "Default security group", "ec2"),
    (r"credential report.*not.*generated", "Insecure Defaults", "LOW", "Credential report not enabled", "iam"),
    (r"CloudTrail.*disabled", "Insecure Defaults", "HIGH", "CloudTrail disabled", "cloudtrail"),
    (r"Config recorder.*disabled", "Insecure Defaults", "HIGH", "Config recorder disabled", "config"),
    (r"GuardDuty.*disabled", "Insecure Defaults", "HIGH", "GuardDuty disabled", "guardduty"),
    (r"S3 access logging.*disabled", "Insecure Defaults", "MEDIUM", "S3 logging disabled", "s3"),
]

def extract_misconfig_from_prowler(prowler_file):
    """Read Prowler JSON and extract matching misconfig"""
    
    if not Path(prowler_file).exists():
        print(f"Error: File not found - {prowler_file}", file=sys.stderr)
        return None
    
    with open(prowler_file, 'r') as f:
        data = json.load(f)
    
    if isinstance(data, list):
        items = data
    else:
        items = data.get('findings', data.get('results', []))
    
    for item in items:
        message = item.get('message', item.get('description', ''))
        
        for pattern, category, severity, keyword, service in PROWLER_MAP:
            if re.search(pattern, message, re.IGNORECASE):
                return f"{category} | {severity} | {keyword}"
    
    return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 prowler_to_text.py <prowler_output_file>", file=sys.stderr)
        sys.exit(1)
    
    prowler_file = sys.argv[1]
    
    result = extract_misconfig_from_prowler(prowler_file)
    
    if result:
        print(result)
    else:
        print("No matching misconfiguration found", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
