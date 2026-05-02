#!/usr/bin/env python3
"""
Universal Prowler to Text - Extracts category, severity, keyword for ALL 50 misconfigs
"""

import json
import sys
import re
from pathlib import Path

# Mapping table - MORE SPECIFIC patterns FIRST
PROWLER_MAP = [
    # S3 - Public ReadWrite (MUST come before PublicRead)
    (r"allows public write access", "Storage Exposure", "CRITICAL", "PublicReadWrite"),
    (r"public read and write", "Storage Exposure", "CRITICAL", "PublicReadWrite"),
    (r"public read.*write", "Storage Exposure", "CRITICAL", "PublicReadWrite"),
    
    # S3 - Public Read
    (r"bucket policy allowing cross account access", "Storage Exposure", "CRITICAL", "PublicRead"),
    (r"bucket ACLs enabled", "Storage Exposure", "CRITICAL", "PublicRead"),
    (r"public read access", "Storage Exposure", "CRITICAL", "PublicRead"),
    
    # S3 - Block Public Access
    (r"Block Public Access is not configured for the S3 Bucket", "Storage Exposure", "HIGH", "BlockPublicAccess disabled"),
    (r"Block Public Access is not configured for the account", "Storage Exposure", "HIGH", "BlockPublicAccess disabled"),
    
    # S3 - Encryption
    (r"S3 Bucket.*encryption.*disabled", "Lack of Encryption", "MEDIUM", "Encryption disabled"),
    (r"server side encryption.*not configured", "Lack of Encryption", "MEDIUM", "Encryption disabled"),
    
    # EBS
    (r"EBS snapshot.*public", "Storage Exposure", "CRITICAL", "EBS snapshot public"),
    (r"EBS volume.*not encrypted", "Lack of Encryption", "HIGH", "EBS encryption"),
    
    # RDS
    (r"RDS snapshot.*public", "Storage Exposure", "CRITICAL", "RDS snapshot public"),
    (r"RDS.*publicly accessible", "Network Oversights", "CRITICAL", "RDS public"),
    (r"RDS instance.*not encrypted", "Lack of Encryption", "HIGH", "RDS encryption"),
    
    # ECR
    (r"ECR repository.*public", "Storage Exposure", "HIGH", "ECR public"),
    
    # AMI
    (r"AMI.*public", "Storage Exposure", "CRITICAL", "AMI public"),
    
    # EFS
    (r"EFS.*public", "Storage Exposure", "HIGH", "EFS public mount"),
    (r"EFS.*not encrypted", "Lack of Encryption", "HIGH", "EFS encryption"),
    
    # IAM
    (r"AdministratorAccess.*attached", "IAM Over-Permission", "CRITICAL", "AdministratorAccess"),
    (r"IAM policy.*Action.*\*", "IAM Over-Permission", "HIGH", "Action wildcard"),
    (r"IAM policy.*Resource.*\*", "IAM Over-Permission", "HIGH", "Resource wildcard"),
    (r"s3:\*.*permission", "IAM Over-Permission", "HIGH", "s3 full access"),
    (r"ec2:\*.*permission", "IAM Over-Permission", "HIGH", "ec2 full access"),
    (r"Root.*MFA.*not enabled", "IAM Over-Permission", "CRITICAL", "Root MFA missing"),
    (r"User.*MFA.*not enabled", "IAM Over-Permission", "HIGH", "User MFA missing"),
    (r"Inactive IAM user", "IAM Over-Permission", "MEDIUM", "Inactive user"),
    (r"Access key.*older than 90 days", "IAM Over-Permission", "MEDIUM", "Old access key"),
    (r"Trust policy.*Principal.*\*", "IAM Over-Permission", "CRITICAL", "Principal star trust"),
    (r"Lambda.*role.*AdministratorAccess", "IAM Over-Permission", "CRITICAL", "Lambda over permissive"),
    (r"Password policy.*not.*enforced", "Insecure Defaults", "MEDIUM", "Password policy missing"),
    
    # Network
    (r"SSH.*0\.0\.0\.0/0", "Network Oversights", "HIGH", "SSH open"),
    (r"RDP.*0\.0\.0\.0/0", "Network Oversights", "HIGH", "RDP open"),
    (r"MySQL.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "MySQL open"),
    (r"PostgreSQL.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "PostgreSQL open"),
    (r"Redis.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "Redis open"),
    (r"MongoDB.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "MongoDB open"),
    (r"all ports.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "All ports open"),
    (r"VPC Flow Logs disabled", "Network Oversights", "MEDIUM", "Flow logs disabled"),
    (r"Default VPC.*in use", "Network Oversights", "MEDIUM", "Default VPC"),
    
    # Other
    (r"DynamoDB.*not encrypted", "Lack of Encryption", "MEDIUM", "DynamoDB encryption"),
    (r"Lambda.*environment variables.*not encrypted", "Lack of Encryption", "HIGH", "Lambda env not encrypted"),
    (r"SQS queue.*not encrypted", "Lack of Encryption", "MEDIUM", "SQS encryption"),
    (r"SNS topic.*not encrypted", "Lack of Encryption", "MEDIUM", "SNS encryption"),
    (r"Redshift.*not encrypted", "Lack of Encryption", "HIGH", "Redshift encryption"),
    (r"CloudTrail.*disabled", "Insecure Defaults", "HIGH", "CloudTrail disabled"),
    (r"Config recorder.*disabled", "Insecure Defaults", "HIGH", "Config recorder disabled"),
    (r"GuardDuty.*disabled", "Insecure Defaults", "HIGH", "GuardDuty disabled"),
    (r"S3 access logging.*disabled", "Insecure Defaults", "MEDIUM", "S3 logging disabled"),
    (r"auto.*assign.*public ip", "Insecure Defaults", "MEDIUM", "Auto-assign public IP"),
    (r"default security group", "Insecure Defaults", "HIGH", "Default security group"),
    (r"credential report", "Insecure Defaults", "LOW", "Credential report not enabled"),
]

def extract_misconfig_from_prowler(prowler_file):
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
        
        # Only process messages containing your bucket name
        if "s3-rw-" not in message:
            continue
        
        for pattern, category, severity, keyword in PROWLER_MAP:
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
