#!/usr/bin/env python3
"""
ScoutSuite to Text - Extract category, severity, keyword from existing ScoutSuite output
Does NOT run ScoutSuite scan - only reads existing JS/JSON file
"""

import json
import sys
import re
import glob
from pathlib import Path

# Mapping table for ALL 50 misconfigurations
SCOUT_MAP = [
    # S3 Misconfigurations (1-10, 33-34, 49)
    (r"public.*read.*acl", "Storage Exposure", "CRITICAL", "PublicRead"),
    (r"public.*read.*write", "Storage Exposure", "CRITICAL", "PublicReadWrite"),
    (r"block public access.*disabled", "Storage Exposure", "HIGH", "BlockPublicAccess disabled"),
    (r"EBS snapshot.*public", "Storage Exposure", "CRITICAL", "EBS snapshot public"),
    (r"RDS snapshot.*public", "Storage Exposure", "CRITICAL", "RDS snapshot public"),
    (r"ECR.*public", "Storage Exposure", "HIGH", "ECR public"),
    (r"AMI.*public", "Storage Exposure", "CRITICAL", "AMI public"),
    (r"EFS.*public", "Storage Exposure", "HIGH", "EFS public mount"),
    (r"bucket policy.*principal.*\*", "Storage Exposure", "CRITICAL", "Principal star"),
    (r"object.*public.*acl", "Storage Exposure", "HIGH", "S3 object public"),
    (r"encryption.*disabled", "Lack of Encryption", "MEDIUM", "Encryption disabled"),
    (r"sse.*not.*enforced", "Lack of Encryption", "MEDIUM", "SSE not enforced"),
    (r"logging.*disabled", "Insecure Defaults", "MEDIUM", "S3 logging disabled"),
    
    # IAM Misconfigurations (11-22, 50)
    (r"action.*\*.*policy", "IAM Over-Permission", "HIGH", "Action wildcard"),
    (r"resource.*\*.*policy", "IAM Over-Permission", "HIGH", "Resource wildcard"),
    (r"administratoraccess", "IAM Over-Permission", "CRITICAL", "AdministratorAccess"),
    (r"s3:\*", "IAM Over-Permission", "HIGH", "s3 full access"),
    (r"ec2:\*", "IAM Over-Permission", "HIGH", "ec2 full access"),
    (r"root.*mfa.*disabled", "IAM Over-Permission", "CRITICAL", "Root MFA missing"),
    (r"user.*mfa.*disabled", "IAM Over-Permission", "HIGH", "User MFA missing"),
    (r"inactive.*user", "IAM Over-Permission", "MEDIUM", "Inactive user"),
    (r"access key.*old", "IAM Over-Permission", "MEDIUM", "Old access key"),
    (r"trust policy.*principal.*\*", "IAM Over-Permission", "CRITICAL", "Principal star trust"),
    (r"lambda.*role.*admin", "IAM Over-Permission", "CRITICAL", "Lambda over permissive"),
    (r"password policy", "Insecure Defaults", "MEDIUM", "Password policy missing"),
    
    # Network Misconfigurations (23-32)
    (r"ssh.*0\.0\.0\.0/0", "Network Oversights", "HIGH", "SSH open"),
    (r"rdp.*0\.0\.0\.0/0", "Network Oversights", "HIGH", "RDP open"),
    (r"mysql.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "MySQL open"),
    (r"postgres.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "PostgreSQL open"),
    (r"redis.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "Redis open"),
    (r"mongodb.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "MongoDB open"),
    (r"all ports.*0\.0\.0\.0/0", "Network Oversights", "CRITICAL", "All ports open"),
    (r"flow logs.*disabled", "Network Oversights", "MEDIUM", "Flow logs disabled"),
    (r"rds.*publicly accessible", "Network Oversights", "CRITICAL", "RDS public"),
    (r"default vpc.*in use", "Network Oversights", "MEDIUM", "Default VPC"),
    
    # Encryption Misconfigurations (35-42)
    (r"ebs.*not encrypted", "Lack of Encryption", "HIGH", "EBS encryption"),
    (r"rds.*not encrypted", "Lack of Encryption", "HIGH", "RDS encryption"),
    (r"dynamodb.*not encrypted", "Lack of Encryption", "MEDIUM", "DynamoDB encryption"),
    (r"lambda.*env.*not encrypted", "Lack of Encryption", "HIGH", "Lambda env not encrypted"),
    (r"sqs.*not encrypted", "Lack of Encryption", "MEDIUM", "SQS encryption"),
    (r"sns.*not encrypted", "Lack of Encryption", "MEDIUM", "SNS encryption"),
    (r"efs.*not encrypted", "Lack of Encryption", "HIGH", "EFS encryption"),
    (r"redshift.*not encrypted", "Lack of Encryption", "HIGH", "Redshift encryption"),
    
    # Insecure Defaults (43-48)
    (r"auto.*assign.*public ip", "Insecure Defaults", "MEDIUM", "Auto-assign public IP"),
    (r"default security group", "Insecure Defaults", "HIGH", "Default security group"),
    (r"credential report", "Insecure Defaults", "LOW", "Credential report not enabled"),
    (r"cloudtrail.*disabled", "Insecure Defaults", "HIGH", "CloudTrail disabled"),
    (r"config.*recorder.*disabled", "Insecure Defaults", "HIGH", "Config recorder disabled"),
    (r"guardduty.*disabled", "Insecure Defaults", "HIGH", "GuardDuty disabled"),
]

def find_scoutsuite_file(base_dir):
    """Find the ScoutSuite results JS file"""
    js_files = glob.glob(f"{base_dir}/**/scoutsuite_results_*.js", recursive=True)
    if not js_files:
        js_files = glob.glob(f"{base_dir}/**/*.js", recursive=True)
        js_files = [f for f in js_files if 'scoutsuite_results' in f]
    
    if not js_files:
        return None
    return js_files[0]

def convert_js_to_json(js_file):
    """Convert ScoutSuite JS to JSON object"""
    with open(js_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    start = content.find('{')
    if start == -1:
        return None
    
    json_content = content[start:]
    return json.loads(json_content)

def extract_misconfig_from_scoutsuite(data):
    """Extract misconfig from ScoutSuite JSON data"""
    if not data:
        return None
    
    # Convert to string for regex searching
    data_str = json.dumps(data).lower()
    
    for pattern, category, severity, keyword in SCOUT_MAP:
        if re.search(pattern, data_str, re.IGNORECASE):
            return f"{category} | {severity} | {keyword}"
    
    return None

def main():
    base_dir = "/home/darshan/misconfig-dataset/scan-results/scoutsuite"
    
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    
    print("Searching for ScoutSuite output...", file=sys.stderr)
    
    js_file = find_scoutsuite_file(base_dir)
    if not js_file:
        print("Error: ScoutSuite output file not found", file=sys.stderr)
        print("Run: scout aws --report-dir scan-results/scoutsuite --quiet", file=sys.stderr)
        sys.exit(1)
    
    print(f"Found: {js_file}", file=sys.stderr)
    
    data = convert_js_to_json(js_file)
    if not data:
        print("Error: Could not parse ScoutSuite output", file=sys.stderr)
        sys.exit(1)
    
    result = extract_misconfig_from_scoutsuite(data)
    
    if result:
        print(result)
    else:
        print("No matching misconfiguration found", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
