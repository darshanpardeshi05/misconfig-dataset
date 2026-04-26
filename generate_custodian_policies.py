#!/usr/bin/env python3
"""
Generate Custodian YAML policies from CloudFormation misconfig templates
Reads all 50 YAML files from category folders and creates custodian policies
"""

import os
import re
import yaml
from pathlib import Path

# Your local paths
BASE_PATH = Path("/home/darshan/misconfig-dataset")
CUSTODIAN_OUTPUT = BASE_PATH / "custodian-policies"
CUSTODIAN_OUTPUT.mkdir(exist_ok=True)

# Category folders and their corresponding AWS services
CATEGORY_FOLDERS = {
    "1-storage-exposure": ["s3", "ebs", "rds", "ecr", "ami", "efs"],
    "2-iam-over-permission": ["iam", "lambda"],
    "3-network-oversights": ["ec2", "vpc", "rds"],
    "4-lack-of-encryption": ["s3", "ebs", "rds", "dynamodb", "lambda", "sqs", "sns", "efs", "redshift"],
    "5-insecure-defaults": ["ec2", "iam", "cloudtrail", "config", "guardduty", "s3"]
}

def extract_metadata_from_yaml(file_path):
    """Extract misconfiguration metadata from CloudFormation template"""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Simple extraction using regex (since files are small)
    metadata = {}
    
    # Extract RuleId
    match = re.search(r'RuleId:\s*"([^"]+)"', content)
    if match:
        metadata['rule_id'] = match.group(1)
    
    # Extract Category
    match = re.search(r'Category:\s*"([^"]+)"', content)
    if match:
        metadata['category'] = match.group(1)
    
    # Extract Severity
    match = re.search(r'Severity:\s*"([^"]+)"', content)
    if match:
        metadata['severity'] = match.group(1)
    
    # Extract Description
    match = re.search(r'Description:\s*"([^"]+)"', content)
    if match:
        metadata['description'] = match.group(1)
    
    # Extract Remediation
    match = re.search(r'Remediation:\s*"([^"]+)"', content)
    if match:
        metadata['remediation'] = match.group(1)
    
    # Extract Keywords list
    keywords = []
    kw_section = re.search(r'Keywords:\s*\n((?:\s*-\s*"[^"]+"\s*\n)+)', content)
    if kw_section:
        keyword_lines = kw_section.group(1)
        keywords = re.findall(r'-\s*"([^"]+)"', keyword_lines)
    metadata['keywords'] = keywords
    
    return metadata

def determine_resource_type(rule_id, category):
    """Map misconfig rule IDs to AWS resource types for Custodian"""
    resource_map = {
        'S3': 'aws.s3',
        'EBS': 'aws.ebs',
        'RDS': 'aws.rds',
        'ECR': 'aws.ecr',
        'AMI': 'aws.ami',
        'EFS': 'aws.efs',
        'IAM': 'aws.iam-role' if 'role' in rule_id.lower() else 'aws.iam-user',
        'LAMBDA': 'aws.lambda',
        'EC2': 'aws.ec2',
        'VPC': 'aws.vpc',
        'DYNAMODB': 'aws.dynamodb',
        'SQS': 'aws.sqs',
        'SNS': 'aws.sns',
        'REDSHIFT': 'aws.redshift',
        'CLOUDTRAIL': 'aws.cloudtrail',
        'CONFIG': 'aws.config',
        'GUARDDUTY': 'aws.guardduty'
    }
    
    for key, resource in resource_map.items():
        if key in rule_id:
            return resource
    return 'aws.ec2'  # Default

def create_custodian_policy(metadata, file_name, resource_type):
    """Create Custodian YAML policy content"""
    
    policy_name = file_name.replace('.yaml', '').replace('.yml', '')
    
    policy = {
        'policies': [
            {
                'name': f'check-{policy_name}',
                'resource': resource_type,
                'description': metadata.get('description', ''),
                'metadata': {
                    'rule_id': metadata.get('rule_id', ''),
                    'category': metadata.get('category', ''),
                    'severity': metadata.get('severity', ''),
                    'remediation': metadata.get('remediation', ''),
                    'keywords': metadata.get('keywords', [])
                },
                'filters': [
                    {
                        'type': 'value',
                        'key': 'tag:Misconfiguration',
                        'value': metadata.get('rule_id', '')
                    }
                ],
                'actions': [
                    {
                        'type': 'notify',
                        'template': 'default',
                        'priority': 'info'
                    }
                ]
            }
        ]
    }
    
    return yaml.dump(policy, default_flow_style=False, sort_keys=False)

def main():
    print("=" * 60)
    print("Generating Custodian Policies from 50 Misconfigurations")
    print("=" * 60)
    
    total_files = 0
    policies_created = 0
    
    for category_folder, services in CATEGORY_FOLDERS.items():
        folder_path = BASE_PATH / category_folder
        if not folder_path.exists():
            print(f"  Warning: Folder not found - {category_folder}")
            continue
        
        yaml_files = list(folder_path.glob("*.yaml")) + list(folder_path.glob("*.yml"))
        
        for yaml_file in yaml_files:
            total_files += 1
            print(f"\n[{total_files}] Processing: {category_folder}/{yaml_file.name}")
            
            try:
                # Extract metadata from CloudFormation template
                metadata = extract_metadata_from_yaml(yaml_file)
                
                if not metadata.get('rule_id'):
                    print(f"     Warning: No RuleId found, skipping")
                    continue
                
                # Determine AWS resource type
                resource_type = determine_resource_type(metadata['rule_id'], category_folder)
                
                # Create Custodian policy
                policy_content = create_custodian_policy(metadata, yaml_file.name, resource_type)
                
                # Save policy file
                output_file = CUSTODIAN_OUTPUT / f"{yaml_file.stem}.yaml"
                with open(output_file, 'w') as f:
                    f.write(policy_content)
                
                print(f"     Created: custodian-policies/{output_file.name}")
                policies_created += 1
                
            except Exception as e:
                print(f"     Error: {e}")
    
    print("\n" + "=" * 60)
    print(f"SUMMARY")
    print("=" * 60)
    print(f"  Total files processed: {total_files}")
    print(f"  Policies created: {policies_created}")
    print(f"  Output folder: {CUSTODIAN_OUTPUT}")
    print("=" * 60)

if __name__ == "__main__":
    main()
