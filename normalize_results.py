#!/usr/bin/env python3
"""
Normalize Results from Prowler, ScoutSuite, and Custodian
Combines all findings into a single unified JSON format
Supports ALL 50 misconfigurations from ALL 3 tools
"""

import json
import os
import glob
import re
from pathlib import Path

class ResultsNormalizer:
    def __init__(self):
        self.base_dir = Path("/home/darshan/misconfig-dataset")
        self.normalized_dir = self.base_dir / "normalized-results"
        self.normalized_dir.mkdir(exist_ok=True)
        
        self.all_findings = []
        
        print("=" * 60)
        print("NORMALIZING RESULTS FROM ALL SCANNING TOOLS")
        print("=" * 60)
    
    def extract_category_from_text(self, text):
        text_lower = text.lower()
        categories = {
            'storage-exposure': ['s3', 'ebs', 'rds', 'ecr', 'ami', 'efs', 'bucket', 'snapshot', 'repository', 'volume'],
            'iam-over-permission': ['iam', 'role', 'policy', 'user', 'access key', 'mfa', 'administrator', 'wildcard'],
            'network-oversights': ['security group', 'sg', 'vpc', 'flow logs', 'port', 'ssh', 'rdp', 'mysql', 'postgres', 'redis', 'mongodb'],
            'lack-of-encryption': ['encryption', 'encrypted', 'sse', 'kms', 'plaintext'],
            'insecure-defaults': ['default', 'cloudtrail', 'config', 'guardduty', 'password policy', 'credential report']
        }
        
        for category, keywords in categories.items():
            for keyword in keywords:
                if keyword in text_lower:
                    return category.replace('-', ' ').title()
        return "Unknown"
    
    def extract_severity(self, text):
        text_upper = text.upper()
        if 'CRITICAL' in text_upper:
            return 'CRITICAL'
        elif 'HIGH' in text_upper:
            return 'HIGH'
        elif 'MEDIUM' in text_upper:
            return 'MEDIUM'
        elif 'LOW' in text_upper:
            return 'LOW'
        return 'MEDIUM'
    
    def process_prowler(self):
        print("\n[1/3] Processing Prowler results...")
        
        prowler_file = self.base_dir / "scan-results" / "prowler_output.json"
        if not prowler_file.exists():
            print("  Warning: Prowler output not found")
            return
        
        with open(prowler_file, 'r') as f:
            data = json.load(f)
        
        count = 0
        if isinstance(data, list):
            findings = data
        else:
            findings = data.get('findings', data.get('results', []))
        
        for finding in findings:
            description = finding.get('message', finding.get('description', str(finding)))
            severity = finding.get('severity', 'MEDIUM')
            
            resource = 'Unknown'
            if 'unmapped' in finding and 'resource_name' in finding['unmapped']:
                resource = finding['unmapped']['resource_name']
            elif 'resource_id' in finding:
                resource = finding['resource_id']
            
            finding_data = {
                'tool': 'prowler',
                'category': self.extract_category_from_text(description),
                'severity': self.extract_severity(severity),
                'description': description[:500],
                'resource': resource,
                'raw_data': finding
            }
            self.all_findings.append(finding_data)
            count += 1
        
        print(f"  Processed {count} findings from Prowler")
    
    def process_scoutsuite(self):
        print("\n[2/3] Processing ScoutSuite results...")
        
        scout_file = self.base_dir / "scan-results" / "scoutsuite_converted.json"
        if not scout_file.exists():
            print("  Warning: ScoutSuite output not found")
            return
        
        with open(scout_file, 'r') as f:
            data = json.load(f)
        
        count = 0
        services = data.get('services', {})
        
        # Process each service
        for service_name, service_data in services.items():
            if not isinstance(service_data, dict):
                continue
            
            # Look for buckets/s3 specific findings
            if service_name == 's3' and 'buckets' in service_data:
                for bucket_name, bucket_info in service_data['buckets'].items():
                    if isinstance(bucket_info, dict):
                        # Check for public access
                        if bucket_info.get('publicly_accessible', False):
                            finding_data = {
                                'tool': 'scoutsuite',
                                'category': 'Storage Exposure',
                                'severity': 'HIGH',
                                'description': f"S3 bucket '{bucket_name}' is publicly accessible",
                                'resource': bucket_name,
                                'raw_data': bucket_info
                            }
                            self.all_findings.append(finding_data)
                            count += 1
                        
                        # Check ACL
                        if 'acl' in bucket_info:
                            acl = bucket_info['acl']
                            if acl.get('public_read', False) or acl.get('public_write', False):
                                finding_data = {
                                    'tool': 'scoutsuite',
                                    'category': 'Storage Exposure',
                                    'severity': 'HIGH',
                                    'description': f"S3 bucket '{bucket_name}' has public ACL",
                                    'resource': bucket_name,
                                    'raw_data': bucket_info
                                }
                                self.all_findings.append(finding_data)
                                count += 1
                        
                        # Check policy
                        if 'policy' in bucket_info and bucket_info['policy']:
                            policy_str = str(bucket_info['policy']).lower()
                            if 'principal' in policy_str and '*' in policy_str:
                                finding_data = {
                                    'tool': 'scoutsuite',
                                    'category': 'Storage Exposure',
                                    'severity': 'HIGH',
                                    'description': f"S3 bucket '{bucket_name}' has public bucket policy",
                                    'resource': bucket_name,
                                    'raw_data': bucket_info
                                }
                                self.all_findings.append(finding_data)
                                count += 1
            
            # Process findings from any service
            if 'findings' in service_data:
                for finding in service_data['findings']:
                    if isinstance(finding, dict):
                        desc = finding.get('description', str(finding))
                        finding_data = {
                            'tool': 'scoutsuite',
                            'category': self.extract_category_from_text(service_name),
                            'severity': self.extract_severity(str(finding)),
                            'description': f"{service_name}: {desc[:200]}",
                            'resource': finding.get('resource_name', service_name),
                            'raw_data': finding
                        }
                        self.all_findings.append(finding_data)
                        count += 1
        
        print(f"  Processed {count} findings from ScoutSuite")
    
    def process_custodian(self):
        print("\n[3/3] Processing Custodian results...")
        
        custodian_dir = self.base_dir / "custodian-results"
        if not custodian_dir.exists():
            print("  Warning: Custodian results not found")
            return
        
        count = 0
        # Find all resources.json files (handles both flat and nested structures)
        resources_files = []
        resources_files.extend(custodian_dir.glob("*/resources.json"))
        resources_files.extend(custodian_dir.glob("*/*/resources.json"))
        
        for resources_file in resources_files:
            folder_name = resources_file.parent.name
            try:
                with open(resources_file, 'r') as f:
                    resources = json.load(f)
            except:
                continue
            
            if resources and len(resources) > 0 and resources != []:
                # Extract policy ID from folder name
                parts = folder_name.split('-')
                policy_id = parts[0] if parts[0].isdigit() else "00"
                
                # Look up category and severity from fix_policies.json
                category = "Unknown"
                severity = "MEDIUM"
                try:
                    fix_file = self.base_dir / "models" / "fix_policies.json"
                    if fix_file.exists():
                        with open(fix_file, 'r') as f:
                            fix_policies = json.load(f)
                            if policy_id in fix_policies:
                                category = fix_policies[policy_id].get('category', 'Unknown')
                                severity = fix_policies[policy_id].get('severity', 'MEDIUM')
                except:
                    pass
                
                # Get resource name
                resource_name = "Unknown"
                if resources and len(resources) > 0:
                    resource_name = resources[0].get('Name', resources[0].get('RepositoryName', resources[0].get('name', str(resources[0]))))
                
                finding_data = {
                    'tool': 'custodian',
                    'misconfig_id': policy_id,
                    'category': category,
                    'severity': severity,
                    'description': f"Misconfiguration detected by policy {folder_name}",
                    'resource': resource_name,
                    'raw_data': resources
                }
                self.all_findings.append(finding_data)
                count += 1
        
        print(f"  Processed {count} findings from Custodian")
    
    def save_normalized_results(self):
        output_file = self.normalized_dir / "all_findings.json"
        
        output_data = {
            'total_findings': len(self.all_findings),
            'findings': self.all_findings
        }
        
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        print(f"\n" + "=" * 60)
        print(f"NORMALIZATION COMPLETE")
        print(f"  Total findings: {len(self.all_findings)}")
        print(f"  Output saved to: {output_file}")
        print("=" * 60)
        
        return output_file
    
    def run(self):
        self.process_prowler()
        self.process_scoutsuite()
        self.process_custodian()
        return self.save_normalized_results()

if __name__ == "__main__":
    normalizer = ResultsNormalizer()
    output_file = normalizer.run()
    print(f"\nNext step: Run preprocess_and_run.py")
