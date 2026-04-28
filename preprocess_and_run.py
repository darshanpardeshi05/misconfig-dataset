#!/usr/bin/env python3
"""
Preprocess and Run Pipeline
Reads normalized findings, processes ONLY Custodian findings
Calls pipeline.py (which triggers phase4_complete.py)
"""

import json
import subprocess
import re
from pathlib import Path

class PreprocessAndRun:
    def __init__(self):
        self.base_dir = Path("/home/darshan/misconfig-dataset")
        self.normalized_file = self.base_dir / "normalized-results" / "all_findings.json"
        
        print("=" * 60)
        print("PREPROCESSING FINDINGS AND RUNNING PIPELINE")
        print("=" * 60)
    
    def extract_keywords(self, finding):
        """Extract keywords from Custodian finding by misconfig_id"""
        mid = finding.get('misconfig_id', '00')
        
        # Map misconfig_id to exact keywords from training data
        mapping = {
            '01': 'PublicRead',
            '02': 'PublicReadWrite',
            '03': 'BlockPublicAccess disabled',
            '04': 'EBS snapshot public',
            '05': 'RDS snapshot public',
            '06': 'ECR public',
            '07': 'AMI public',
            '08': 'EFS public mount',
            '09': 'S3 bucket policy public',
            '10': 'S3 object public',
            '11': 'Action wildcard',
            '12': 'Resource wildcard',
            '13': 'Action wildcard',
            '14': 'AdministratorAccess',
            '15': 's3 full access',
            '16': 'ec2 full access',
            '17': 'Root MFA missing',
            '18': 'User MFA missing',
            '19': 'Inactive user',
            '20': 'Old access key',
            '21': 'Principal star',
            '22': 'Lambda over permissive',
            '23': 'SSH open',
            '24': 'RDP open',
            '25': 'MySQL open',
            '26': 'PostgreSQL open',
            '27': 'Redis open',
            '28': 'MongoDB open',
            '29': 'All ports open',
            '30': 'Flow logs disabled',
            '31': 'RDS public',
            '32': 'Default VPC',
            '33': 'Encryption disabled',
            '34': 'SSE not enforced',
            '35': 'EBS encryption',
            '36': 'RDS encryption',
            '38': 'Lambda env not encrypted',
            '39': 'SQS encryption',
            '40': 'SNS encryption',
            '41': 'EFS encryption',
            '43': 'Auto-assign public IP',
            '44': 'Default security group',
            '45': 'Credential report not enabled',
            '49': 'S3 logging disabled',
            '50': 'Password policy missing'
        }
        return mapping.get(mid, 'misconfiguration')
    
    def get_category_severity(self, finding):
        """Get category and severity from finding"""
        category = finding.get('category', 'Storage Exposure')
        severity = finding.get('severity', 'CRITICAL')
        return category, severity
    
    def run(self):
        if not self.normalized_file.exists():
            print(f"Error: {self.normalized_file} not found")
            print("Run normalize_results.py first")
            return False
        
        with open(self.normalized_file, 'r') as f:
            data = json.load(f)
        
        findings = data.get('findings', [])
        
        # Filter only Custodian findings
        custodian_findings = [f for f in findings if f.get('tool') == 'custodian']
        
        print(f"\nFound {len(custodian_findings)} Custodian findings to process")
        print(f"(Skipping Prowler/ScoutSuite findings to avoid timeouts)\n")
        
        for finding in custodian_findings:
            misconfig_id = finding.get('misconfig_id', 'Unknown')
            category, severity = self.get_category_severity(finding)
            keywords = self.extract_keywords(finding)
            
            print(f"\n{'='*50}")
            print(f"Processing Custodian Finding ID: {misconfig_id}")
            print(f"  Category: {category}")
            print(f"  Severity: {severity}")
            print(f"  Keywords: {keywords}")
            print(f"{'='*50}")
            
            # Call pipeline.py
            print(f"\nCalling pipeline.py...")
            result = subprocess.run(
                ['python3', 'pipeline.py', category, severity, keywords],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=self.base_dir
            )
            
            if result.returncode == 0:
                print(f"  Pipeline completed successfully")
                # Show last few lines of output
                lines = result.stdout.split('\n')
                for line in lines[-15:]:
                    if line.strip():
                        print(f"    {line[:150]}")
            else:
                print(f"  Pipeline error: {result.stderr[:300]}")
        
        print("\n" + "=" * 60)
        print("PREPROCESSING AND PIPELINE EXECUTION COMPLETE")
        print("=" * 60)
        return True

if __name__ == "__main__":
    processor = PreprocessAndRun()
    processor.run()
