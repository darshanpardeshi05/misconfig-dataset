#!/usr/bin/env python3
"""
Preprocess and Run Pipeline
Reads normalized findings, extracts category/severity/keywords,
calls pipeline.py ONLY (which will automatically trigger phase4_complete.py)
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
    
    def extract_keywords_for_pipeline(self, finding):
        """Extract keywords from finding for pipeline input"""
        
        # For Custodian, use misconfig_id to get proper keywords
        if finding.get('tool') == 'custodian' and 'misconfig_id' in finding:
            mid = finding['misconfig_id']
            keywords_map = {
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
                '13': 'Action and Resource wildcard',
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
                '44': 'Default security group in use',
                '45': 'Credential report not enabled',
                '49': 'S3 logging disabled',
                '50': 'Password policy missing'
            }
            return keywords_map.get(mid, 'misconfiguration')
        
        # For Prowler and ScoutSuite, extract from description
        description = finding.get('description', '')
        desc_lower = description.lower()
        
        if 's3' in desc_lower and 'public' in desc_lower:
            return 'PublicRead'
        elif 'ebs' in desc_lower and 'snapshot' in desc_lower:
            return 'EBS snapshot public'
        elif 'rds' in desc_lower and 'snapshot' in desc_lower:
            return 'RDS snapshot public'
        elif 'ecr' in desc_lower:
            return 'ECR public'
        elif 'ami' in desc_lower:
            return 'AMI public'
        elif 'iam' in desc_lower or 'policy' in desc_lower:
            return 'Action wildcard'
        elif 'ssh' in desc_lower or 'port 22' in desc_lower:
            return 'SSH open'
        elif 'rdp' in desc_lower or 'port 3389' in desc_lower:
            return 'RDP open'
        elif 'encryption' in desc_lower:
            return 'Encryption disabled'
        elif 'cloudtrail' in desc_lower:
            return 'CloudTrail disabled'
        elif 'guardduty' in desc_lower:
            return 'GuardDuty disabled'
        elif 'config' in desc_lower:
            return 'Config recorder disabled'
        else:
            return 'misconfiguration'
    
    def run_pipeline(self, category, severity, keywords):
        """Call pipeline.py (which will trigger phase4_complete.py internally)"""
        print(f"\n  Calling pipeline.py...")
        print(f"    Input: category={category}, severity={severity}")
        print(f"    Keywords: {keywords}")
        
        try:
            result = subprocess.run(
                ['python3', 'pipeline.py', category, severity, keywords],
                capture_output=True, text=True, timeout=300, cwd=self.base_dir
            )
            
            if result.returncode == 0:
                print(f"    Pipeline completed successfully")
                # Print last few lines of output for visibility
                output_lines = result.stdout.split('\n')
                for line in output_lines[-10:]:
                    if line.strip():
                        print(f"    {line[:100]}")
            else:
                print(f"    Pipeline failed: {result.stderr[:200]}")
            
            return result.returncode == 0
        except Exception as e:
            print(f"    Pipeline error: {e}")
            return False
    
    def run(self):
        if not self.normalized_file.exists():
            print(f"Error: {self.normalized_file} not found")
            print("Run normalize_results.py first")
            return False
        
        with open(self.normalized_file, 'r') as f:
            data = json.load(f)
        
        findings = data.get('findings', [])
        total = len(findings)
        
        print(f"\nFound {total} findings to process")
        
        success_count = 0
        for idx, finding in enumerate(findings, 1):
            print(f"\n[{idx}/{total}] Processing finding...")
            print(f"  Tool: {finding.get('tool')}")
            print(f"  Category: {finding.get('category')}")
            print(f"  Severity: {finding.get('severity')}")
            
            category = finding.get('category', 'Unknown')
            severity = finding.get('severity', 'MEDIUM')
            keywords = self.extract_keywords_for_pipeline(finding)
            
            # Only call pipeline.py - it will trigger Phase 4 automatically
            if self.run_pipeline(category, severity, keywords):
                success_count += 1
        
        print("\n" + "=" * 60)
        print("PREPROCESSING AND PIPELINE EXECUTION COMPLETE")
        print("=" * 60)
        print(f"  Successful: {success_count}/{total}")
        print("=" * 60)
        return success_count == total

if __name__ == "__main__":
    processor = PreprocessAndRun()
    processor.run()
