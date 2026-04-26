#!/usr/bin/env python3
"""
Preprocess and Run Pipeline
Reads normalized findings, extracts category/severity/keywords,
calls pipeline.py and phase4_complete.py for auto-fix
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
        
        # Simple keyword extraction based on description
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
        """Call pipeline.py to get prediction"""
        print(f"\n  Calling pipeline.py...")
        print(f"    Input: category={category}, severity={severity}")
        print(f"    Keywords: {keywords}")
        
        try:
            result = subprocess.run(
                ['python3', 'pipeline.py', category, severity, keywords],
                capture_output=True, text=True, timeout=30, cwd=self.base_dir
            )
            
            predicted_id = None
            for line in result.stdout.split('\n'):
                numbers = re.findall(r'\d+', line)
                if numbers and ('Predicted Misconfig ID:' in line or 'Final Verdict:' in line):
                    predicted_id = numbers[0]
                    break
            
            return {'success': True, 'predicted_id': predicted_id, 'output': result.stdout[:300]}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def run_autofix(self, category, severity, keywords):
        """Call phase4_complete.py for auto-fix"""
        print(f"\n  Running auto-fix...")
        
        try:
            result = subprocess.run(
                ['python3', 'phase4_complete.py', category, severity, keywords],
                capture_output=True, text=True, timeout=300, cwd=self.base_dir
            )
            return {'success': result.returncode == 0, 'output': result.stdout[:300]}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
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
        
        for idx, finding in enumerate(findings, 1):
            print(f"\n[{idx}/{total}] Processing finding...")
            print(f"  Tool: {finding.get('tool')}")
            print(f"  Category: {finding.get('category')}")
            print(f"  Severity: {finding.get('severity')}")
            
            category = finding.get('category', 'Unknown')
            severity = finding.get('severity', 'MEDIUM')
            keywords = self.extract_keywords_for_pipeline(finding)
            
            # Run pipeline.py
            pipeline_result = self.run_pipeline(category, severity, keywords)
            
            if pipeline_result['success']:
                print(f"    Pipeline success. Predicted ID: {pipeline_result.get('predicted_id')}")
                
                # Run auto-fix
                autofix_result = self.run_autofix(category, severity, keywords)
                if autofix_result['success']:
                    print(f"    Auto-fix completed successfully")
                else:
                    print(f"    Auto-fix failed: {autofix_result.get('error')}")
            else:
                print(f"    Pipeline failed: {pipeline_result.get('error')}")
        
        print("\n" + "=" * 60)
        print("PREPROCESSING AND PIPELINE EXECUTION COMPLETE")
        print("=" * 60)
        return True

if __name__ == "__main__":
    processor = PreprocessAndRun()
    processor.run()

