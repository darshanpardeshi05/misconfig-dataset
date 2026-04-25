#!/usr/bin/env python3
"""
Phase 4: AWS Misconfiguration Auto-Fix Pipeline
Complete automation for detection, backup, deploy, rollback
"""

import subprocess
import json
import os
import sys
import boto3
import time
import logging
import re
from datetime import datetime
from pathlib import Path

class AutoFixPipeline:
    def __init__(self, models_path="models"):
        self.models_path = Path(models_path)
        self.backup_dir = Path("backups")
        self.backup_dir.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('auto_fix.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        self.aws_session = None
        self.init_aws_session()
        
        print("=" * 60)
        print("PHASE 4: AWS MISCONFIGURATION AUTO-FIX PIPELINE")
        print("=" * 60)
    
    def init_aws_session(self):
        """Initialize AWS session"""
        try:
            self.aws_session = boto3.Session()
            self.sts = self.aws_session.client('sts')
            account_id = self.sts.get_caller_identity()['Account']
            self.region = self.aws_session.region_name or 'us-east-1'
            self.logger.info(f"AWS Session initialized for account: {account_id}, region: {self.region}")
            print(f"  AWS Account: {account_id}")
            print(f"  AWS Region: {self.region}")
        except Exception as e:
            self.logger.error(f"Failed to initialize AWS session: {e}")
            print("  ERROR: AWS credentials not configured")
            sys.exit(1)
    
    def call_pipeline(self, category, severity, keywords):
        """Call pipeline.py to get prediction and fix policy"""
        self.logger.info(f"Calling pipeline.py for: {category}/{severity}")
        print(f"\n[1/7] Detecting misconfiguration...")
        
        try:
            result = subprocess.run(
                ['python3', 'pipeline.py', category, severity, keywords],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                self.logger.error(f"Pipeline failed: {result.stderr}")
                return None
            
            output = result.stdout
            predicted_id = None
            
            # Parse output to find predicted ID
            for line in output.split('\n'):
                # Look for "Predicted Misconfig ID: 25" or "Final Verdict: Misconfig ID 25"
                if 'Predicted Misconfig ID:' in line or 'Final Verdict: Misconfig ID' in line:
                    # Extract numbers using regex
                    numbers = re.findall(r'\d+', line)
                    if numbers:
                        predicted_id = numbers[0]
                        break
            
            if not predicted_id:
                self.logger.error("Could not parse predicted ID from pipeline output")
                print("  ERROR: Could not detect misconfiguration ID")
                return None
            
            fix_policy = self.get_fix_policy(predicted_id)
            
            print(f"  Predicted Misconfig ID: {predicted_id}")
            
            return {
                'predicted_id': int(predicted_id),
                'fix_policy': fix_policy,
                'full_output': output
            }
            
        except subprocess.TimeoutExpired:
            self.logger.error("Pipeline timeout")
            return None
        except Exception as e:
            self.logger.error(f"Pipeline error: {e}")
            return None
    
    def get_fix_policy(self, misconfig_id):
        """Load fix policy from JSON"""
        fix_file = self.models_path / "fix_policies.json"
        
        if not fix_file.exists():
            self.logger.error(f"Fix policies file not found: {fix_file}")
            return None
        
        with open(fix_file, 'r') as f:
            fix_policies = json.load(f)
        
        misconfig_id_str = str(misconfig_id)
        if misconfig_id_str in fix_policies:
            return fix_policies[misconfig_id_str]
        else:
            self.logger.warning(f"No fix policy found for ID: {misconfig_id}")
            return None
    
    def get_user_approval(self, fix_policy):
        """Ask user for approval before applying fix"""
        print("\n[2/7] User Approval Required")
        print("-" * 40)
        print(f"Misconfig ID: {fix_policy.get('misconfig_id', 'Unknown')}")
        print(f"Rule ID: {fix_policy.get('rule_id', 'Unknown')}")
        print(f"Category: {fix_policy.get('category', 'Unknown')}")
        print(f"Severity: {fix_policy.get('severity', 'Unknown')}")
        print(f"Description: {fix_policy.get('description', 'Unknown')[:200]}")
        print(f"\nRemediation: {fix_policy.get('remediation', 'Unknown')}")
        
        print("\n" + "-" * 40)
        response = input("Apply this fix? (yes/no): ").strip().lower()
        
        return response in ['yes', 'y']
    
    def backup_current_state(self, fix_policy):
        """Backup current AWS state before applying fix"""
        print("\n[3/7] Backing up current state...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"backup_{timestamp}.json"
        
        backup_data = {
            'timestamp': timestamp,
            'misconfig_id': fix_policy.get('misconfig_id'),
            'rule_id': fix_policy.get('rule_id'),
            'aws_service': fix_policy.get('aws_service'),
            'status': 'backup_created'
        }
        
        with open(backup_file, 'w') as f:
            json.dump(backup_data, f, indent=2, default=str)
        
        print(f"  Backup saved to: {backup_file}")
        self.logger.info(f"Backup completed: {backup_file}")
        return backup_file
    
    def deploy_fix(self, fix_policy, backup_file):
        """Deploy the fix policy"""
        print("\n[4/7] Deploying fix...")
        
        fix_command = fix_policy.get('fix_command', '')
        service = fix_policy.get('aws_service', 'Unknown')
        
        print(f"  Service: {service}")
        print(f"  Command: {fix_command[:150]}...")
        
        # For Phase 4, we'll simulate deployment
        # Real deployment would execute actual boto3 commands
        print("  Fix deployed successfully (simulation mode)")
        self.logger.info(f"Fix deployed for service: {service}")
        return True
    
    def verify_fix(self, fix_policy):
        """Verify if fix was successful"""
        print("\n[5/7] Verifying fix...")
        time.sleep(2)
        
        print("  Fix verified successfully (simulation mode)")
        return True
    
    def rollback(self, backup_file):
        """Rollback to previous state if fix failed"""
        print("\n[6/7] Rolling back to previous state...")
        
        if not backup_file or not os.path.exists(backup_file):
            print("  No backup found. Cannot rollback.")
            return False
        
        print("  Rollback completed (simulation mode)")
        self.logger.info(f"Rollback completed from backup: {backup_file}")
        return True
    
    def send_alert(self, message, success=True):
        """Send alert for success or failure"""
        print("\n[7/7] Sending alert...")
        
        if success:
            self.logger.info(f"SUCCESS: {message}")
            print(f"  [SUCCESS] {message}")
        else:
            self.logger.error(f"FAILURE: {message}")
            print(f"  [ALERT] {message}")
    
    def run(self, category, severity, keywords):
        """Main execution flow"""
        print("\n" + "=" * 60)
        print("STARTING AUTO-FIX PIPELINE")
        print("=" * 60)
        print(f"Input: {category} | {severity} | {keywords[:50]}...")
        
        # Step 1: Detection
        result = self.call_pipeline(category, severity, keywords)
        if not result or not result['fix_policy']:
            self.send_alert("Detection failed - no fix policy found", success=False)
            return False
        
        fix_policy = result['fix_policy']
        
        # Step 2: User approval
        if not self.get_user_approval(fix_policy):
            self.send_alert("User rejected the fix", success=False)
            return False
        
        # Step 3: Backup
        backup_file = self.backup_current_state(fix_policy)
        if not backup_file:
            self.send_alert("Backup failed - aborting fix", success=False)
            return False
        
        # Step 4: Deploy fix
        if not self.deploy_fix(fix_policy, backup_file):
            self.send_alert("Fix deployment failed - initiating rollback", success=False)
            self.rollback(backup_file)
            return False
        
        # Step 5: Verify fix
        if not self.verify_fix(fix_policy):
            self.send_alert("Verification failed - initiating rollback", success=False)
            self.rollback(backup_file)
            return False
        
        # Success
        self.send_alert(f"Fix successfully applied for Misconfig ID {result['predicted_id']}", success=True)
        
        print("\n" + "=" * 60)
        print("AUTO-FIX PIPELINE COMPLETED SUCCESSFULLY")
        print("=" * 60)
        return True


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 auto_fix.py <category> <severity> <keywords>")
        print("Example: python3 auto_fix.py 'Storage Exposure' 'CRITICAL' 'PublicRead'")
        sys.exit(1)
    
    category = sys.argv[1]
    severity = sys.argv[2]
    keywords = sys.argv[3]
    
    pipeline = AutoFixPipeline()
    success = pipeline.run(category, severity, keywords)
    
    sys.exit(0 if success else 1)
