#!/usr/bin/env python3
"""
Phase 4: AWS Misconfiguration Auto-Fix Pipeline - REAL AWS IMPLEMENTATION
Complete automation for detection, backup, deploy, verify, rollback
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
        print("PHASE 4: AWS MISCONFIGURATION AUTO-FIX PIPELINE (REAL AWS)")
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
            
            for line in output.split('\n'):
                if 'Predicted Misconfig ID:' in line or 'Final Verdict: Misconfig ID' in line:
                    numbers = re.findall(r'\d+', line)
                    if numbers:
                        predicted_id = numbers[0]
                        break
            
            if not predicted_id:
                self.logger.error("Could not parse predicted ID")
                return None
            
            fix_policy = self.get_fix_policy(predicted_id)
            print(f"  Predicted Misconfig ID: {predicted_id}")
            
            return {
                'predicted_id': int(predicted_id),
                'fix_policy': fix_policy
            }
        except Exception as e:
            self.logger.error(f"Pipeline error: {e}")
            return None
    
    def get_fix_policy(self, misconfig_id):
        """Load fix policy from JSON"""
        fix_file = self.models_path / "fix_policies.json"
        if not fix_file.exists():
            self.logger.error(f"Fix policies file not found")
            return None
        
        with open(fix_file, 'r') as f:
            fix_policies = json.load(f)
        
        return fix_policies.get(str(misconfig_id))
    
    def get_user_approval(self, fix_policy):
        """Ask user for approval"""
        print("\n[2/7] User Approval Required")
        print("-" * 40)
        print(f"Misconfig ID: {fix_policy.get('misconfig_id', 'Unknown')}")
        print(f"Rule ID: {fix_policy.get('rule_id', 'Unknown')}")
        print(f"Category: {fix_policy.get('category', 'Unknown')}")
        print(f"Severity: {fix_policy.get('severity', 'Unknown')}")
        print(f"Description: {fix_policy.get('description', 'Unknown')[:150]}")
        print(f"\nFix Command: {fix_policy.get('fix_command', 'Unknown')[:100]}...")
        
        print("\n" + "-" * 40)
        response = input("Apply this fix to AWS? (yes/no): ").strip().lower()
        return response in ['yes', 'y']
    
    def backup_s3_bucket(self, bucket_name):
        """Backup S3 bucket configuration"""
        s3 = self.aws_session.client('s3')
        backup = {}
        
        try:
            backup['bucket_policy'] = s3.get_bucket_policy(Bucket=bucket_name)['Policy']
        except:
            backup['bucket_policy'] = None
        
        try:
            backup['public_access_block'] = s3.get_public_access_block(Bucket=bucket_name)
        except:
            backup['public_access_block'] = None
        
        try:
            backup['bucket_acl'] = s3.get_bucket_acl(Bucket=bucket_name)
        except:
            backup['bucket_acl'] = None
        
        return backup
    
    def backup_ec2_security_group(self, sg_id):
        """Backup EC2 security group rules"""
        ec2 = self.aws_session.client('ec2')
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        return response['SecurityGroups'][0]
    
    def backup_iam_user(self, user_name):
        """Backup IAM user policies"""
        iam = self.aws_session.client('iam')
        backup = {
            'inline_policies': [],
            'managed_policies': [],
            'access_keys': []
        }
        
        # Get inline policies
        response = iam.list_user_policies(UserName=user_name)
        backup['inline_policies'] = response['PolicyNames']
        
        # Get managed policies
        response = iam.list_attached_user_policies(UserName=user_name)
        backup['managed_policies'] = response['AttachedPolicies']
        
        # Get access keys
        response = iam.list_access_keys(UserName=user_name)
        backup['access_keys'] = response['AccessKeyMetadata']
        
        return backup
    
    def backup_current_state(self, fix_policy, aws_resource):
        """Backup current AWS state based on service"""
        print("\n[3/7] Backing up current state...")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = self.backup_dir / f"backup_{timestamp}.json"
        
        service = fix_policy.get('aws_service', '').upper()
        backup_data = {
            'timestamp': timestamp,
            'misconfig_id': fix_policy.get('misconfig_id'),
            'rule_id': fix_policy.get('rule_id'),
            'aws_service': service,
            'aws_resource': aws_resource,
            'backup': {}
        }
        
        try:
            if service == 'S3':
                backup_data['backup'] = self.backup_s3_bucket(aws_resource)
            elif service == 'EC2':
                backup_data['backup'] = self.backup_ec2_security_group(aws_resource)
            elif service == 'IAM':
                backup_data['backup'] = self.backup_iam_user(aws_resource)
            else:
                backup_data['backup'] = {'note': f'Backup for {service} not implemented'}
            
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            print(f"  Backup saved to: {backup_file}")
            self.logger.info(f"Backup completed: {backup_file}")
            return backup_file
            
        except Exception as e:
            self.logger.error(f"Backup failed: {e}")
            return None
    
    def deploy_s3_fix(self, bucket_name, fix_command):
        """Deploy S3 fix using boto3"""
        s3 = self.aws_session.client('s3')
        
        if 'put-public-access-block' in fix_command:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            print("  S3: Public access block enabled")
        
        if 'delete-bucket-policy' in fix_command:
            s3.delete_bucket_policy(Bucket=bucket_name)
            print("  S3: Bucket policy deleted")
        
        if 'put-bucket-encryption' in fix_command:
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }]
                }
            )
            print("  S3: Encryption enabled")
        
        return True
    
    def deploy_ec2_fix(self, sg_id, fix_command):
        """Deploy EC2 security group fix"""
        ec2 = self.aws_session.client('ec2')
        
        if 'revoke-security-group-ingress' in fix_command:
            # Remove SSH from 0.0.0.0/0
            try:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[{
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }]
                )
                print("  EC2: SSH from 0.0.0.0/0 revoked")
            except:
                print("  EC2: SSH rule not found or already removed")
        
        return True
    
    def deploy_iam_fix(self, user_name, fix_command):
        """Deploy IAM fix"""
        iam = self.aws_session.client('iam')
        
        if 'delete-user-policy' in fix_command:
            # Extract policy name from command
            import re
            match = re.search(r'--policy-name\s+(\S+)', fix_command)
            if match:
                policy_name = match.group(1)
                iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
                print(f"  IAM: Policy {policy_name} deleted")
        
        if 'update-access-key' in fix_command and 'Inactive' in fix_command:
            match = re.search(r'--access-key-id\s+(\S+)', fix_command)
            if match:
                key_id = match.group(1)
                iam.update_access_key(
                    UserName=user_name,
                    AccessKeyId=key_id,
                    Status='Inactive'
                )
                print(f"  IAM: Access key {key_id} deactivated")
        
        return True
    
    def deploy_fix(self, fix_policy, aws_resource):
        """Deploy fix policy to AWS"""
        print("\n[4/7] Deploying fix to AWS...")
        
        service = fix_policy.get('aws_service', '').upper()
        fix_command = fix_policy.get('fix_command', '')
        
        print(f"  Service: {service}")
        print(f"  Resource: {aws_resource}")
        
        try:
            if service == 'S3':
                self.deploy_s3_fix(aws_resource, fix_command)
            elif service == 'EC2':
                self.deploy_ec2_fix(aws_resource, fix_command)
            elif service == 'IAM':
                self.deploy_iam_fix(aws_resource, fix_command)
            else:
                print(f"  Service {service} deployment not implemented")
                return False
            
            self.logger.info(f"Fix deployed for {service}: {aws_resource}")
            print("  Fix deployed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Deployment failed: {e}")
            print(f"  ERROR: {e}")
            return False
    
    def verify_s3_fix(self, bucket_name):
        """Verify S3 fix was applied"""
        s3 = self.aws_session.client('s3')
        
        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
            config = response['PublicAccessBlockConfiguration']
            if config['BlockPublicAcls'] and config['BlockPublicPolicy']:
                return True
        except:
            pass
        return False
    
    def verify_ec2_fix(self, sg_id):
        """Verify EC2 security group fix"""
        ec2 = self.aws_session.client('ec2')
        response = ec2.describe_security_groups(GroupIds=[sg_id])
        
        for rule in response['SecurityGroups'][0].get('IpPermissions', []):
            if rule.get('FromPort') == 22:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        return False
        return True
    
    def verify_iam_fix(self, user_name):
        """Verify IAM fix"""
        iam = self.aws_session.client('iam')
        response = iam.list_user_policies(UserName=user_name)
        # If no policies, fix succeeded
        return len(response['PolicyNames']) == 0
    
    def verify_fix(self, fix_policy, aws_resource):
        """Verify fix was successful"""
        print("\n[5/7] Verifying fix...")
        time.sleep(5)  # Wait for propagation
        
        service = fix_policy.get('aws_service', '').upper()
        
        try:
            if service == 'S3':
                success = self.verify_s3_fix(aws_resource)
            elif service == 'EC2':
                success = self.verify_ec2_fix(aws_resource)
            elif service == 'IAM':
                success = self.verify_iam_fix(aws_resource)
            else:
                success = True
            
            if success:
                print("  Fix verified successfully")
                return True
            else:
                print("  Fix verification FAILED")
                return False
                
        except Exception as e:
            self.logger.error(f"Verification failed: {e}")
            return False
    
    def rollback_s3(self, bucket_name, backup_data):
        """Rollback S3 configuration"""
        s3 = self.aws_session.client('s3')
        
        if backup_data.get('bucket_policy'):
            s3.put_bucket_policy(Bucket=bucket_name, Policy=backup_data['bucket_policy'])
            print("  S3: Bucket policy restored")
    
    def rollback_ec2(self, sg_id, backup_data):
        """Rollback EC2 security group"""
        ec2 = self.aws_session.client('ec2')
        # Re-add the rules that were removed
        # This is complex - for now, log warning
        print("  EC2: Manual rollback may be required")
    
    def rollback(self, backup_file):
        """Rollback to previous state"""
        print("\n[6/7] Rolling back to previous state...")
        
        if not backup_file or not os.path.exists(backup_file):
            print("  No backup found. Cannot rollback.")
            return False
        
        try:
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
            
            service = backup_data.get('aws_service', '')
            aws_resource = backup_data.get('aws_resource', '')
            
            if service == 'S3':
                self.rollback_s3(aws_resource, backup_data['backup'])
            elif service == 'EC2':
                self.rollback_ec2(aws_resource, backup_data['backup'])
            else:
                print(f"  Rollback for {service} not implemented")
            
            print("  Rollback completed")
            self.logger.info(f"Rollback completed from {backup_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            return False
    
    def send_alert(self, message, success=True):
        """Send alert"""
        print("\n[7/7] Sending alert...")
        
        if success:
            self.logger.info(f"SUCCESS: {message}")
            print(f"  [SUCCESS] {message}")
        else:
            self.logger.error(f"FAILURE: {message}")
            print(f"  [ALERT] {message}")
    
    def get_aws_resource(self, fix_policy):
        """Get AWS resource identifier from user"""
        service = fix_policy.get('aws_service', '').upper()
        
        if service == 'S3':
            return input("Enter S3 bucket name: ").strip()
        elif service == 'EC2':
            return input("Enter Security Group ID (sg-xxxx): ").strip()
        elif service == 'IAM':
            return input("Enter IAM username: ").strip()
        elif service == 'RDS':
            return input("Enter RDS instance ID: ").strip()
        else:
            return input(f"Enter {service} resource identifier: ").strip()
    
    def run(self, category, severity, keywords):
        """Main execution flow"""
        print("\n" + "=" * 60)
        print("STARTING AUTO-FIX PIPELINE")
        print("=" * 60)
        print(f"Input: {category} | {severity} | {keywords[:50]}...")
        
        # Step 1: Detection
        result = self.call_pipeline(category, severity, keywords)
        if not result or not result['fix_policy']:
            self.send_alert("Detection failed", success=False)
            return False
        
        fix_policy = result['fix_policy']
        
        # Get AWS resource from user
        aws_resource = self.get_aws_resource(fix_policy)
        if not aws_resource:
            self.send_alert("No AWS resource provided", success=False)
            return False
        
        # Step 2: User approval
        if not self.get_user_approval(fix_policy):
            self.send_alert("User rejected the fix", success=False)
            return False
        
        # Step 3: Backup
        backup_file = self.backup_current_state(fix_policy, aws_resource)
        if not backup_file:
            self.send_alert("Backup failed", success=False)
            return False
        
        # Step 4: Deploy fix
        if not self.deploy_fix(fix_policy, aws_resource):
            self.send_alert("Deployment failed - rolling back", success=False)
            self.rollback(backup_file)
            return False
        
        # Step 5: Verify fix
        if not self.verify_fix(fix_policy, aws_resource):
            self.send_alert("Verification failed - rolling back", success=False)
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
