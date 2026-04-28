#!/usr/bin/env python3
"""
Retrain XGBoost with ALL keywords and ensure correct mapping
"""

import os
import re
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import xgboost as xgb
import joblib
from pathlib import Path

BASE_PATH = Path("/home/darshan/misconfig-dataset")

# Manual mapping to ensure correct predictions
KEYWORD_TO_ID = {
    'PublicRead': 1,
    'PublicReadWrite': 2,
    'BlockPublicAccess disabled': 3,
    'EBS snapshot public': 4,
    'RDS snapshot public': 5,
    'ECR public': 6,
    'AMI public': 7,
    'EFS public mount': 8,
    'S3 bucket policy public': 9,
    'S3 object public': 10,
    'Action wildcard': 11,
    'Resource wildcard': 12,
    'AdministratorAccess': 14,
    's3 full access': 15,
    'ec2 full access': 16,
    'Root MFA missing': 17,
    'User MFA missing': 18,
    'Inactive user': 19,
    'Old access key': 20,
    'Principal star': 21,
    'Lambda over permissive': 22,
    'SSH open': 23,
    'RDP open': 24,
    'MySQL open': 25,
    'PostgreSQL open': 26,
    'Redis open': 27,
    'MongoDB open': 28,
    'All ports open': 29,
    'Flow logs disabled': 30,
    'RDS public': 31,
    'Default VPC': 32,
    'Encryption disabled': 33,
    'SSE not enforced': 34,
    'EBS encryption': 35,
    'RDS encryption': 36,
    'Lambda env not encrypted': 38,
    'SQS encryption': 39,
    'SNS encryption': 40,
    'EFS encryption': 41,
    'Auto-assign public IP': 43,
    'Default security group': 44,
    'Credential report not enabled': 45,
    'S3 logging disabled': 49,
    'Password policy missing': 50
}

def extract_keywords_and_label(yaml_file):
    with open(yaml_file, 'r') as f:
        content = f.read()
    
    match = re.search(r'RuleId:\s*"([^"]+)"', content)
    if not match:
        return None
    
    label = match.group(1)
    
    category_match = re.search(r'Category:\s*"([^"]+)"', content)
    category = category_match.group(1) if category_match else "Unknown"
    
    severity_match = re.search(r'Severity:\s*"([^"]+)"', content)
    severity = severity_match.group(1) if severity_match else "MEDIUM"
    
    keywords = []
    kw_section = re.search(r'Keywords:\s*\n((?:\s*-\s*"[^"]+"\s*\n)+)', content)
    if kw_section:
        keyword_lines = kw_section.group(1)
        keywords = re.findall(r'-\s*"([^"]+)"', keyword_lines)
    
    return {
        'category': category,
        'severity': severity,
        'keywords': keywords,
        'rule_id': label
    }

def main():
    print("=" * 60)
    print("RETRAINING XGBOOST WITH KEYWORD TO ID MAPPING")
    print("=" * 60)
    
    all_data = []
    
    # First, add manual keyword mapping
    for keyword, misconfig_id in KEYWORD_TO_ID.items():
        all_data.append({
            'category': 'Storage-Exposure' if misconfig_id <= 10 else 'IAM-OverPermission',
            'severity': 'CRITICAL' if misconfig_id <= 10 else 'HIGH',
            'keyword': keyword,
            'rule_id': str(misconfig_id)
        })
    
    # Also extract from YAML files for additional keywords
    category_folders = ["1-storage-exposure", "2-iam-over-permission", "3-network-oversights", "4-lack-of-encryption", "5-insecure-defaults"]
    
    for category_folder in category_folders:
        folder_path = BASE_PATH / category_folder
        if not folder_path.exists():
            continue
        
        for yaml_file in folder_path.glob("*.yaml"):
            data = extract_keywords_and_label(yaml_file)
            if data and data['keywords']:
                for keyword in data['keywords']:
                    # Extract number from RuleId (e.g., S3-001 -> 1)
                    numbers = re.findall(r'\d+', data['rule_id'])
                    rule_num = int(numbers[0]) if numbers else 0
                    
                    all_data.append({
                        'category': data['category'].replace('-', ' '),
                        'severity': data['severity'],
                        'keyword': keyword,
                        'rule_id': str(rule_num)
                    })
    
    df = pd.DataFrame(all_data)
    df = df.drop_duplicates(subset=['keyword', 'rule_id'])
    
    print(f"Total training samples: {len(df)}")
    print(f"Unique keywords: {df['keyword'].nunique()}")
    print(f"Unique labels: {df['rule_id'].nunique()}")
    
    # Encode
    le_category = LabelEncoder()
    le_severity = LabelEncoder()
    le_keyword = LabelEncoder()
    le_label = LabelEncoder()
    
    df['category_enc'] = le_category.fit_transform(df['category'])
    df['severity_enc'] = le_severity.fit_transform(df['severity'])
    df['keyword_enc'] = le_keyword.fit_transform(df['keyword'])
    df['label_enc'] = le_label.fit_transform(df['rule_id'])
    
    X = df[['category_enc', 'severity_enc', 'keyword_enc']]
    y = df['label_enc']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("\nTraining XGBoost model...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        random_state=42,
        eval_metric='mlogloss',
        use_label_encoder=False
    )
    
    xgb_model.fit(X_train, y_train)
    
    # Test prediction for "PublicRead"
    test_keyword = 'PublicRead'
    try:
        test_cat_enc = le_category.transform(['Storage Exposure'])[0]
        test_sev_enc = le_severity.transform(['CRITICAL'])[0]
        test_kw_enc = le_keyword.transform([test_keyword])[0]
        
        test_input = pd.DataFrame([[test_cat_enc, test_sev_enc, test_kw_enc]], 
                                  columns=['category_enc', 'severity_enc', 'keyword_enc'])
        pred = xgb_model.predict(test_input)
        pred_label = le_label.inverse_transform(pred)[0]
        print(f"\nTest: Keyword '{test_keyword}' -> Predicted ID: {pred_label}")
    except Exception as e:
        print(f"\nTest prediction error: {e}")
    
    # Save models
    models_path = BASE_PATH / "models"
    joblib.dump(xgb_model, models_path / "xgboost_model.pkl")
    
    # Create feature encoders in the format pipeline expects
    feature_encoders = {
        'category': le_category,
        'severity': le_severity,
        'keywords': le_keyword
    }
    joblib.dump(feature_encoders, models_path / "xgboost_feature_encoders.pkl")
    joblib.dump(le_label, models_path / "xgboost_label_encoder.pkl")
    joblib.dump(le_label, models_path / "xgboost_train_label_encoder.pkl")
    
    print("\n" + "=" * 60)
    print("RETRAINING COMPLETE")
    print("=" * 60)
    print(f"  Model saved to: {models_path / 'xgboost_model.pkl'}")
    print("=" * 60)

if __name__ == "__main__":
    main()
