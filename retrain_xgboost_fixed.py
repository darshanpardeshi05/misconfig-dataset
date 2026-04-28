#!/usr/bin/env python3
"""
Retrain XGBoost with continuous labels and ALL keywords
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

# Complete keyword to misconfig ID mapping (ALL 50)
KEYWORD_TO_ID = {
    # Storage Exposure (1-10)
    'PublicRead': 1,
    'PublicReadWrite': 2,
    'BlockPublicAccess disabled': 3,
    'EBS snapshot public': 4,
    'RDS snapshot public': 5,
    'ECR public': 6,
    'AMI public': 7,
    'EFS public mount': 8,
    'S3 bucket policy public': 9,
    'Principal star': 9,
    'bucket policy principal star': 9,
    'Principal *': 9,
    'S3 object public': 10,
    # IAM Over-Permission (11-22)
    'Action wildcard': 11,
    'Resource wildcard': 12,
    'Action and Resource wildcard': 13,
    'AdministratorAccess': 14,
    's3 full access': 15,
    'ec2 full access': 16,
    'Root MFA missing': 17,
    'User MFA missing': 18,
    'Inactive user': 19,
    'Old access key': 20,
    'Principal star trust': 21,
    'Lambda over permissive': 22,
    # Network Oversights (23-32)
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
    # Lack of Encryption (33-42)
    'Encryption disabled': 33,
    'SSE not enforced': 34,
    'EBS encryption': 35,
    'RDS encryption': 36,
    'DynamoDB encryption': 37,
    'Lambda env not encrypted': 38,
    'SQS encryption': 39,
    'SNS encryption': 40,
    'EFS encryption': 41,
    'Redshift encryption': 42,
    # Insecure Defaults (43-50)
    'Auto-assign public IP': 43,
    'Default security group': 44,
    'Credential report not enabled': 45,
    'CloudTrail disabled': 46,
    'Config recorder disabled': 47,
    'GuardDuty disabled': 48,
    'S3 logging disabled': 49,
    'Password policy missing': 50
}

def main():
    print("=" * 60)
    print("RETRAINING XGBOOST WITH ALL 50 MISCONFIGURATIONS")
    print("=" * 60)
    
    all_data = []
    
    # Add all keyword mappings
    for keyword, misconfig_id in KEYWORD_TO_ID.items():
        # Determine category based on ID range
        if misconfig_id <= 10:
            category = "Storage Exposure"
            severity = "CRITICAL"
        elif misconfig_id <= 22:
            category = "IAM Over-Permission"
            severity = "HIGH"
        elif misconfig_id <= 32:
            category = "Network Oversights"
            severity = "HIGH"
        elif misconfig_id <= 42:
            category = "Lack of Encryption"
            severity = "MEDIUM"
        else:
            category = "Insecure Defaults"
            severity = "MEDIUM"
        
        all_data.append({
            'category': category,
            'severity': severity,
            'keyword': keyword,
            'label': misconfig_id
        })
    
    # Create DataFrame
    df = pd.DataFrame(all_data)
    df = df.drop_duplicates(subset=['keyword', 'label'])
    
    print(f"Total training samples: {len(df)}")
    print(f"Unique keywords: {df['keyword'].nunique()}")
    print(f"Unique labels: {sorted(df['label'].unique())}")
    
    # Encode using LabelEncoder (handles non-continuous labels)
    le_category = LabelEncoder()
    le_severity = LabelEncoder()
    le_keyword = LabelEncoder()
    le_label = LabelEncoder()
    
    df['category_enc'] = le_category.fit_transform(df['category'])
    df['severity_enc'] = le_severity.fit_transform(df['severity'])
    df['keyword_enc'] = le_keyword.fit_transform(df['keyword'])
    df['label_enc'] = le_label.fit_transform(df['label'])
    
    print(f"Encoded labels (0-{df['label_enc'].max()}): {sorted(df['label_enc'].unique())}")
    
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
    
    # Test predictions
    print("\nTesting predictions:")
    test_cases = [
        ('Storage Exposure', 'CRITICAL', 'PublicRead', 1),
        ('Storage Exposure', 'CRITICAL', 'PublicReadWrite', 2),
        ('Storage Exposure', 'HIGH', 'BlockPublicAccess disabled', 3),
        ('Storage Exposure', 'CRITICAL', 'Principal star', 9),
        ('Storage Exposure', 'CRITICAL', 'bucket policy principal star', 9),
        ('IAM Over-Permission', 'HIGH', 'Action wildcard', 11),
        ('Network Oversights', 'HIGH', 'SSH open', 23),
    ]
    
    for category, severity, keyword, expected in test_cases:
        try:
            cat_enc = le_category.transform([category])[0]
            sev_enc = le_severity.transform([severity])[0]
            kw_enc = le_keyword.transform([keyword])[0]
            
            test_input = pd.DataFrame([[cat_enc, sev_enc, kw_enc]], 
                                      columns=['category_enc', 'severity_enc', 'keyword_enc'])
            pred_enc = xgb_model.predict(test_input)
            pred_label = le_label.inverse_transform(pred_enc)[0]
            status = "✓" if pred_label == expected else "✗"
            print(f"  {status} '{keyword}' -> Predicted: {pred_label}, Expected: {expected}")
        except Exception as e:
            print(f"  ✗ '{keyword}' failed: {e}")
    
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
    print(f"  Model saved to: {models_path / 'xgboost_model.pkl'}")
    print("=" * 60)

if __name__ == "__main__":
    main()
