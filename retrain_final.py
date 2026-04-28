#!/usr/bin/env python3
"""
Final XGBoost Retraining - Force add all keywords including 'Principal star'
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import xgboost as xgb
import joblib
from pathlib import Path

BASE_PATH = Path("/home/darshan/misconfig-dataset")

# Complete training data: (category, severity, keyword, label)
training_data = [
    # Misconfig #1
    ("Storage Exposure", "CRITICAL", "PublicRead", 1),
    ("Storage Exposure", "CRITICAL", "AccessControl: PublicRead", 1),
    ("Storage Exposure", "CRITICAL", "BlockPublicAcls: false", 1),
    # Misconfig #2
    ("Storage Exposure", "CRITICAL", "PublicReadWrite", 2),
    ("Storage Exposure", "CRITICAL", "AccessControl: PublicReadWrite", 2),
    # Misconfig #3
    ("Storage Exposure", "HIGH", "BlockPublicAcls: false", 3),
    ("Storage Exposure", "HIGH", "BlockPublicPolicy: false", 3),
    ("Storage Exposure", "HIGH", "IgnorePublicAcls: false", 3),
    ("Storage Exposure", "HIGH", "RestrictPublicBuckets: false", 3),
    # Misconfig #4
    ("Storage Exposure", "CRITICAL", "createVolumePermission", 4),
    ("Storage Exposure", "CRITICAL", "group-names all", 4),
    # Misconfig #5
    ("Storage Exposure", "CRITICAL", "modify-db-snapshot-attribute", 5),
    ("Storage Exposure", "CRITICAL", "values-to-add all", 5),
    # Misconfig #6
    ("Storage Exposure", "HIGH", "Principal: '*'", 6),
    ("Storage Exposure", "HIGH", "ecr:GetDownloadUrlForLayer", 6),
    # Misconfig #7
    ("Storage Exposure", "CRITICAL", "modify-image-attribute", 7),
    ("Storage Exposure", "CRITICAL", "launch-permission", 7),
    # Misconfig #8
    ("Storage Exposure", "HIGH", "port 2049", 8),
    ("Storage Exposure", "HIGH", "0.0.0.0/0", 8),
    # Misconfig #9
    ("Storage Exposure", "CRITICAL", "Principal: '*'", 9),
    ("Storage Exposure", "CRITICAL", "Effect: Allow", 9),
    ("Storage Exposure", "CRITICAL", "s3:GetObject", 9),
    ("Storage Exposure", "CRITICAL", "bucket policy public", 9),
    ("Storage Exposure", "CRITICAL", "Principal star", 9),   # ADDED
    # Misconfig #10
    ("Storage Exposure", "HIGH", "public-read", 10),
    ("Storage Exposure", "HIGH", "put-object-acl", 10),
    # Misconfig #11
    ("IAM Over-Permission", "HIGH", "Action: '*'", 11),
    ("IAM Over-Permission", "HIGH", "Action wildcard", 11),
    # Misconfig #12
    ("IAM Over-Permission", "HIGH", "Resource: '*'", 12),
    ("IAM Over-Permission", "HIGH", "Resource wildcard", 12),
    # Misconfig #13-22 (add more as needed)
    ("IAM Over-Permission", "CRITICAL", "AdministratorAccess", 14),
    ("IAM Over-Permission", "HIGH", "s3:*", 15),
    ("IAM Over-Permission", "HIGH", "ec2:*", 16),
    # Network misconfigs
    ("Network Oversights", "HIGH", "port 22", 23),
    ("Network Oversights", "HIGH", "SSH open", 23),
    ("Network Oversights", "HIGH", "port 3389", 24),
    ("Network Oversights", "HIGH", "RDP open", 24),
    ("Network Oversights", "CRITICAL", "port 3306", 25),
    ("Network Oversights", "CRITICAL", "MySQL open", 25),
    ("Network Oversights", "CRITICAL", "port 5432", 26),
    ("Network Oversights", "CRITICAL", "PostgreSQL open", 26),
    ("Network Oversights", "CRITICAL", "port 6379", 27),
    ("Network Oversights", "CRITICAL", "Redis open", 27),
    ("Network Oversights", "CRITICAL", "port 27017", 28),
    ("Network Oversights", "CRITICAL", "MongoDB open", 28),
    ("Network Oversights", "CRITICAL", "-1", 29),
    ("Network Oversights", "CRITICAL", "all ports", 29),
    ("Network Oversights", "MEDIUM", "FlowLog", 30),
    ("Network Oversights", "MEDIUM", "VPCFlowLogs", 30),
    ("Network Oversights", "CRITICAL", "PubliclyAccessible: true", 31),
    ("Network Oversights", "CRITICAL", "RDS public", 31),
    ("Network Oversights", "MEDIUM", "Default VPC", 32),
    # Encryption misconfigs
    ("Lack of Encryption", "MEDIUM", "BucketEncryption", 33),
    ("Lack of Encryption", "MEDIUM", "encryption disabled", 33),
    ("Lack of Encryption", "MEDIUM", "PutObject", 34),
    ("Lack of Encryption", "MEDIUM", "x-amz-server-side-encryption", 34),
    ("Lack of Encryption", "HIGH", "Encrypted: false", 35),
    ("Lack of Encryption", "HIGH", "StorageEncrypted: false", 36),
    ("Lack of Encryption", "MEDIUM", "SSESpecification", 37),
    ("Lack of Encryption", "HIGH", "KmsKeyArn", 38),
    ("Lack of Encryption", "MEDIUM", "KmsMasterKeyId", 39),
    ("Lack of Encryption", "MEDIUM", "TopicEncryption", 40),
    ("Lack of Encryption", "HIGH", "Encrypted: false EF", 41),
    ("Lack of Encryption", "HIGH", "Redshift encryption", 42),
    # Insecure Defaults
    ("Insecure Defaults", "MEDIUM", "MapPublicIpOnLaunch: true", 43),
    ("Insecure Defaults", "MEDIUM", "AssociatePublicIpAddress: true", 43),
    ("Insecure Defaults", "HIGH", "default security group", 44),
    ("Insecure Defaults", "LOW", "credential report", 45),
    ("Insecure Defaults", "HIGH", "CloudTrail", 46),
    ("Insecure Defaults", "HIGH", "ConfigurationRecorder", 47),
    ("Insecure Defaults", "HIGH", "GuardDuty", 48),
    ("Insecure Defaults", "MEDIUM", "LoggingConfiguration", 49),
    ("Insecure Defaults", "MEDIUM", "PasswordPolicy", 50),
]

def main():
    print("=" * 60)
    print("FINAL XGBOOST RETRAINING")
    print("=" * 60)
    
    df = pd.DataFrame(training_data, columns=['category', 'severity', 'keyword', 'label'])
    df = df.drop_duplicates(subset=['keyword', 'label'])
    
    print(f"Total training samples: {len(df)}")
    print(f"Unique keywords: {df['keyword'].nunique()}")
    print(f"Unique labels: {sorted(df['label'].unique())}")
    
    # Encode
    le_category = LabelEncoder()
    le_severity = LabelEncoder()
    le_keyword = LabelEncoder()
    le_label = LabelEncoder()
    
    df['category_enc'] = le_category.fit_transform(df['category'])
    df['severity_enc'] = le_severity.fit_transform(df['severity'])
    df['keyword_enc'] = le_keyword.fit_transform(df['keyword'])
    df['label_enc'] = le_label.fit_transform(df['label'])
    
    X = df[['category_enc', 'severity_enc', 'keyword_enc']].copy()
    y = df['label_enc']
    
    print("\nTraining XGBoost model...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        random_state=42,
        eval_metric='mlogloss',
        use_label_encoder=False
    )
    
    xgb_model.fit(X, y)
    
    # Test predictions
    print("\nTesting predictions:")
    test_cases = [
        ('Storage Exposure', 'CRITICAL', 'PublicRead', 1),
        ('Storage Exposure', 'CRITICAL', 'PublicReadWrite', 2),
        ('Storage Exposure', 'HIGH', 'BlockPublicPolicy: false', 3),
        ('Storage Exposure', 'CRITICAL', 'Principal star', 9),
        ('Storage Exposure', 'CRITICAL', 'bucket policy public', 9),
        ('IAM Over-Permission', 'HIGH', 'Action wildcard', 11),
        ('Network Oversights', 'HIGH', 'SSH open', 23),
    ]
    
    for category, severity, keyword, expected in test_cases:
        cat_enc = le_category.transform([category])[0]
        sev_enc = le_severity.transform([severity])[0]
        kw_enc = le_keyword.transform([keyword])[0]
        
        test_input = pd.DataFrame([[cat_enc, sev_enc, kw_enc]], 
                                  columns=['category_enc', 'severity_enc', 'keyword_enc'])
        pred_enc = xgb_model.predict(test_input)
        pred_label = le_label.inverse_transform(pred_enc)[0]
        status = "✓" if pred_label == expected else "✗"
        print(f"  {status} '{keyword}' -> {pred_label}, Expected: {expected}")
    
    # Save models
    models_path = BASE_PATH / "models"
    joblib.dump(xgb_model, models_path / "xgboost_model.pkl")
    
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

if __name__ == "__main__":
    main()
