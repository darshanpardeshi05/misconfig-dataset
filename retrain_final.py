#!/usr/bin/env python3
"""
Final XGBoost Retraining - Force add all keywords
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
    ("Storage Exposure", "HIGH", "EFS public mount", 8),
    ("Storage Exposure", "HIGH", "port 2049", 8),
    ("Storage Exposure", "HIGH", "0.0.0.0/0", 8),
    ("Storage Exposure", "HIGH", "MountTarget", 8),
    ("Storage Exposure", "HIGH", "PublicSubnet", 8),
    # Misconfig #9
    ("Storage Exposure", "CRITICAL", "Principal: '*'", 9),
    ("Storage Exposure", "CRITICAL", "bucket policy public", 9),
    ("Storage Exposure", "CRITICAL", "Principal star", 9),
    # Misconfig #10
    ("Storage Exposure", "HIGH", "S3 object public", 10),
    ("Storage Exposure", "HIGH", "public-read object", 10),
    ("Storage Exposure", "HIGH", "object level exposure", 10),
    ("Storage Exposure", "HIGH", "PutObjectAcl", 10),
    # Misconfig #11
    ("IAM Over-Permission", "HIGH", "Action: '*'", 11),
    ("IAM Over-Permission", "HIGH", "Action wildcard", 11),
    # Misconfig #12
    ("IAM Over-Permission", "HIGH", "Resource: '*'", 12),
    ("IAM Over-Permission", "HIGH", "Resource wildcard", 12),
    # Misconfig #13
    ("IAM Over-Permission", "CRITICAL", "Action and Resource wildcard", 13),
    ("IAM Over-Permission", "CRITICAL", "full admin policy", 13),
    ("IAM Over-Permission", "CRITICAL", "both wildcard", 13),
    ("IAM Over-Permission", "CRITICAL", "administrator equivalent", 13),
    # Misconfig #14
    ("IAM Over-Permission", "CRITICAL", "AdministratorAccess", 14),
    ("IAM Over-Permission", "CRITICAL", "AdministratorAccess", 14),
    ("IAM Over-Permission", "CRITICAL", "AdministratorAccess", 14),
    ("IAM Over-Permission", "CRITICAL", "AdministratorAccess", 14),
    ("IAM Over-Permission", "CRITICAL", "AdministratorAccess", 14),
    ("IAM Over-Permission", "CRITICAL", "iam admin role", 14),
    ("IAM Over-Permission", "CRITICAL", "managed policy admin", 14),
    ("IAM Over-Permission", "CRITICAL", "full access role", 14),
    # Misconfig #15
    ("IAM Over-Permission", "HIGH", "s3:*", 15),
    ("IAM Over-Permission", "HIGH", "s3 full access", 15),
    # Misconfig #16
    ("IAM Over-Permission", "HIGH", "ec2:*", 16),
    ("IAM Over-Permission", "HIGH", "ec2 full access", 16),
    ("IAM Over-Permission", "HIGH", "ec2 full access user", 16),
    # Misconfig #18
    ("IAM Over-Permission", "HIGH", "User MFA missing", 18),
    ("IAM Over-Permission", "HIGH", "MFADevice", 18),
    ("IAM Over-Permission", "HIGH", "no mfa user", 18),
    # Misconfig #19
    ("IAM Over-Permission", "MEDIUM", "Inactive user", 19),
    ("IAM Over-Permission", "MEDIUM", "AccessKey Active", 19),
    ("IAM Over-Permission", "MEDIUM", "Orphaned account", 19),
    ("IAM Over-Permission", "MEDIUM", "Unused credentials", 19),
    # Misconfig #20
    ("IAM Over-Permission", "MEDIUM", "Old access key", 20),
    ("IAM Over-Permission", "MEDIUM", "AccessKey", 20),
    ("IAM Over-Permission", "MEDIUM", "Key rotation", 20),
    # Misconfig #21
    ("IAM Over-Permission", "CRITICAL", "Principal star trust", 21),
    ("IAM Over-Permission", "CRITICAL", "trust policy principal star", 21),
    ("IAM Over-Permission", "CRITICAL", "anyone can assume role", 21),
    # Network misconfigs
    ("Network Oversights", "HIGH", "SSH open", 23),
    ("Network Oversights", "HIGH", "RDP open", 24),
    ("Network Oversights", "CRITICAL", "MySQL open", 25),
    ("Network Oversights", "CRITICAL", "PostgreSQL open", 26),
    ("Network Oversights", "CRITICAL", "Redis open", 27),
    ("Network Oversights", "CRITICAL", "MongoDB open", 28),
    ("Network Oversights", "CRITICAL", "All ports open", 29),
    ("Network Oversights", "MEDIUM", "Flow logs disabled", 30),
    ("Network Oversights", "CRITICAL", "RDS public", 31),
    ("Network Oversights", "MEDIUM", "Default VPC", 32),
    # Encryption misconfigs
    ("Lack of Encryption", "MEDIUM", "Encryption disabled", 33),
    ("Lack of Encryption", "MEDIUM", "SSE not enforced", 34),
    ("Lack of Encryption", "HIGH", "EBS encryption", 35),
    ("Lack of Encryption", "HIGH", "RDS encryption", 36),
    ("Lack of Encryption", "MEDIUM", "DynamoDB encryption", 37),
    ("Lack of Encryption", "HIGH", "Lambda env not encrypted", 38),
    ("Lack of Encryption", "MEDIUM", "SQS encryption", 39),
    ("Lack of Encryption", "MEDIUM", "SNS encryption", 40),
    ("Lack of Encryption", "HIGH", "EFS encryption", 41),
    ("Lack of Encryption", "HIGH", "Redshift encryption", 42),
    # Insecure Defaults
    ("Insecure Defaults", "MEDIUM", "Auto-assign public IP", 43),
    ("Insecure Defaults", "HIGH", "Default security group", 44),
    ("Insecure Defaults", "LOW", "Credential report not enabled", 45),
    ("Insecure Defaults", "HIGH", "CloudTrail disabled", 46),
    ("Insecure Defaults", "HIGH", "Config recorder disabled", 47),
    ("Insecure Defaults", "HIGH", "GuardDuty disabled", 48),
    ("Insecure Defaults", "MEDIUM", "S3 logging disabled", 49),
    ("Insecure Defaults", "MEDIUM", "Password policy missing", 50),
]

def main():
    print("=" * 60)
    print("RETRAINING XGBOOST WITH ALL KEYWORDS")
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
    
    X = df[['category_enc', 'severity_enc', 'keyword_enc']]
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
        ("IAM Over-Permission", "HIGH", "ec2 full access", 16),
        ("IAM Over-Permission", "HIGH", "ec2:*", 16),
        ("Storage Exposure", "CRITICAL", "PublicRead", 1),
        ("Storage Exposure", "CRITICAL", "PublicReadWrite", 2),
    ]
    
    for category, severity, keyword, expected in test_cases:
        cat_enc = le_category.transform([category])[0]
        sev_enc = le_severity.transform([severity])[0]
        kw_enc = le_keyword.transform([keyword])[0]
        
        test_input = pd.DataFrame([[cat_enc, sev_enc, kw_enc]], 
                                  columns=['category_enc', 'severity_enc', 'keyword_enc'])
        pred_enc = xgb_model.predict(test_input)
        pred_label = int(le_label.inverse_transform(pred_enc)[0])
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
