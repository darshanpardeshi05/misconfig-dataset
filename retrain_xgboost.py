#!/usr/bin/env python3
"""
Retrain XGBoost with ALL keywords from ALL 50 CloudFormation templates
This fixes the "unseen labels" error
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

def extract_keywords_and_label(yaml_file):
    """Extract keywords and label from CloudFormation template"""
    with open(yaml_file, 'r') as f:
        content = f.read()
    
    # Extract RuleId (this is our label/target)
    match = re.search(r'RuleId:\s*"([^"]+)"', content)
    if not match:
        return None, None
    
    label = match.group(1)
    
    # Extract Category
    category_match = re.search(r'Category:\s*"([^"]+)"', content)
    category = category_match.group(1) if category_match else "Unknown"
    
    # Extract Severity
    severity_match = re.search(r'Severity:\s*"([^"]+)"', content)
    severity = severity_match.group(1) if severity_match else "MEDIUM"
    
    # Extract Keywords
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
    print("RETRAINING XGBOOST WITH ALL KEYWORDS FROM 50 MISCONFIGS")
    print("=" * 60)
    
    all_data = []
    
    # Scan all category folders
    category_folders = ["1-storage-exposure", "2-iam-over-permission", "3-network-oversights", "4-lack-of-encryption", "5-insecure-defaults"]
    
    for category_folder in category_folders:
        folder_path = BASE_PATH / category_folder
        if not folder_path.exists():
            print(f"Warning: {category_folder} not found")
            continue
        
        yaml_files = list(folder_path.glob("*.yaml"))
        print(f"Found {len(yaml_files)} files in {category_folder}")
        
        for yaml_file in yaml_files:
            data = extract_keywords_and_label(yaml_file)
            if data and data['keywords']:
                # Create one row per keyword
                for keyword in data['keywords']:
                    all_data.append({
                        'category': data['category'],
                        'severity': data['severity'],
                        'keyword': keyword,
                        'rule_id': data['rule_id']
                    })
    
    print(f"\nTotal training samples (keyword instances): {len(all_data)}")
    
    if len(all_data) == 0:
        print("ERROR: No training data found!")
        return
    
    df = pd.DataFrame(all_data)
    
    # Encode categorical variables
    le_category = LabelEncoder()
    le_severity = LabelEncoder()
    le_keyword = LabelEncoder()
    le_label = LabelEncoder()
    
    df['category_encoded'] = le_category.fit_transform(df['category'])
    df['severity_encoded'] = le_severity.fit_transform(df['severity'])
    df['keyword_encoded'] = le_keyword.fit_transform(df['keyword'])
    df['label_encoded'] = le_label.fit_transform(df['rule_id'])
    
    print(f"Unique categories: {len(le_category.classes_)}")
    print(f"Unique severities: {len(le_severity.classes_)}")
    print(f"Unique keywords: {len(le_keyword.classes_)}")
    print(f"Unique labels (Rule IDs): {len(le_label.classes_)}")
    
    # Prepare features
    X = df[['category_encoded', 'severity_encoded', 'keyword_encoded']]
    y = df['label_encoded']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train XGBoost
    print("\nTraining XGBoost model...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        eval_metric='mlogloss',
        use_label_encoder=False
    )
    
    xgb_model.fit(X_train, y_train)
    
    # Save model and encoders
    models_path = BASE_PATH / "models"
    models_path.mkdir(exist_ok=True)
    
    joblib.dump(xgb_model, models_path / "xgboost_model.pkl")
    joblib.dump(le_category, models_path / "xgboost_category_encoder.pkl")
    joblib.dump(le_severity, models_path / "xgboost_severity_encoder.pkl")
    joblib.dump(le_keyword, models_path / "xgboost_keyword_encoder.pkl")
    joblib.dump(le_label, models_path / "xgboost_label_encoder.pkl")
    
    # Update feature encoders (used by pipeline.py)
    feature_encoders = {
        'category': le_category,
        'severity': le_severity,
        'keywords': le_keyword
    }
    joblib.dump(feature_encoders, models_path / "xgboost_feature_encoders.pkl")
    
    # Also save as train_label_encoder (used by pipeline.py)
    joblib.dump(le_label, models_path / "xgboost_train_label_encoder.pkl")
    
    print("\n" + "=" * 60)
    print("RETRAINING COMPLETE")
    print(f"  Model: {models_path / 'xgboost_model.pkl'}")
    print(f"  Feature encoders: {models_path / 'xgboost_feature_encoders.pkl'}")
    print("=" * 60)

if __name__ == "__main__":
    main()
