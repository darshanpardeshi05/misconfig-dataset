#!/usr/bin/env python3
"""
Complete Pipeline for AWS Misconfiguration Detection
Includes: Keyword Matching + Random Forest + XGBoost + Isolation Forest
Phase 3 only - Run Phase 4 manually after this
"""

import joblib
import pandas as pd
import numpy as np
import json
import sys
import re
from pathlib import Path
from difflib import get_close_matches

class MisconfigDetectionPipeline:
    def __init__(self, models_path="models"):
        self.models_path = Path(models_path)
        
        print("=" * 60)
        print("LOADING MISCONFIGURATION DETECTION PIPELINE (PHASE 3)")
        print("=" * 60)
        
        print("\n[1/8] Loading keyword mapping...")
        with open(self.models_path / "keywords.json", 'r') as f:
            self.keyword_mapping = json.load(f)
        self.create_inverted_keyword_index()
        print(f"  OK Loaded {len(self.keyword_mapping)} misconfigurations")
        
        print("[2/8] Loading Random Forest model...")
        self.rf_model = joblib.load(self.models_path / "random_forest.pkl")
        print("  OK Random Forest loaded")
        
        print("[3/8] Loading Isolation Forest model...")
        self.if_model = joblib.load(self.models_path / "isolation_forest.pkl")
        print("  OK Isolation Forest loaded")
        
        print("[4/8] Loading XGBoost model...")
        self.xgb_model = joblib.load(self.models_path / "xgboost_model.pkl")
        print("  OK XGBoost loaded")
        
        print("[5/8] Loading XGBoost label encoder...")
        self.xgb_label_encoder = joblib.load(self.models_path / "xgboost_train_label_encoder.pkl")
        print("  OK XGBoost label encoder loaded")
        
        print("[6/8] Loading XGBoost feature encoders...")
        self.xgb_feature_encoders = joblib.load(self.models_path / "xgboost_feature_encoders.pkl")
        print("  OK XGBoost feature encoders loaded")
        
        print("[7/8] Loading vectorizer...")
        self.vectorizer = joblib.load(self.models_path / "vectorizer.pkl")
        print("  OK Vectorizer loaded")
        
        print("[8/8] Loading fix policies...")
        with open(self.models_path / "fix_policies.json", 'r') as f:
            self.fix_policies = json.load(f)
        print(f"  OK Loaded {len(self.fix_policies)} fix policies")
        
        print("\n" + "=" * 60)
        print("PIPELINE READY FOR PREDICTIONS")
        print("=" * 60)
    
    def create_inverted_keyword_index(self):
        self.keyword_to_file = {}
        for filename, data in self.keyword_mapping.items():
            for keyword in data.get('keywords', []):
                keyword_lower = keyword.lower()
                if keyword_lower not in self.keyword_to_file:
                    self.keyword_to_file[keyword_lower] = []
                self.keyword_to_file[keyword_lower].append(filename)
        
        self.file_to_index = {}
        for idx, filename in enumerate(self.keyword_mapping.keys(), start=1):
            self.file_to_index[filename] = idx
    
    def keyword_match(self, input_keywords):
        if isinstance(input_keywords, str):
            input_keywords = [input_keywords]
        
        input_keywords_lower = [kw.lower() for kw in input_keywords]
        matches = {}
        
        for input_kw in input_keywords_lower:
            for known_kw, files in self.keyword_to_file.items():
                if input_kw in known_kw or known_kw in input_kw:
                    for file in files:
                        matches[file] = matches.get(file, 0) + 1
        
        if not matches:
            return None, 0
        
        best_match = max(matches, key=matches.get)
        confidence = matches[best_match] / len(input_keywords_lower)
        
        return best_match, confidence
    
    def preprocess_for_xgboost(self, category, severity, keywords):
        input_df = pd.DataFrame({
            'category': [category],
            'severity': [severity],
            'keywords': [keywords]
        })
        
        try:
            input_df['category'] = self.xgb_feature_encoders['category'].transform(input_df['category'])
            input_df['severity'] = self.xgb_feature_encoders['severity'].transform(input_df['severity'])
            input_df['keywords'] = self.xgb_feature_encoders['keywords'].transform(input_df['keywords'])
        except ValueError as e:
            print(f"  Warning: Cannot encode input. Error: {e}")
            return None
        
        return input_df
    
    def predict_xgboost(self, encoded_input):
        if encoded_input is None:
            return None
        
        pred_encoded = self.xgb_model.predict(encoded_input)
        pred_original = self.xgb_label_encoder.inverse_transform(pred_encoded)
        return int(pred_original[0])
    
    def predict(self, category, severity, keywords):
        print("\n" + "-" * 40)
        print("PREDICTION REQUEST")
        print("-" * 40)
        print(f"Input: category={category}, severity={severity}")
        print(f"Keywords: {keywords[:100]}...")
        
        result = {
            "input": {"category": category, "severity": severity, "keywords": keywords},
            "final_verdict": None
        }
        
        print("\n[1/4] Keyword Matching...")
        matched_file, confidence = self.keyword_match([keywords] + keywords.split())
        if matched_file:
            matched_id = self.file_to_index.get(matched_file)
            print(f"  Matched: {matched_file} (ID: {matched_id}, Confidence: {confidence:.2f})")
            final_id = matched_id
        else:
            print("  No keyword match found")
            final_id = None
        
        print("\n[2/4] Preprocessing for ML models...")
        encoded_input = self.preprocess_for_xgboost(category, severity, keywords)
        
        print("\n[3/4] Running ML predictions...")
        xgb_pred = self.predict_xgboost(encoded_input)
        if xgb_pred:
            print(f"  XGBoost Prediction: Misconfig ID = {xgb_pred}")
            final_id = xgb_pred
        
        print("\n" + "-" * 40)
        print("FINAL VERDICT")
        print("-" * 40)
        
        if final_id:
            result["final_verdict"] = final_id
            print(f"Predicted Misconfig ID: {final_id}")
        else:
            print("ERROR: Could not identify misconfiguration")
            return result
        
        # Get fix policy
        fix_policy = self.fix_policies.get(str(final_id))
        if fix_policy:
            print(f"\nFix Policy:")
            print(f"  Remediation: {fix_policy.get('remediation', 'N/A')[:100]}...")
            print(f"  Service: {fix_policy.get('aws_service', 'N/A')}")
        
        return result


if __name__ == "__main__":
    pipeline = MisconfigDetectionPipeline()
    
    if len(sys.argv) == 4:
        category = sys.argv[1]
        severity = sys.argv[2]
        keywords = sys.argv[3]
        
        result = pipeline.predict(category, severity, keywords)
        
        print("\n" + "=" * 60)
        print("PHASE 3 COMPLETE")
        print("=" * 60)
        print(f"Final Verdict: Misconfig ID {result['final_verdict']}")
        print("\n" + "=" * 60)
        print("NEXT STEP: Run Phase 4 manually:")
        print(f"  python3 phase4_complete.py --id {result['final_verdict']} \"{category}\" \"{severity}\" \"{keywords}\"")
        print("=" * 60)
        
    else:
        print("\nUsage:")
        print("  python3 pipeline.py <category> <severity> <keywords>")
        print("\nExample:")
        print("  python3 pipeline.py 'Storage Exposure' 'CRITICAL' 'PublicRead'")
