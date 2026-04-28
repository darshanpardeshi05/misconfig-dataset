#!/usr/bin/env python3
"""
Complete Pipeline for AWS Misconfiguration Detection
Phase 3 only - Prioritizes Keyword Match over XGBoost
"""

import joblib
import pandas as pd
import json
import sys
import re
from pathlib import Path

class MisconfigDetectionPipeline:
    def __init__(self, models_path="models"):
        self.models_path = Path(models_path)
        
        print("=" * 60)
        print("LOADING MISCONFIGURATION DETECTION PIPELINE (PHASE 3)")
        print("=" * 60)
        
        print("\n[1/6] Loading keyword mapping...")
        with open(self.models_path / "keywords.json", 'r') as f:
            self.keyword_mapping = json.load(f)
        self.create_inverted_keyword_index()
        print(f"  OK Loaded {len(self.keyword_mapping)} misconfigurations")
        
        print("[2/6] Loading XGBoost model...")
        self.xgb_model = joblib.load(self.models_path / "xgboost_model.pkl")
        print("  OK XGBoost loaded")
        
        print("[3/6] Loading XGBoost label encoder...")
        self.xgb_label_encoder = joblib.load(self.models_path / "xgboost_train_label_encoder.pkl")
        print("  OK XGBoost label encoder loaded")
        
        print("[4/6] Loading XGBoost feature encoders...")
        self.xgb_feature_encoders = joblib.load(self.models_path / "xgboost_feature_encoders.pkl")
        print("  OK XGBoost feature encoders loaded")
        
        print("[5/6] Loading fix policies...")
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
    
    def predict_xgboost(self, category, severity, keywords):
        try:
            cat_enc = self.xgb_feature_encoders['category'].transform([category])[0]
            sev_enc = self.xgb_feature_encoders['severity'].transform([severity])[0]
            kw_enc = self.xgb_feature_encoders['keywords'].transform([keywords])[0]
            
            input_df = pd.DataFrame([[cat_enc, sev_enc, kw_enc]], 
                                   columns=['category_enc', 'severity_enc', 'keyword_enc'])
            
            pred_encoded = self.xgb_model.predict(input_df)
            pred_original = self.xgb_label_encoder.inverse_transform(pred_encoded)
            result = pred_original[0]
            if isinstance(result, str):
                numbers = re.findall(r'\d+', result)
                if numbers:
                    return int(numbers[0])
            return int(result)
        except Exception as e:
            print(f"  XGBoost prediction failed: {e}")
            return None
    
    def predict(self, category, severity, keywords):
        print("\n" + "-" * 40)
        print("PREDICTION REQUEST")
        print("-" * 40)
        print(f"Input: category={category}, severity={severity}")
        print(f"Keywords: {keywords[:100]}...")
        
        keyword_id = None
        keyword_confidence = 0
        xgboost_id = None
        
        print("\n[1/3] Keyword Matching...")
        matched_file, confidence = self.keyword_match([keywords] + keywords.split())
        if matched_file:
            keyword_id = self.file_to_index.get(matched_file)
            keyword_confidence = confidence
            print(f"  Matched: {matched_file} (ID: {keyword_id}, Confidence: {confidence:.2f})")
        else:
            print("  No keyword match found")
        
        print("\n[2/3] Running XGBoost prediction...")
        xgboost_id = self.predict_xgboost(category, severity, keywords)
        if xgboost_id:
            print(f"  XGBoost Prediction: Misconfig ID = {xgboost_id}")
        
        print("\n" + "-" * 40)
        print("FINAL VERDICT")
        print("-" * 40)
        
        # Prioritize keyword match when confidence is high (>= 0.5)
        final_id = None
        if keyword_id and keyword_confidence >= 0.5:
            final_id = keyword_id
            print(f"  Using Keyword Match result (Confidence: {keyword_confidence:.2f})")
        elif xgboost_id:
            final_id = xgboost_id
            print(f"  Using XGBoost result (Keyword match confidence too low)")
        elif keyword_id:
            final_id = keyword_id
            print(f"  Using Keyword Match result (low confidence fallback)")
        
        if final_id:
            print(f"\nPredicted Misconfig ID: {final_id}")
            fix_policy = self.fix_policies.get(str(final_id))
            if fix_policy:
                print(f"\nFix Policy:")
                print(f"  Remediation: {fix_policy.get('remediation', 'N/A')[:100]}...")
                print(f"  Service: {fix_policy.get('aws_service', 'N/A')}")
            return final_id
        else:
            print("ERROR: Could not identify misconfiguration")
            return None


if __name__ == "__main__":
    pipeline = MisconfigDetectionPipeline()
    
    if len(sys.argv) == 4:
        category = sys.argv[1]
        severity = sys.argv[2]
        keywords = sys.argv[3]
        
        result_id = pipeline.predict(category, severity, keywords)
        
        print("\n" + "=" * 60)
        print("PHASE 3 COMPLETE")
        print("=" * 60)
        print(f"Final Verdict: Misconfig ID {result_id}")
        print("\n" + "=" * 60)
        print("NEXT STEP: Run Phase 4 manually:")
        print(f"  python3 phase4_complete.py --id {result_id} \"{category}\" \"{severity}\" \"{keywords}\"")
        print("=" * 60)
        
    else:
        print("\nUsage:")
        print("  python3 pipeline.py <category> <severity> <keywords>")
        print("\nExample:")
        print("  python3 pipeline.py 'Storage Exposure' 'CRITICAL' 'PublicRead'")
