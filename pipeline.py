#!/usr/bin/env python3
"""
Complete Pipeline for AWS Misconfiguration Detection
Includes: Keyword Matching + Random Forest + XGBoost + Isolation Forest
Now triggers Phase 4 auto-fix automatically
"""

import joblib
import pandas as pd
import numpy as np
import json
import subprocess
from pathlib import Path
from difflib import get_close_matches

class MisconfigDetectionPipeline:
    def __init__(self, models_path="models"):
        self.models_path = Path(models_path)
        
        print("=" * 60)
        print("LOADING MISCONFIGURATION DETECTION PIPELINE")
        print("=" * 60)
        
        # Load Keyword Mapping
        print("\n[1/8] Loading keyword mapping...")
        with open(self.models_path / "keywords.json", 'r') as f:
            self.keyword_mapping = json.load(f)
        self.create_inverted_keyword_index()
        print(f"  OK Loaded {len(self.keyword_mapping)} misconfigurations")
        
        # Load Random Forest model
        print("[2/8] Loading Random Forest model...")
        self.rf_model = joblib.load(self.models_path / "random_forest.pkl")
        print("  OK Random Forest loaded")
        
        # Load Isolation Forest model
        print("[3/8] Loading Isolation Forest model...")
        self.if_model = joblib.load(self.models_path / "isolation_forest.pkl")
        print("  OK Isolation Forest loaded")
        
        # Load XGBoost model
        print("[4/8] Loading XGBoost model...")
        self.xgb_model = joblib.load(self.models_path / "xgboost_model.pkl")
        print("  OK XGBoost loaded")
        
        # Load XGBoost label encoder
        print("[5/8] Loading XGBoost label encoder...")
        self.xgb_label_encoder = joblib.load(self.models_path / "xgboost_train_label_encoder.pkl")
        print("  OK XGBoost label encoder loaded")
        
        # Load XGBoost feature encoders
        print("[6/8] Loading XGBoost feature encoders...")
        self.xgb_feature_encoders = joblib.load(self.models_path / "xgboost_feature_encoders.pkl")
        print("  OK XGBoost feature encoders loaded")
        
        # Load vectorizer
        print("[7/8] Loading vectorizer...")
        self.vectorizer = joblib.load(self.models_path / "vectorizer.pkl")
        print("  OK Vectorizer loaded")
        
        # Load fix policies
        print("[8/8] Loading fix policies...")
        with open(self.models_path / "fix_policies.json", 'r') as f:
            self.fix_policies = json.load(f)
        print(f"  OK Loaded {len(self.fix_policies)} fix policies")
        
        print("\n" + "=" * 60)
        print("PIPELINE READY FOR PREDICTIONS")
        print("=" * 60)
    
    def create_inverted_keyword_index(self):
        """Create mapping from keyword to misconfig filename"""
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
        """Match input keywords against known keywords"""
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
        """Preprocess raw input for XGBoost model"""
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
    
    def predict_random_forest(self, keywords):
        """Predict using Random Forest model"""
        try:
            keywords_vectorized = self.vectorizer.transform([keywords])
            return None
        except Exception as e:
            print(f"  Warning: Random Forest prediction failed: {e}")
            return None
    
    def predict_isolation_forest(self, encoded_input):
        """Detect anomaly using Isolation Forest"""
        if encoded_input is None:
            return None
        
        try:
            anomaly_pred = self.if_model.predict(encoded_input)
            return int(anomaly_pred[0] == -1)
        except Exception as e:
            print(f"  Warning: Isolation Forest prediction failed: {e}")
            return None
    
    def predict_xgboost(self, encoded_input):
        """Predict using XGBoost model"""
        if encoded_input is None:
            return None
        
        pred_encoded = self.xgb_model.predict(encoded_input)
        pred_original = self.xgb_label_encoder.inverse_transform(pred_encoded)
        return int(pred_original[0])
    
    def get_fix_policy(self, misconfig_id):
        """Get fix policy from fix_policies.json"""
        misconfig_id_str = str(misconfig_id)
        if misconfig_id_str in self.fix_policies:
            return self.fix_policies[misconfig_id_str]
        return None
    
    def trigger_phase4(self, category, severity, keywords, predicted_id):
        """Trigger Phase 4 auto-fix after prediction"""
        print("\n" + "=" * 60)
        print("TRIGGERING PHASE 4: AUTO-FIX")
        print("=" * 60)
        print(f"Predicted Misconfig ID: {predicted_id}")
        
        try:
            result = subprocess.run(
                ['python3', 'phase4_complete.py', '--id', str(predicted_id), category, severity, keywords],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                print("✓ Phase 4 auto-fix completed successfully")
            else:
                print(f"✗ Phase 4 auto-fix failed: {result.stderr}")
                
        except Exception as e:
            print(f"Error triggering Phase 4: {e}")
    
    def predict(self, category, severity, keywords):
        """Main prediction method - Complete pipeline"""
        print("\n" + "-" * 40)
        print("PREDICTION REQUEST")
        print("-" * 40)
        print(f"Input: category={category}, severity={severity}")
        print(f"Keywords: {keywords[:100]}...")
        
        result = {
            "input": {
                "category": category,
                "severity": severity,
                "keywords": keywords
            },
            "keyword_match": {
                "matched_file": None,
                "matched_id": None,
                "confidence": 0
            },
            "xgboost": {
                "predicted_id": None
            },
            "random_forest": {
                "predicted_id": None
            },
            "isolation_forest": {
                "anomaly_flag": None
            },
            "fix_policy": None,
            "final_verdict": None
        }
        
        # Step 1: Keyword Matching
        print("\n[1/4] Keyword Matching...")
        matched_file, confidence = self.keyword_match([keywords] + keywords.split())
        if matched_file:
            matched_id = self.file_to_index.get(matched_file)
            result["keyword_match"]["matched_file"] = matched_file
            result["keyword_match"]["matched_id"] = matched_id
            result["keyword_match"]["confidence"] = round(confidence, 2)
            print(f"  Matched: {matched_file} (ID: {matched_id}, Confidence: {confidence:.2f})")
        else:
            print("  No keyword match found")
        
        # Step 2: Preprocess for ML models
        print("\n[2/4] Preprocessing for ML models...")
        encoded_input = self.preprocess_for_xgboost(category, severity, keywords)
        
        # Step 3: XGBoost Prediction
        print("\n[3/4] Running ML predictions...")
        xgb_pred = self.predict_xgboost(encoded_input)
        if xgb_pred:
            result["xgboost"]["predicted_id"] = xgb_pred
            print(f"  XGBoost Prediction: Misconfig ID = {xgb_pred}")
        
        # Step 4: Random Forest Prediction
        rf_pred = self.predict_random_forest(keywords)
        if rf_pred:
            result["random_forest"]["predicted_id"] = rf_pred
            print(f"  Random Forest Prediction: Misconfig ID = {rf_pred}")
        
        # Step 5: Isolation Forest Anomaly Detection
        if_pred = self.predict_isolation_forest(encoded_input)
        if if_pred is not None:
            result["isolation_forest"]["anomaly_flag"] = if_pred
            anomaly_status = "ANOMALY DETECTED" if if_pred == 1 else "Normal"
            print(f"  Isolation Forest: {anomaly_status}")
        
        # Step 6: Determine Final Verdict
        print("\n" + "-" * 40)
        print("FINAL VERDICT")
        print("-" * 40)
        
        final_id = None
        if xgb_pred:
            final_id = xgb_pred
            result["final_verdict"] = final_id
            print(f"Predicted Misconfig ID: {final_id}")
        elif matched_id:
            final_id = matched_id
            result["final_verdict"] = final_id
            print(f"Predicted Misconfig ID (from keyword match): {final_id}")
        else:
            print("ERROR: Could not identify misconfiguration")
            return result
        
        # Step 7: Get Fix Policy
        fix_policy = self.get_fix_policy(final_id)
        if fix_policy:
            result["fix_policy"] = fix_policy
            print(f"\nFix Policy:")
            print(f"  Remediation: {fix_policy.get('remediation', 'N/A')[:100]}...")
            print(f"  Fix Command: {fix_policy.get('fix_command', 'N/A')[:100]}...")
        
        return result


if __name__ == "__main__":
    import sys
    
    pipeline = MisconfigDetectionPipeline()
    
    if len(sys.argv) == 4:
        category = sys.argv[1]
        severity = sys.argv[2]
        keywords = sys.argv[3]
        
        result = pipeline.predict(category, severity, keywords)
        
        print("\n" + "=" * 60)
        print("COMPLETE RESULT")
        print("=" * 60)
        print(f"Final Verdict: Misconfig ID {result['final_verdict']}")
        
        if result['fix_policy']:
            print(f"\nRemediation: {result['fix_policy'].get('remediation', 'N/A')}")
        
        # Trigger Phase 4 auto-fix
        if result['final_verdict']:
            pipeline.trigger_phase4(category, severity, keywords, result['final_verdict'])
        
    else:
        print("\nUsage:")
        print("  python3 pipeline.py <category> <severity> <keywords>")
        print("\nExample:")
        print("  python3 pipeline.py 'Storage Exposure' 'CRITICAL' 'PublicRead'")

