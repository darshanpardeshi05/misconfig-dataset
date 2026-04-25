#!/usr/bin/env python3
"""
Pipeline for AWS Misconfiguration Detection
Loads all 3 models and makes predictions
"""

import joblib
import pandas as pd
import numpy as np
from pathlib import Path

class MisconfigDetectionPipeline:
    def __init__(self, models_path="models"):
        self.models_path = Path(models_path)
        
        print("=" * 60)
        print("LOADING MISCONFIGURATION DETECTION PIPELINE")
        print("=" * 60)
        
        # Load Random Forest model
        print("\n[1/6] Loading Random Forest model...")
        self.rf_model = joblib.load(self.models_path / "random_forest.pkl")
        print("  OK Random Forest loaded")
        
        # Load Isolation Forest model
        print("[2/6] Loading Isolation Forest model...")
        self.if_model = joblib.load(self.models_path / "isolation_forest.pkl")
        print("  OK Isolation Forest loaded")
        
        # Load XGBoost model
        print("[3/6] Loading XGBoost model...")
        self.xgb_model = joblib.load(self.models_path / "xgboost_model.pkl")
        print("  OK XGBoost loaded")
        
        # Load XGBoost label encoder
        print("[4/6] Loading XGBoost label encoder...")
        self.xgb_label_encoder = joblib.load(self.models_path / "xgboost_train_label_encoder.pkl")
        print("  OK XGBoost label encoder loaded")
        
        # Load XGBoost feature encoders
        print("[5/6] Loading XGBoost feature encoders...")
        self.xgb_feature_encoders = joblib.load(self.models_path / "xgboost_feature_encoders.pkl")
        print("  OK XGBoost feature encoders loaded")
        
        # Load vectorizer
        print("[6/6] Loading vectorizer...")
        self.vectorizer = joblib.load(self.models_path / "vectorizer.pkl")
        print("  OK Vectorizer loaded")
        
        # Get known classes for error handling
        self.known_categories = list(self.xgb_feature_encoders['category'].classes_)
        self.known_severities = list(self.xgb_feature_encoders['severity'].classes_)
        self.known_keywords = list(self.xgb_feature_encoders['keywords'].classes_)
        
        print("\n" + "=" * 60)
        print("PIPELINE READY FOR PREDICTIONS")
        print("=" * 60)
    
    def encode_safely(self, encoder, value, encoder_name):
        """Safely encode a value, return None if unknown"""
        try:
            return encoder.transform([value])[0]
        except ValueError:
            print(f"  Warning: Unknown {encoder_name}: '{value}'")
            return None
    
    def preprocess_for_xgboost(self, category, severity, keywords):
        """
        Preprocess raw input for XGBoost model
        """
        # Encode category
        category_encoded = self.encode_safely(
            self.xgb_feature_encoders['category'], category, "category"
        )
        if category_encoded is None:
            return None
        
        # Encode severity
        severity_encoded = self.encode_safely(
            self.xgb_feature_encoders['severity'], severity, "severity"
        )
        if severity_encoded is None:
            return None
        
        # Encode keywords
        keywords_encoded = self.encode_safely(
            self.xgb_feature_encoders['keywords'], keywords, "keywords"
        )
        if keywords_encoded is None:
            return None
        
        # Create dataframe
        input_df = pd.DataFrame({
            'category': [category_encoded],
            'severity': [severity_encoded],
            'keywords': [keywords_encoded]
        })
        
        return input_df
    
    def find_closest_keyword(self, input_keyword):
        """Find closest matching keyword from known keywords"""
        from difflib import get_close_matches
        
        matches = get_close_matches(input_keyword, self.known_keywords, n=1, cutoff=0.6)
        if matches:
            print(f"  Suggested: Use '{matches[0]}' instead")
            return matches[0]
        return None
    
    def predict(self, category, severity, keywords):
        """
        Main prediction method
        """
        print("\n" + "-" * 40)
        print("PREDICTION REQUEST")
        print("-" * 40)
        print(f"Input: category={category}, severity={severity}")
        print(f"Keywords: {keywords[:100]}...")
        
        # Check if inputs are known
        if category not in self.known_categories:
            print(f"\n  Warning: Unknown category '{category}'")
            print(f"  Known categories: {self.known_categories}")
            return {"error": f"Unknown category: {category}"}
        
        if severity not in self.known_severities:
            print(f"\n  Warning: Unknown severity '{severity}'")
            print(f"  Known severities: {self.known_severities}")
            return {"error": f"Unknown severity: {severity}"}
        
        if keywords not in self.known_keywords:
            print(f"\n  Warning: Unknown keyword pattern")
            print(f"  This keyword was not seen during training")
            
            # Suggest closest match
            closest = self.find_closest_keyword(keywords)
            if closest:
                print(f"\n  Suggestion: Use a keyword from the dataset")
                print(f"  Example: '{closest}'")
            
            return {"error": f"Unknown keyword pattern. Use exact keyword from training data."}
        
        # Preprocess for XGBoost
        encoded_input = self.preprocess_for_xgboost(category, severity, keywords)
        
        if encoded_input is None:
            return {"error": "Failed to encode input"}
        
        # XGBoost Prediction
        pred_encoded = self.xgb_model.predict(encoded_input)
        pred_original = self.xgb_label_encoder.inverse_transform(pred_encoded)
        xgb_pred = pred_original[0]
        
        print(f"\n[1] XGBoost Prediction: Misconfig ID = {xgb_pred}")
        
        return {
            "predicted_misconfig_id": int(xgb_pred),
            "input": {
                "category": category,
                "severity": severity,
                "keywords": keywords
            }
        }
    
    def list_known_keywords(self):
        """Print all known keywords from training"""
        print("\nKnown keywords from training data:")
        for i, kw in enumerate(self.known_keywords[:10]):
            print(f"  {i+1}. {kw}")
        if len(self.known_keywords) > 10:
            print(f"  ... and {len(self.known_keywords) - 10} more")


# CLI Support
if __name__ == "__main__":
    import sys
    
    pipeline = MisconfigDetectionPipeline()
    
    if len(sys.argv) == 4:
        category = sys.argv[1]
        severity = sys.argv[2]
        keywords = sys.argv[3]
        
        result = pipeline.predict(category, severity, keywords)
        
        print("\n" + "=" * 60)
        print("FINAL RESULT")
        print("=" * 60)
        
        if "error" in result:
            print(f"ERROR: {result['error']}")
            print("\nTo see known keywords, run:")
            print("  python3 pipeline.py --list-keywords")
        else:
            print(f"Predicted Misconfig ID: {result['predicted_misconfig_id']}")
    
    elif len(sys.argv) == 2 and sys.argv[1] == "--list-keywords":
        pipeline.list_known_keywords()
    
    else:
        print("\nUsage:")
        print("  python3 pipeline.py <category> <severity> <keywords>")
        print("  python3 pipeline.py --list-keywords")
        print("\nExample:")
        print("  python3 pipeline.py 'Storage Exposure' 'CRITICAL' 'PublicRead'")
