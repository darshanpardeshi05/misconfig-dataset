#!/usr/bin/env python3
"""
Convert ScoutSuite .js output file to pure JSON format.
"""

import json
import os
import sys
import glob
from pathlib import Path

def find_js_file(base_dir):
    """Find the ScoutSuite results .js file."""
    # Look for the specific results file
    results_file = os.path.join(base_dir, "scoutsuite-results", "scoutsuite_results_aws-719279823313.js")
    
    if os.path.exists(results_file):
        return results_file
    
    # Fallback: search for any scoutsuite_results_aws file
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.startswith("scoutsuite_results_aws") and file.endswith(".js"):
                return os.path.join(root, file)
    
    return None

def convert_js_to_json(js_file_path, output_json_path):
    """Convert ScoutSuite JS to valid JSON."""
    with open(js_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the first { character
    start = content.find('{')
    if start == -1:
        raise ValueError("No JSON object found in ScoutSuite output")
    
    json_content = content[start:]
    data = json.loads(json_content)
    
    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    print(f"Converted {js_file_path} -> {output_json_path}")
    return output_json_path

def main():
    base_dir = "/home/darshan/misconfig-dataset/scan-results/scoutsuite"
    output_json = "/home/darshan/misconfig-dataset/scan-results/scoutsuite_converted.json"

    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
    if len(sys.argv) > 2:
        output_json = sys.argv[2]

    js_file = find_js_file(base_dir)
    if js_file:
        convert_js_to_json(js_file, output_json)
        print("ScoutSuite conversion complete.")
        print(f"Output saved to: {output_json}")
    else:
        print("ERROR: No ScoutSuite results JS file found")

if __name__ == "__main__":
    main()
