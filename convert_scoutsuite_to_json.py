#!/usr/bin/env python3
"""
Convert ScoutSuite .js output file to pure JSON format.
Handles both single-line and multi-line JS files.
"""

import os
import json
import sys
import glob
import re

def find_js_file(base_dir):
    """Find the ScoutSuite .js file in the report directory."""
    pattern = f"{base_dir}/**/scoutsuite_results_*.js"
    js_files = glob.glob(pattern, recursive=True)
    
    if not js_files:
        pattern2 = f"{base_dir}/**/scoutsuite-results/scoutsuite_results_*.js"
        js_files = glob.glob(pattern2, recursive=True)
    
    if not js_files:
        print(f"Searching in: {base_dir}")
        all_js = glob.glob(f"{base_dir}/**/*.js", recursive=True)
        print(f"Found .js files: {all_js}")
        raise FileNotFoundError(f"No ScoutSuite results .js file found in {base_dir}")
    
    return js_files[0]

def convert_js_to_json(js_file_path, output_json_path):
    """Convert ScoutSuite JS to valid JSON."""
    with open(js_file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the first { character (start of JSON)
    start = content.find('{')
    if start == -1:
        raise ValueError("No JSON object found in ScoutSuite output")
    
    # Extract from first { to end
    json_content = content[start:]
    
    # Parse and re-serialize to ensure validity
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
    convert_js_to_json(js_file, output_json)

    print("ScoutSuite conversion complete.")
    print(f"Output saved to: {output_json}")

if __name__ == "__main__":
    main()
