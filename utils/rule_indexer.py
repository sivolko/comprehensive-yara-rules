#!/usr/bin/env python3
# Rule Indexer for YARA Rules Repository
# Author: Shubhendu Shubham
# Date: 2025-05-21

import os
import re
import json
import argparse
from datetime import datetime

def parse_yara_rule(file_path):
    """Parse YARA rule file to extract metadata."""
    rule_data = {
        "file": os.path.basename(file_path),
        "path": file_path,
        "rules": []
    }
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Find all rule definitions
    rule_matches = re.finditer(r'rule\s+(\w+)\s*{', content)
    for match in rule_matches:
        rule_name = match.group(1)
        
        # Extract metadata section for this rule
        meta_match = re.search(rf'{rule_name}\s*{{.*?meta:(.*?)strings:', content, re.DOTALL)
        if not meta_match:
            continue
            
        meta_content = meta_match.group(1)
        
        # Extract key metadata values
        meta = {}
        for key in ['description', 'author', 'date', 'reference', 'severity']:
            meta_match = re.search(rf'{key}\s*=\s*"([^"]*)"', meta_content)
            if meta_match:
                meta[key] = meta_match.group(1)
        
        rule_data["rules"].append({
            "name": rule_name,
            "metadata": meta
        })
    
    return rule_data

def build_index(repo_dir):
    """Build an index of all YARA rules in the repository."""
    index = {
        "indexed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "categories": {}
    }
    
    # Directories matching the repository structure
    categories = [
        "malware", "ransomware", "backdoors", "trojans", "information_stealers",
        "exploits", "apt", "packers", "cryptominers", "webshells", "maldocs",
        "antidebug_antivm"
    ]
    
    for category in categories:
        category_path = os.path.join(repo_dir, category)
        if not os.path.exists(category_path):
            continue
            
        index["categories"][category] = []
        
        for file in os.listdir(category_path):
            if file.endswith('.yar') or file.endswith('.yara'):
                file_path = os.path.join(category_path, file)
                rule_data = parse_yara_rule(file_path)
                if rule_data["rules"]:
                    index["categories"][category].append(rule_data)
    
    return index

def main():
    parser = argparse.ArgumentParser(description='YARA Rule Repository Indexer')
    parser.add_argument('--repo-dir', default='.', help='Repository root directory')
    parser.add_argument('--output', default='rule_index.json', help='Output index file path')
    args = parser.parse_args()
    
    print(f"Building YARA rule index for: {args.repo_dir}")
    index = build_index(args.repo_dir)
    
    with open(args.output, 'w') as f:
        json.dump(index, f, indent=2)
    
    # Print summary
    total_rules = 0
    for category, rules in index["categories"].items():
        category_count = sum(len(r["rules"]) for r in rules)
        total_rules += category_count
        print(f"Category {category}: {category_count} rules")
    
    print(f"Total rules indexed: {total_rules}")
    print(f"Index saved to: {args.output}")

if __name__ == "__main__":
    main()