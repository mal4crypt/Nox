#!/usr/bin/env python3
"""
Custom Script: Analyze and categorize vulnerabilities from NOX scans

Usage:
    python3 scripts/analyze_vulnerabilities.py --input scan.json --threshold high
    python3 scripts/analyze_vulnerabilities.py --input scan.json --generate-report
"""

import json
import sys
import argparse
from pathlib import Path
from collections import defaultdict

def severity_to_score(severity):
    """Convert severity to numeric score"""
    scores = {
        "Critical": 5,
        "High": 4,
        "Medium": 3,
        "Low": 2,
        "Info": 1
    }
    return scores.get(severity, 0)

def analyze_vulnerabilities(input_file, threshold="all", generate_report=False):
    """Analyze vulnerability data from NOX scan"""
    
    # Load scan results
    with open(input_file) as f:
        data = json.load(f)
    
    vulns = data.get("vulnerabilities", [])
    open_ports = data.get("open_ports", [])
    
    print("╔════════════════════════════════════════════════════════╗")
    print("║       NOX VULNERABILITY ANALYSIS REPORT                ║")
    print("╚════════════════════════════════════════════════════════╝\n")
    
    print(f"Target: {data.get('target', 'Unknown')}")
    print(f"Scan Date: {data.get('timestamp', 'Unknown')}")
    print(f"Total Findings: {len(vulns)}")
    print(f"Open Ports: {len(open_ports)}\n")
    
    # Categorize by severity
    by_severity = defaultdict(list)
    for vuln in vulns:
        severity = vuln.get("severity", "Unknown")
        by_severity[severity].append(vuln)
    
    # Print by severity
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    
    total_risk_score = 0
    for severity in severity_order:
        if severity in by_severity:
            vulns_for_severity = by_severity[severity]
            count = len(vulns_for_severity)
            risk_score = count * severity_to_score(severity)
            total_risk_score += risk_score
            
            print(f"[{severity:8}] {count:2} findings (Risk: {risk_score})")
            
            if generate_report:
                for vuln in vulns_for_severity:
                    print(f"    • {vuln.get('cve', 'Unknown')}: {vuln.get('service', 'Unknown')}")
    
    print(f"\n[TOTAL RISK SCORE: {total_risk_score}]\n")
    
    # Risk assessment
    if total_risk_score >= 20:
        print("⚠️  CRITICAL RISK - Immediate action required")
    elif total_risk_score >= 10:
        print("🔴 HIGH RISK - Address within 1 week")
    elif total_risk_score >= 5:
        print("🟠 MEDIUM RISK - Address within 1 month")
    else:
        print("🟡 LOW RISK - Monitor and address in maintenance window")
    
    print(f"\n✅ Analysis complete - {len(vulns)} vulnerabilities analyzed")
    
    # Save analysis report if requested
    if generate_report:
        report_file = input_file.replace(".json", "_analysis.json")
        report_data = {
            "target": data.get("target"),
            "timestamp": data.get("timestamp"),
            "total_vulnerabilities": len(vulns),
            "by_severity": {
                severity: len(vulns_list)
                for severity, vulns_list in by_severity.items()
            },
            "total_risk_score": total_risk_score,
            "vulnerabilities": vulns
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"Report saved: {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze NOX vulnerability scan results")
    parser.add_argument("--input", required=True, help="Input JSON file from NOX scan")
    parser.add_argument("--threshold", default="all", choices=["critical", "high", "all"], help="Filter by severity")
    parser.add_argument("--generate-report", action="store_true", help="Generate detailed report")
    
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"❌ Error: File not found: {args.input}")
        sys.exit(1)
    
    analyze_vulnerabilities(args.input, args.threshold, args.generate_report)
