#!/usr/bin/env python3
"""
Custom Script: Aggregate findings from multiple NOX scans

Usage:
    python3 scripts/aggregate_findings.py --pattern "scan_*.json" --output results.json
    python3 scripts/aggregate_findings.py --dir ./results --output aggregated.json
"""

import json
import sys
import argparse
import glob
from pathlib import Path
from collections import defaultdict

def aggregate_findings(pattern=None, directory=None, output_file="aggregated_findings.json"):
    """Aggregate findings from multiple scan files"""
    
    # Get list of files to aggregate
    if pattern:
        files = glob.glob(pattern)
    elif directory:
        files = glob.glob(f"{directory}/**/*.json", recursive=True)
    else:
        print("❌ Error: Provide --pattern or --dir")
        return False
    
    if not files:
        print("❌ No files found to aggregate")
        return False
    
    print("╔════════════════════════════════════════════════════════╗")
    print("║         FINDINGS AGGREGATION REPORT                    ║")
    print("╚════════════════════════════════════════════════════════╝\n")
    
    print(f"[*] Found {len(files)} scan files to aggregate\n")
    
    # Aggregate data
    all_vulnerabilities = []
    all_ports = set()
    targets = set()
    scan_metadata = []
    
    for scan_file in files:
        try:
            with open(scan_file) as f:
                data = json.load(f)
            
            print(f"[+] Processing: {scan_file}")
            
            # Collect data
            target = data.get("target", "Unknown")
            targets.add(target)
            
            vulns = data.get("vulnerabilities", [])
            all_vulnerabilities.extend(vulns)
            
            ports = data.get("open_ports", [])
            all_ports.update(ports)
            
            scan_metadata.append({
                "file": scan_file,
                "target": target,
                "vulnerabilities": len(vulns),
                "open_ports": len(ports),
                "timestamp": data.get("timestamp")
            })
        
        except Exception as e:
            print(f"[-] Error processing {scan_file}: {e}")
    
    # Categorize vulnerabilities
    by_severity = defaultdict(list)
    by_service = defaultdict(list)
    
    for vuln in all_vulnerabilities:
        severity = vuln.get("severity", "Unknown")
        service = vuln.get("service", "Unknown")
        
        by_severity[severity].append(vuln)
        by_service[service].append(vuln)
    
    # Create aggregated report
    aggregated = {
        "timestamp": __import__('datetime').datetime.now().isoformat(),
        "summary": {
            "total_targets": len(targets),
            "total_vulnerabilities": len(all_vulnerabilities),
            "total_unique_ports": len(all_ports),
            "scan_files_processed": len(files)
        },
        "targets": list(targets),
        "vulnerabilities_by_severity": {
            severity: len(vulns)
            for severity, vulns in by_severity.items()
        },
        "vulnerabilities_by_service": {
            service: len(vulns)
            for service, vulns in by_service.items()
        },
        "open_ports": sorted(list(all_ports)),
        "scan_metadata": scan_metadata,
        "vulnerabilities": all_vulnerabilities
    }
    
    # Print summary
    print(f"\n[+] Aggregation Complete\n")
    print(f"Total Targets: {len(targets)}")
    print(f"Total Vulnerabilities: {len(all_vulnerabilities)}")
    print(f"Unique Open Ports: {len(all_ports)}\n")
    
    print("Vulnerabilities by Severity:")
    for severity in ["Critical", "High", "Medium", "Low", "Info"]:
        if severity in by_severity:
            print(f"  {severity}: {len(by_severity[severity])}")
    
    print("\nTop Affected Services:")
    top_services = sorted(by_service.items(), key=lambda x: len(x[1]), reverse=True)[:5]
    for service, vulns in top_services:
        print(f"  {service}: {len(vulns)} vulnerabilities")
    
    # Save aggregated report
    with open(output_file, 'w') as f:
        json.dump(aggregated, f, indent=2)
    
    print(f"\n[+] Aggregated report saved to: {output_file}")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aggregate findings from multiple NOX scans")
    parser.add_argument("--pattern", help="Glob pattern for files to aggregate (e.g., 'scan_*.json')")
    parser.add_argument("--dir", help="Directory to search recursively for JSON files")
    parser.add_argument("--output", default="aggregated_findings.json", help="Output file")
    
    args = parser.parse_args()
    
    success = aggregate_findings(args.pattern, args.dir, args.output)
    sys.exit(0 if success else 1)
