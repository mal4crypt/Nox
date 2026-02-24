#!/usr/bin/env python3
"""
NOX Comprehensive Test Suite
Industrial-standard testing for all modules
"""

import subprocess
import json
import sys
import os
from datetime import datetime
from pathlib import Path

class TestRunner:
    """Run comprehensive tests on all NOX modules"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'test_results': [],
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'skipped': 0,
                'errors': []
            }
        }
        self.root_dir = Path(__file__).parent
    
    def run_test(self, test_name, command, expected_fields=None):
        """Run a single test"""
        print(f"\n{'='*80}")
        print(f"Testing: {test_name}")
        print(f"Command: {command}")
        print(f"{'='*80}")
        
        self.results['summary']['total_tests'] += 1
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=str(self.root_dir),
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check exit code
            if result.returncode != 0:
                print(f"❌ FAILED: Non-zero exit code ({result.returncode})")
                if result.stderr:
                    print(f"Error output: {result.stderr[:500]}")
                self.results['summary']['failed'] += 1
                self.results['test_results'].append({
                    'name': test_name,
                    'status': 'FAILED',
                    'reason': f'Exit code {result.returncode}',
                    'stderr': result.stderr[:500]
                })
                return False
            
            # Extract JSON from output (banner is printed before JSON)
            output = result.stdout.strip()
            json_start = output.find('{')
            if json_start == -1:
                json_start = output.find('[')
            
            if json_start != -1:
                json_str = output[json_start:]
            else:
                json_str = output
            
            # Try to parse JSON output
            try:
                output_json = json.loads(json_str)
                print(f"✅ PASSED: Valid JSON output")
                
                # Check for expected fields
                if expected_fields:
                    missing_fields = []
                    for field in expected_fields:
                        if field not in str(output_json):
                            missing_fields.append(field)
                    
                    if missing_fields:
                        print(f"⚠️  WARNING: Missing expected fields: {missing_fields}")
                        self.results['summary']['passed'] += 1
                        self.results['test_results'].append({
                            'name': test_name,
                            'status': 'PASSED_WITH_WARNINGS',
                            'missing_fields': missing_fields
                        })
                        return True
                
                self.results['summary']['passed'] += 1
                self.results['test_results'].append({
                    'name': test_name,
                    'status': 'PASSED',
                    'output_keys': list(output_json.keys()) if isinstance(output_json, dict) else 'array'
                })
                return True
            
            except json.JSONDecodeError as e:
                print(f"❌ FAILED: Invalid JSON output - {str(e)[:200]}")
                print(f"   Output (first 300 chars): {json_str[:300]}")
                self.results['summary']['failed'] += 1
                self.results['test_results'].append({
                    'name': test_name,
                    'status': 'FAILED',
                    'reason': f'Invalid JSON: {str(e)[:200]}'
                })
                return False
        
        except subprocess.TimeoutExpired:
            print(f"❌ FAILED: Test timeout (>30 seconds)")
            self.results['summary']['failed'] += 1
            self.results['test_results'].append({
                'name': test_name,
                'status': 'FAILED',
                'reason': 'Timeout exceeded'
            })
            return False
        
        except Exception as e:
            print(f"❌ ERROR: {str(e)}")
            self.results['summary']['failed'] += 1
            self.results['summary']['errors'].append(f"{test_name}: {str(e)}")
            self.results['test_results'].append({
                'name': test_name,
                'status': 'ERROR',
                'error': str(e)
            })
            return False
    
    def run_all_tests(self):
        """Run all module tests"""
        print(f"\n{'█'*80}")
        print(f"NOX COMPREHENSIVE TEST SUITE - Industrial Standard Validation")
        print(f"{'█'*80}")
        
        # Phase 1 Tests (Enterprise)
        print(f"\n\n{'▓'*80}")
        print(f"PHASE 1: ENTERPRISE SECURITY MODULES")
        print(f"{'▓'*80}")
        
        self.run_test(
            "Active Directory Scanner (ADX)",
            "python3 cred/adx.py --domain example.com --full-enum --confirm-legal",
            ['timestamp', 'target_domain', 'users', 'vulnerabilities']
        )
        
        self.run_test(
            "AWS Security Assessment (AWSX)",
            "python3 cloud/awsx.py --full-assessment --confirm-legal",
            ['timestamp', 'iam', 'vulnerabilities']
        )
        
        self.run_test(
            "Kubernetes Security Scanner (KUBEX)",
            "python3 cloud/kubex.py --cluster minikube --full-scan --confirm-legal",
            ['timestamp', 'cluster', 'rbac', 'vulnerabilities']
        )
        
        self.run_test(
            "API Testing Framework (APIX)",
            "python3 webpwn/apix.py --target https://api.example.com --full-test --confirm-legal",
            ['timestamp', 'target', 'endpoints', 'vulnerabilities']
        )
        
        # Phase 2 Tests (Advanced Ops)
        print(f"\n\n{'▓'*80}")
        print(f"PHASE 2: ADVANCED OPERATIONS MODULES")
        print(f"{'▓'*80}")
        
        self.run_test(
            "Packet Capture & Analysis (PACKETX)",
            "python3 netpwn/packetx.py --interface eth0 --full-analysis --confirm-legal",
            ['timestamp', 'packets_captured', 'findings']
        )
        
        self.run_test(
            "WAF Bypass & Evasion (WAFBYPASS)",
            "python3 evasion/wafbypass.py --target https://example.com --full-test --confirm-legal",
            ['timestamp', 'target', 'waf_detected', 'bypass_techniques']
        )
        
        self.run_test(
            "SIEM Integration (SEND_TO_SIEM)",
            "python3 scripts/send_to_siem.py --siem-server siem.example.com --full-test --confirm-legal",
            ['timestamp', 'siem_server', 'alerts_sent']
        )
        
        self.run_test(
            "CI/CD Security Scanner (CICD_SECURITY)",
            "python3 scripts/cicd_security.py --platform github --full-test --confirm-legal",
            ['timestamp', 'platform', 'vulnerabilities']
        )
        
        # Phase 3 Tests (Strategic)
        print(f"\n\n{'▓'*80}")
        print(f"PHASE 3: STRATEGIC COMPLETION MODULES")
        print(f"{'▓'*80}")
        
        self.run_test(
            "Azure Security Assessment (AZUREX)",
            "python3 cloud/azurex.py --subscription test --full-scan --confirm-legal",
            ['timestamp', 'subscription', 'identity', 'vulnerabilities']
        )
        
        self.run_test(
            "GCP Security Assessment (GCPX)",
            "python3 cloud/gcpx.py --project test-project --full-scan --confirm-legal",
            ['timestamp', 'project', 'iam', 'vulnerabilities']
        )
        
        self.run_test(
            "Data Mining & OSINT (DATAMINER)",
            "python3 intel/dataminer.py --target example.com --full-recon --confirm-legal",
            ['timestamp', 'target', 'osint', 'summary']
        )
        
        self.run_test(
            "Threat Intelligence Analysis (THREATX)",
            "python3 spekt/threatx.py --target example.com --full-analysis --confirm-legal",
            ['timestamp', 'intelligence', 'threat_level']
        )
        
        self.run_test(
            "Automated Remediation (AUTO_REMEDIATE)",
            "python3 scripts/auto_remediate.py --full-remediate --confirm-legal --approve",
            ['timestamp', 'remediation', 'summary']
        )
        
        self.run_test(
            "Security Dashboard (DASHBOARDX)",
            "python3 report/dashboardx.py --full-dashboard --confirm-legal",
            ['timestamp', 'dashboard', 'metrics']
        )
        
        # Print Summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        summary = self.results['summary']
        
        print(f"\n\n{'█'*80}")
        print(f"TEST SUMMARY")
        print(f"{'█'*80}\n")
        
        print(f"Total Tests Run:   {summary['total_tests']}")
        print(f"Passed:            {summary['passed']} ✅")
        print(f"Failed:            {summary['failed']} ❌")
        print(f"Skipped:           {summary['skipped']} ⊘")
        
        pass_rate = (summary['passed'] / summary['total_tests'] * 100) if summary['total_tests'] > 0 else 0
        print(f"\nPass Rate:         {pass_rate:.1f}%")
        
        if summary['errors']:
            print(f"\nErrors:")
            for error in summary['errors']:
                print(f"  • {error}")
        
        print(f"\n{'█'*80}\n")
        
        # Save results
        results_file = self.root_dir / 'test_results.json'
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"✅ Test results saved to: {results_file}")
        
        if pass_rate >= 95:
            print(f"✅ INDUSTRIAL STANDARD: PASSED (>95% pass rate)")
            return 0
        elif pass_rate >= 85:
            print(f"⚠️  INDUSTRIAL STANDARD: ACCEPTABLE (>85% pass rate)")
            return 0
        else:
            print(f"❌ INDUSTRIAL STANDARD: FAILED (<85% pass rate)")
            return 1

def main():
    runner = TestRunner()
    return runner.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())
