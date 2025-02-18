import platform
import subprocess
import winreg
import json
from datetime import datetime
import socket
import os
import sys
from typing import Dict, List, Any

class STIGScanner:
    def __init__(self):
        self.findings = []
        self.hostname = socket.gethostname()
        self.os_info = platform.platform()
        
    def check_password_policy(self) -> None:
        """Check Windows password policy settings"""
        try:
            # Using SecEdit to export security policy
            subprocess.run(['secedit', '/export', '/cfg', 'secpol.cfg'], capture_output=True)
            
            with open('secpol.cfg', 'r') as file:
                policy_data = file.read()
                
            # Check minimum password length
            if 'MinimumPasswordLength = 14' not in policy_data:
                self.findings.append({
                    'severity': 'high',
                    'rule_id': 'V-63405',
                    'title': 'Minimum Password Length',
                    'status': 'Open',
                    'description': 'Minimum password length must be configured to 14 characters.',
                    'fix': 'Configure minimum password length to 14 characters in Security Policy.'
                })
                
            # Check password complexity
            if 'PasswordComplexity = 1' not in policy_data:
                self.findings.append({
                    'severity': 'high',
                    'rule_id': 'V-63407',
                    'title': 'Password Complexity',
                    'status': 'Open',
                    'description': 'Password complexity requirements must be enabled.',
                    'fix': 'Enable password complexity requirements in Security Policy.'
                })
                
            # Cleanup temporary file
            os.remove('secpol.cfg')
            
        except Exception as e:
            self.findings.append({
                'severity': 'info',
                'rule_id': 'CHECK-ERROR',
                'title': 'Password Policy Check Error',
                'status': 'Error',
                'description': f'Error checking password policy: {str(e)}',
                'fix': 'Ensure you have appropriate permissions to check security policy.'
            })

    def check_audit_policy(self) -> None:
        """Check Windows audit policy settings"""
        try:
            result = subprocess.run(['auditpol', '/get', '/category:*'], capture_output=True, text=True)
            audit_data = result.stdout

            # Check account logon auditing
            if 'Account Logon' in audit_data and 'Success and Failure' not in audit_data:
                self.findings.append({
                    'severity': 'medium',
                    'rule_id': 'V-63463',
                    'title': 'Audit Account Logon',
                    'status': 'Open',
                    'description': 'Account logon events must be audited.',
                    'fix': 'Configure audit policy to audit Account Logon events for Success and Failure.'
                })

        except Exception as e:
            self.findings.append({
                'severity': 'info',
                'rule_id': 'CHECK-ERROR',
                'title': 'Audit Policy Check Error',
                'status': 'Error',
                'description': f'Error checking audit policy: {str(e)}',
                'fix': 'Ensure you have appropriate permissions to check audit policy.'
            })

    def check_registry_settings(self) -> None:
        """Check Windows registry settings for STIG compliance"""
        registry_checks = [
            {
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'name': 'NoConnectedUser',
                'expected_value': 1,
                'rule_id': 'V-63447',
                'title': 'Microsoft Accounts',
                'description': 'Microsoft accounts must not be used for local account authentication.',
                'severity': 'medium'
            },
            {
                'path': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
                'name': 'EnableLUA',
                'expected_value': 1,
                'rule_id': 'V-63449',
                'title': 'User Account Control',
                'description': 'User Account Control must be enabled.',
                'severity': 'high'
            }
        ]

        for check in registry_checks:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, check['path'], 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(key, check['name'])
                winreg.CloseKey(key)

                if value != check['expected_value']:
                    self.findings.append({
                        'severity': check['severity'],
                        'rule_id': check['rule_id'],
                        'title': check['title'],
                        'status': 'Open',
                        'description': check['description'],
                        'fix': f"Set registry value {check['path']}\\{check['name']} to {check['expected_value']}"
                    })

            except Exception as e:
                self.findings.append({
                    'severity': 'info',
                    'rule_id': 'CHECK-ERROR',
                    'title': f"Registry Check Error - {check['title']}",
                    'status': 'Error',
                    'description': f"Error checking registry setting: {str(e)}",
                    'fix': 'Ensure you have appropriate permissions to read registry settings.'
                })

    def check_service_settings(self) -> None:
        """Check Windows service settings"""
        services_to_check = [
            {
                'name': 'RemoteRegistry',
                'expected_state': 'stopped',
                'rule_id': 'V-63545',
                'title': 'Remote Registry Service',
                'description': 'Remote Registry service must be disabled.',
                'severity': 'medium'
            },
            {
                'name': 'Telnet',
                'expected_state': 'stopped',
                'rule_id': 'V-63547',
                'title': 'Telnet Service',
                'description': 'Telnet service must be disabled.',
                'severity': 'high'
            }
        ]

        for service in services_to_check:
            try:
                result = subprocess.run(['sc', 'query', service['name']], capture_output=True, text=True)
                
                if 'RUNNING' in result.stdout and service['expected_state'] == 'stopped':
                    self.findings.append({
                        'severity': service['severity'],
                        'rule_id': service['rule_id'],
                        'title': service['title'],
                        'status': 'Open',
                        'description': service['description'],
                        'fix': f"Stop and disable the {service['name']} service."
                    })

            except Exception as e:
                self.findings.append({
                    'severity': 'info',
                    'rule_id': 'CHECK-ERROR',
                    'title': f"Service Check Error - {service['title']}",
                    'status': 'Error',
                    'description': f"Error checking service: {str(e)}",
                    'fix': 'Ensure you have appropriate permissions to query services.'
                })

    def run_scan(self) -> None:
        """Run all STIG compliance checks"""
        print(f"Starting STIG scan on {self.hostname} at {datetime.now()}")
        
        # Run all checks
        self.check_password_policy()
        self.check_audit_policy()
        self.check_registry_settings()
        self.check_service_settings()

    def generate_report(self) -> None:
        """Generate scan report"""
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'hostname': self.hostname,
                'os_info': self.os_info
            },
            'findings': self.findings,
            'summary': {
                'total_findings': len(self.findings),
                'high_severity': len([f for f in self.findings if f['severity'] == 'high']),
                'medium_severity': len([f for f in self.findings if f['severity'] == 'medium']),
                'low_severity': len([f for f in self.findings if f['severity'] == 'low'])
            }
        }

        # Save report to file
        with open('stig_scan_report.json', 'w') as f:
            json.dump(report, f, indent=4)

        # Print summary to console
        print("\nScan Summary:")
        print(f"Total findings: {report['summary']['total_findings']}")
        print(f"High severity: {report['summary']['high_severity']}")
        print(f"Medium severity: {report['summary']['medium_severity']}")
        print(f"Low severity: {report['summary']['low_severity']}")
        print("\nDetailed report saved to 'stig_scan_report.json'")

def main():
    if platform.system() != 'Windows':
        print("This STIG scanner is designed for Windows systems only.")
        sys.exit(1)

    try:
        scanner = STIGScanner()
        scanner.run_scan()
        scanner.generate_report()
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 