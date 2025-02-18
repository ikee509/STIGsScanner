import asyncio
import subprocess
from typing import List, Dict, Any
import os

class SecurityConfigScanner:
    """Scanner for system security configurations"""
    
    async def scan(self) -> List[Dict[str, Any]]:
        """Run security configuration checks"""
        findings = []
        
        # Check password policies
        findings.extend(await self._check_password_policy())
        
        # Check SSH configuration
        findings.extend(await self._check_ssh_config())
        
        # Check system-wide security settings
        findings.extend(await self._check_system_security())
        
        return findings

    async def _check_password_policy(self) -> List[Dict[str, Any]]:
        """Check password policy settings"""
        findings = []
        
        # Read PAM configuration
        try:
            with open('/etc/pam.d/common-password', 'r') as f:
                pam_config = f.read()

            # Check password complexity
            if 'pam_pwquality.so' not in pam_config:
                findings.append({
                    'severity': 'high',
                    'rule_id': 'V-72427',
                    'title': 'Password Quality Requirements',
                    'status': 'failed',
                    'description': 'Password quality requirements are not properly configured.',
                    'fix': 'Install and configure pam_pwquality module.',
                    'check_type': 'password_policy'
                })

        except Exception as e:
            findings.append({
                'severity': 'error',
                'rule_id': 'CHECK-ERROR',
                'title': 'Password Policy Check Error',
                'status': 'error',
                'description': f'Error checking password policy: {str(e)}',
                'fix': 'Ensure proper permissions to read PAM configuration.',
                'check_type': 'password_policy'
            })

        return findings

    async def _check_ssh_config(self) -> List[Dict[str, Any]]:
        """Check SSH server configuration"""
        findings = []
        
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                ssh_config = f.read()

            # Check Protocol version
            if 'Protocol 2' not in ssh_config:
                findings.append({
                    'severity': 'high',
                    'rule_id': 'V-72433',
                    'title': 'SSH Protocol Version',
                    'status': 'failed',
                    'description': 'SSH must be configured to use Protocol version 2.',
                    'fix': 'Set "Protocol 2" in /etc/ssh/sshd_config',
                    'check_type': 'ssh_config'
                })

            # Check PermitRootLogin
            if 'PermitRootLogin yes' in ssh_config:
                findings.append({
                    'severity': 'high',
                    'rule_id': 'V-72435',
                    'title': 'SSH Root Login',
                    'status': 'failed',
                    'description': 'Direct root login via SSH must be disabled.',
                    'fix': 'Set "PermitRootLogin no" in /etc/ssh/sshd_config',
                    'check_type': 'ssh_config'
                })

        except Exception as e:
            findings.append({
                'severity': 'error',
                'rule_id': 'CHECK-ERROR',
                'title': 'SSH Configuration Check Error',
                'status': 'error',
                'description': f'Error checking SSH configuration: {str(e)}',
                'fix': 'Ensure proper permissions to read SSH configuration.',
                'check_type': 'ssh_config'
            })

        return findings

    async def _check_system_security(self) -> List[Dict[str, Any]]:
        """Check system-wide security settings"""
        findings = []
        
        # Check core dumps
        try:
            with open('/etc/security/limits.conf', 'r') as f:
                limits_config = f.read()

            if '*     hard    core    0' not in limits_config:
                findings.append({
                    'severity': 'medium',
                    'rule_id': 'V-72439',
                    'title': 'Core Dumps',
                    'status': 'failed',
                    'description': 'Core dumps must be disabled for all users.',
                    'fix': 'Add "*     hard    core    0" to /etc/security/limits.conf',
                    'check_type': 'system_security'
                })

        except Exception as e:
            findings.append({
                'severity': 'error',
                'rule_id': 'CHECK-ERROR',
                'title': 'System Security Check Error',
                'status': 'error',
                'description': f'Error checking system security settings: {str(e)}',
                'fix': 'Ensure proper permissions to read system configuration files.',
                'check_type': 'system_security'
            })

        return findings 