import asyncio
import subprocess
from typing import List, Dict, Any
import logging
import os
import re
from pathlib import Path

class ServiceScanner:
    """Scanner for checking service configurations against STIG requirements"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Services that must be disabled
        self.disabled_services = [
            "telnet",
            "rsh-server",
            "rlogin-server",
            "rexec-server",
            "ypserv",
            "tftp-server",
            "xinetd",
            "vsftpd",
            "rsyncd"
        ]
        
        # Services that must be enabled and running
        self.required_services = [
            "auditd",
            "sshd",
            "systemd-timesyncd"
        ]
        
        # Service configurations to check
        self.service_configs = {
            "sshd": {
                "path": "/etc/ssh/sshd_config",
                "settings": {
                    "PermitRootLogin": "no",
                    "Protocol": "2",
                    "PermitEmptyPasswords": "no",
                    "X11Forwarding": "no",
                    "MaxAuthTries": "4",
                    "ClientAliveInterval": "300",
                    "ClientAliveCountMax": "0"
                }
            },
            "auditd": {
                "path": "/etc/audit/auditd.conf",
                "settings": {
                    "max_log_file_action": "keep_logs",
                    "space_left_action": "email",
                    "action_mail_acct": "root",
                    "admin_space_left_action": "halt"
                }
            }
        }

    async def scan(self) -> List[Dict[str, Any]]:
        """Run service configuration checks"""
        findings = []
        
        # Check service states
        findings.extend(await self._check_service_states())
        
        # Check service configurations
        findings.extend(await self._check_service_configs())
        
        # Check for unauthorized services
        findings.extend(await self._check_unauthorized_services())
        
        # Check systemd targets
        findings.extend(await self._check_systemd_targets())
        
        return findings

    async def _check_service_states(self) -> List[Dict[str, Any]]:
        """Check if required services are running and disabled services are stopped"""
        findings = []
        
        # Check required services
        for service in self.required_services:
            try:
                status = await self._get_service_status(service)
                
                if status["active"] != "active":
                    findings.append({
                        "rule_id": "V-72051",
                        "title": f"Required Service Not Running: {service}",
                        "status": "failed",
                        "severity": "high",
                        "description": f"Required service {service} is not running",
                        "fix": f"systemctl start {service} && systemctl enable {service}",
                        "check_type": "service"
                    })
                
                if not status["enabled"]:
                    findings.append({
                        "rule_id": "V-72053",
                        "title": f"Required Service Not Enabled: {service}",
                        "status": "failed",
                        "severity": "medium",
                        "description": f"Required service {service} is not enabled",
                        "fix": f"systemctl enable {service}",
                        "check_type": "service"
                    })
                    
            except Exception as e:
                self.logger.error(f"Error checking service {service}: {str(e)}")
                
        # Check disabled services
        for service in self.disabled_services:
            try:
                status = await self._get_service_status(service)
                
                if status["active"] == "active":
                    findings.append({
                        "rule_id": "V-72055",
                        "title": f"Prohibited Service Running: {service}",
                        "status": "failed",
                        "severity": "high",
                        "description": f"Prohibited service {service} is running",
                        "fix": f"systemctl stop {service} && systemctl disable {service}",
                        "check_type": "service"
                    })
                
                if status["enabled"]:
                    findings.append({
                        "rule_id": "V-72057",
                        "title": f"Prohibited Service Enabled: {service}",
                        "status": "failed",
                        "severity": "medium",
                        "description": f"Prohibited service {service} is enabled",
                        "fix": f"systemctl disable {service}",
                        "check_type": "service"
                    })
                    
            except Exception as e:
                self.logger.debug(f"Error checking service {service}: {str(e)}")

        return findings

    async def _check_service_configs(self) -> List[Dict[str, Any]]:
        """Check service configuration files"""
        findings = []
        
        for service, config in self.service_configs.items():
            config_path = config["path"]
            
            if not os.path.exists(config_path):
                findings.append({
                    "rule_id": "V-72059",
                    "title": f"Missing Service Configuration: {service}",
                    "status": "failed",
                    "severity": "high",
                    "description": f"Configuration file {config_path} for service {service} is missing",
                    "fix": f"Reinstall {service} package",
                    "check_type": "service"
                })
                continue
                
            try:
                with open(config_path, 'r') as f:
                    content = f.read()
                    
                for setting, required_value in config["settings"].items():
                    # Look for the setting in the config file
                    pattern = rf"^\s*{setting}\s+(.+?)\s*$"
                    match = re.search(pattern, content, re.MULTILINE)
                    
                    if not match or match.group(1) != required_value:
                        findings.append({
                            "rule_id": "V-72061",
                            "title": f"Incorrect Service Configuration: {service}",
                            "status": "failed",
                            "severity": "medium",
                            "description": f"Service {service} has incorrect setting for {setting}",
                            "fix": f"Set '{setting} {required_value}' in {config_path}",
                            "check_type": "service"
                        })
                        
            except Exception as e:
                self.logger.error(f"Error checking {service} configuration: {str(e)}")
                findings.append({
                    "rule_id": "CHECK-ERROR",
                    "title": f"Service Configuration Check Error: {service}",
                    "status": "error",
                    "severity": "info",
                    "description": f"Error checking service configuration: {str(e)}",
                    "fix": "Ensure proper permissions to read service configuration",
                    "check_type": "service"
                })

        return findings

    async def _check_unauthorized_services(self) -> List[Dict[str, Any]]:
        """Check for unauthorized network services"""
        findings = []
        
        try:
            # Check listening ports
            process = await asyncio.create_subprocess_exec(
                "ss", "-tuln",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                
                # Check for telnet port
                if ":23" in output:
                    findings.append({
                        "rule_id": "V-72063",
                        "title": "Telnet Port Open",
                        "status": "failed",
                        "severity": "high",
                        "description": "Telnet port (23) is open",
                        "fix": "Identify and disable service listening on port 23",
                        "check_type": "service"
                    })
                
                # Check for FTP port
                if ":21" in output:
                    findings.append({
                        "rule_id": "V-72065",
                        "title": "FTP Port Open",
                        "status": "failed",
                        "severity": "high",
                        "description": "FTP port (21) is open",
                        "fix": "Identify and disable service listening on port 21",
                        "check_type": "service"
                    })
                    
        except Exception as e:
            self.logger.error(f"Error checking network services: {str(e)}")
            findings.append({
                "rule_id": "CHECK-ERROR",
                "title": "Network Service Check Error",
                "status": "error",
                "severity": "info",
                "description": f"Error checking network services: {str(e)}",
                "fix": "Ensure proper permissions to check network status",
                "check_type": "service"
            })

        return findings

    async def _check_systemd_targets(self) -> List[Dict[str, Any]]:
        """Check systemd target configurations"""
        findings = []
        
        try:
            # Check default target
            process = await asyncio.create_subprocess_exec(
                "systemctl", "get-default",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                default_target = stdout.decode().strip()
                
                # Check if graphical target is default
                if default_target == "graphical.target":
                    findings.append({
                        "rule_id": "V-72067",
                        "title": "Graphical Target Default",
                        "status": "failed",
                        "severity": "medium",
                        "description": "System is configured to boot to graphical target",
                        "fix": "systemctl set-default multi-user.target",
                        "check_type": "service"
                    })
                    
        except Exception as e:
            self.logger.error(f"Error checking systemd targets: {str(e)}")
            findings.append({
                "rule_id": "CHECK-ERROR",
                "title": "Systemd Target Check Error",
                "status": "error",
                "severity": "info",
                "description": f"Error checking systemd targets: {str(e)}",
                "fix": "Ensure proper permissions to check systemd configuration",
                "check_type": "service"
            })

        return findings

    async def _get_service_status(self, service: str) -> Dict[str, Any]:
        """Get service status using systemctl"""
        status = {
            "active": "unknown",
            "enabled": False
        }
        
        try:
            # Check if service is active
            process = await asyncio.create_subprocess_exec(
                "systemctl", "is-active", service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            status["active"] = stdout.decode().strip()
            
            # Check if service is enabled
            process = await asyncio.create_subprocess_exec(
                "systemctl", "is-enabled", service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            status["enabled"] = stdout.decode().strip() == "enabled"
            
        except Exception as e:
            self.logger.error(f"Error getting status for service {service}: {str(e)}")
            
        return status 