import os
import stat
import pwd
import grp
from typing import List, Dict, Any
import logging
from pathlib import Path

class FilePermissionScanner:
    """Scanner for checking file permissions against STIG requirements"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Critical files that require specific permissions
        self.critical_files = {
            "/etc/passwd": {"mode": 0o644, "owner": "root", "group": "root"},
            "/etc/shadow": {"mode": 0o640, "owner": "root", "group": "shadow"},
            "/etc/group": {"mode": 0o644, "owner": "root", "group": "root"},
            "/etc/gshadow": {"mode": 0o640, "owner": "root", "group": "shadow"},
            "/etc/ssh/sshd_config": {"mode": 0o600, "owner": "root", "group": "root"},
            "/etc/sudoers": {"mode": 0o440, "owner": "root", "group": "root"}
        }
        
        # World-writable directories that should be checked
        self.check_world_writable = [
            "/tmp",
            "/var/tmp",
            "/var/log"
        ]

    async def scan(self) -> List[Dict[str, Any]]:
        """Run file permission checks"""
        findings = []
        
        # Check critical file permissions
        findings.extend(await self._check_critical_files())
        
        # Check world-writable files
        findings.extend(await self._check_world_writable_files())
        
        # Check home directory permissions
        findings.extend(await self._check_home_directories())
        
        return findings

    async def _check_critical_files(self) -> List[Dict[str, Any]]:
        """Check permissions on critical system files"""
        findings = []
        
        for filepath, required in self.critical_files.items():
            try:
                if not os.path.exists(filepath):
                    findings.append({
                        "rule_id": "V-72011",
                        "title": f"Missing Critical File: {filepath}",
                        "status": "failed",
                        "severity": "high",
                        "description": f"Critical system file {filepath} is missing",
                        "fix": f"Restore {filepath} from system backup or reinstall package",
                        "check_type": "file_permission"
                    })
                    continue

                stat_info = os.stat(filepath)
                current_mode = stat.S_IMODE(stat_info.st_mode)
                current_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                current_group = grp.getgrgid(stat_info.st_gid).gr_name

                if current_mode != required["mode"]:
                    findings.append({
                        "rule_id": "V-72013",
                        "title": f"Incorrect File Permissions: {filepath}",
                        "status": "failed",
                        "severity": "high",
                        "description": f"File {filepath} has incorrect permissions: {oct(current_mode)} (should be {oct(required['mode'])})",
                        "fix": f"chmod {oct(required['mode'])[2:]} {filepath}",
                        "check_type": "file_permission"
                    })

                if current_owner != required["owner"] or current_group != required["group"]:
                    findings.append({
                        "rule_id": "V-72015",
                        "title": f"Incorrect File Ownership: {filepath}",
                        "status": "failed",
                        "severity": "high",
                        "description": f"File {filepath} has incorrect ownership: {current_owner}:{current_group} (should be {required['owner']}:{required['group']})",
                        "fix": f"chown {required['owner']}:{required['group']} {filepath}",
                        "check_type": "file_permission"
                    })

            except Exception as e:
                self.logger.error(f"Error checking {filepath}: {str(e)}")
                findings.append({
                    "rule_id": "CHECK-ERROR",
                    "title": f"File Permission Check Error: {filepath}",
                    "status": "error",
                    "severity": "info",
                    "description": f"Error checking file permissions: {str(e)}",
                    "fix": "Ensure proper permissions to read file attributes",
                    "check_type": "file_permission"
                })

        return findings

    async def _check_world_writable_files(self) -> List[Dict[str, Any]]:
        """Check for unauthorized world-writable files"""
        findings = []
        
        for directory in self.check_world_writable:
            try:
                for root, dirs, files in os.walk(directory):
                    for name in files + dirs:
                        filepath = os.path.join(root, name)
                        try:
                            stat_info = os.stat(filepath)
                            mode = stat.S_IMODE(stat_info.st_mode)
                            
                            # Check if world-writable
                            if mode & stat.S_IWOTH:
                                # Skip if sticky bit is set for allowed directories
                                if directory in ["/tmp", "/var/tmp"] and \
                                   os.path.isdir(filepath) and \
                                   mode & stat.S_ISVTX:
                                    continue
                                    
                                findings.append({
                                    "rule_id": "V-72017",
                                    "title": f"World-Writable File: {filepath}",
                                    "status": "failed",
                                    "severity": "medium",
                                    "description": f"File {filepath} is world-writable (mode: {oct(mode)})",
                                    "fix": f"chmod o-w {filepath}",
                                    "check_type": "file_permission"
                                })
                                
                        except Exception as e:
                            self.logger.debug(f"Error checking {filepath}: {str(e)}")

            except Exception as e:
                self.logger.error(f"Error scanning directory {directory}: {str(e)}")

        return findings

    async def _check_home_directories(self) -> List[Dict[str, Any]]:
        """Check home directory permissions"""
        findings = []
        
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if not line.strip() or line.startswith('#'):
                        continue
                        
                    fields = line.strip().split(':')
                    if len(fields) >= 6:
                        username = fields[0]
                        home_dir = fields[5]
                        
                        if home_dir and home_dir != '/':
                            try:
                                if os.path.exists(home_dir):
                                    stat_info = os.stat(home_dir)
                                    mode = stat.S_IMODE(stat_info.st_mode)
                                    
                                    # Check if home directory is world-readable or world-writable
                                    if mode & (stat.S_IROTH | stat.S_IWOTH):
                                        findings.append({
                                            "rule_id": "V-72019",
                                            "title": f"Insecure Home Directory: {home_dir}",
                                            "status": "failed",
                                            "severity": "medium",
                                            "description": f"Home directory {home_dir} for user {username} has incorrect permissions: {oct(mode)}",
                                            "fix": f"chmod o-rw {home_dir}",
                                            "check_type": "file_permission"
                                        })
                                        
                                    # Check ownership
                                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
                                    if owner != username and owner != "root":
                                        findings.append({
                                            "rule_id": "V-72021",
                                            "title": f"Incorrect Home Directory Ownership: {home_dir}",
                                            "status": "failed",
                                            "severity": "medium",
                                            "description": f"Home directory {home_dir} is owned by {owner} instead of {username}",
                                            "fix": f"chown {username} {home_dir}",
                                            "check_type": "file_permission"
                                        })
                                        
                            except Exception as e:
                                self.logger.debug(f"Error checking home directory {home_dir}: {str(e)}")
                                
        except Exception as e:
            self.logger.error(f"Error reading passwd file: {str(e)}")
            findings.append({
                "rule_id": "CHECK-ERROR",
                "title": "Home Directory Check Error",
                "status": "error",
                "severity": "info",
                "description": f"Error checking home directories: {str(e)}",
                "fix": "Ensure proper permissions to read passwd file",
                "check_type": "file_permission"
            })

        return findings 