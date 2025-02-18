import pwd
import grp
import spwd
from typing import List, Dict, Any
import logging
from datetime import datetime, timedelta
import re

class UserGroupScanner:
    """Scanner for checking user and group configurations"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Users that must exist
        self.required_users = ["root"]
        
        # Groups that must exist
        self.required_groups = ["root", "shadow", "sudo"]
        
        # Users that should not exist
        self.prohibited_users = ["games", "irc", "news", "uucp"]
        
        # Maximum password age in days
        self.max_password_age = 60
        
        # Minimum password age in days
        self.min_password_age = 1

    async def scan(self) -> List[Dict[str, Any]]:
        """Run user and group configuration checks"""
        findings = []
        
        # Check required users and groups
        findings.extend(await self._check_required_entities())
        
        # Check prohibited users
        findings.extend(await self._check_prohibited_users())
        
        # Check password aging
        findings.extend(await self._check_password_aging())
        
        # Check root account
        findings.extend(await self._check_root_account())
        
        # Check sudo group configuration
        findings.extend(await self._check_sudo_config())
        
        return findings

    async def _check_required_entities(self) -> List[Dict[str, Any]]:
        """Check for required users and groups"""
        findings = []
        
        # Check required users
        existing_users = [user.pw_name for user in pwd.getpwall()]
        for username in self.required_users:
            if username not in existing_users:
                findings.append({
                    "rule_id": "V-72031",
                    "title": f"Missing Required User: {username}",
                    "status": "failed",
                    "severity": "high",
                    "description": f"Required user {username} does not exist",
                    "fix": f"useradd {username}",
                    "check_type": "user_group"
                })

        # Check required groups
        existing_groups = [group.gr_name for group in grp.getgrall()]
        for groupname in self.required_groups:
            if groupname not in existing_groups:
                findings.append({
                    "rule_id": "V-72033",
                    "title": f"Missing Required Group: {groupname}",
                    "status": "failed",
                    "severity": "high",
                    "description": f"Required group {groupname} does not exist",
                    "fix": f"groupadd {groupname}",
                    "check_type": "user_group"
                })

        return findings

    async def _check_prohibited_users(self) -> List[Dict[str, Any]]:
        """Check for prohibited user accounts"""
        findings = []
        
        existing_users = [user.pw_name for user in pwd.getpwall()]
        for username in self.prohibited_users:
            if username in existing_users:
                findings.append({
                    "rule_id": "V-72035",
                    "title": f"Prohibited User Account: {username}",
                    "status": "failed",
                    "severity": "medium",
                    "description": f"Prohibited user account {username} exists",
                    "fix": f"userdel {username}",
                    "check_type": "user_group"
                })

        return findings

    async def _check_password_aging(self) -> List[Dict[str, Any]]:
        """Check password aging settings"""
        findings = []
        
        try:
            for user in spwd.getspall():
                if user.sp_lstchg == -1:
                    continue  # Skip if password aging is disabled
                    
                # Check maximum password age
                if user.sp_max > self.max_password_age or user.sp_max == -1:
                    findings.append({
                        "rule_id": "V-72037",
                        "title": f"Password Age Violation: {user.sp_namp}",
                        "status": "failed",
                        "severity": "medium",
                        "description": f"User {user.sp_namp} has maximum password age > {self.max_password_age} days",
                        "fix": f"chage -M {self.max_password_age} {user.sp_namp}",
                        "check_type": "user_group"
                    })

                # Check minimum password age
                if user.sp_min < self.min_password_age:
                    findings.append({
                        "rule_id": "V-72039",
                        "title": f"Minimum Password Age Violation: {user.sp_namp}",
                        "status": "failed",
                        "severity": "medium",
                        "description": f"User {user.sp_namp} has minimum password age < {self.min_password_age} days",
                        "fix": f"chage -m {self.min_password_age} {user.sp_namp}",
                        "check_type": "user_group"
                    })

        except Exception as e:
            self.logger.error(f"Error checking password aging: {str(e)}")
            findings.append({
                "rule_id": "CHECK-ERROR",
                "title": "Password Aging Check Error",
                "status": "error",
                "severity": "info",
                "description": f"Error checking password aging: {str(e)}",
                "fix": "Ensure proper permissions to read shadow file",
                "check_type": "user_group"
            })

        return findings

    async def _check_root_account(self) -> List[Dict[str, Any]]:
        """Check root account configuration"""
        findings = []
        
        try:
            root_user = pwd.getpwnam("root")
            
            # Check root UID
            if root_user.pw_uid != 0:
                findings.append({
                    "rule_id": "V-72041",
                    "title": "Invalid Root UID",
                    "status": "failed",
                    "severity": "high",
                    "description": f"Root account has invalid UID: {root_user.pw_uid}",
                    "fix": "Restore root account UID to 0",
                    "check_type": "user_group"
                })

            # Check root GID
            if root_user.pw_gid != 0:
                findings.append({
                    "rule_id": "V-72043",
                    "title": "Invalid Root GID",
                    "status": "failed",
                    "severity": "high",
                    "description": f"Root account has invalid GID: {root_user.pw_gid}",
                    "fix": "Restore root account GID to 0",
                    "check_type": "user_group"
                })

            # Check root shell
            valid_shells = ["/bin/bash", "/bin/sh"]
            if root_user.pw_shell not in valid_shells:
                findings.append({
                    "rule_id": "V-72045",
                    "title": "Invalid Root Shell",
                    "status": "failed",
                    "severity": "medium",
                    "description": f"Root account has invalid shell: {root_user.pw_shell}",
                    "fix": "chsh -s /bin/bash root",
                    "check_type": "user_group"
                })

        except Exception as e:
            self.logger.error(f"Error checking root account: {str(e)}")
            findings.append({
                "rule_id": "CHECK-ERROR",
                "title": "Root Account Check Error",
                "status": "error",
                "severity": "info",
                "description": f"Error checking root account: {str(e)}",
                "fix": "Ensure proper permissions to read passwd file",
                "check_type": "user_group"
            })

        return findings

    async def _check_sudo_config(self) -> List[Dict[str, Any]]:
        """Check sudo configuration"""
        findings = []
        
        try:
            sudo_group = grp.getgrnam("sudo")
            
            # Check sudo group members
            if len(sudo_group.gr_mem) > 0:
                findings.append({
                    "rule_id": "V-72047",
                    "title": "Direct Sudo Group Members",
                    "status": "failed",
                    "severity": "medium",
                    "description": f"Users are directly assigned to sudo group: {', '.join(sudo_group.gr_mem)}",
                    "fix": "Remove users from sudo group and use sudoers file for access control",
                    "check_type": "user_group"
                })

            # Check sudoers file
            if os.path.exists("/etc/sudoers"):
                with open("/etc/sudoers", "r") as f:
                    content = f.read()
                    
                    # Check for NOPASSWD entries
                    if "NOPASSWD" in content:
                        findings.append({
                            "rule_id": "V-72049",
                            "title": "Sudo Without Password",
                            "status": "failed",
                            "severity": "high",
                            "description": "Sudo configuration allows execution without password",
                            "fix": "Remove NOPASSWD entries from sudoers file",
                            "check_type": "user_group"
                        })

        except Exception as e:
            self.logger.error(f"Error checking sudo configuration: {str(e)}")
            findings.append({
                "rule_id": "CHECK-ERROR",
                "title": "Sudo Configuration Check Error",
                "status": "error",
                "severity": "info",
                "description": f"Error checking sudo configuration: {str(e)}",
                "fix": "Ensure proper permissions to read sudo configuration",
                "check_type": "user_group"
            })

        return findings 