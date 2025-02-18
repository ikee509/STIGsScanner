import asyncio
import logging
import json
import os
import subprocess
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path
import shutil

class RemediationManager:
    """Manages remediation plans and executions for STIG findings"""
    
    def __init__(self, db_manager):
        self.db = db_manager
        self.logger = logging.getLogger(__name__)
        self.backup_dir = Path("/var/lib/stig-agent/backups")
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    async def create_plan(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Create a remediation plan from scan findings"""
        findings = scan_results["findings"]
        plan_items = []

        for finding in findings:
            if finding["status"] == "failed":
                remediation = self._get_remediation_steps(finding)
                if remediation:
                    plan_items.append({
                        "finding_id": finding["rule_id"],
                        "title": finding["title"],
                        "severity": finding["severity"],
                        "remediation": remediation,
                        "backup_required": remediation.get("backup_required", True)
                    })

        plan = {
            "scan_id": scan_results.get("scan_id"),
            "items": plan_items,
            "created_at": datetime.now().isoformat()
        }

        # Store the plan in the database
        plan_id = await self.db.store_remediation_plan(plan)
        plan["plan_id"] = plan_id

        return plan

    def _get_remediation_steps(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Get remediation steps for a specific finding"""
        remediation_map = {
            # Password Policy Remediations
            "V-72427": {
                "type": "package_install",
                "package": "libpam-pwquality",
                "config_file": "/etc/security/pwquality.conf",
                "settings": {
                    "minlen": "14",
                    "dcredit": "-1",
                    "ucredit": "-1",
                    "lcredit": "-1",
                    "ocredit": "-1"
                },
                "backup_required": True
            },
            # SSH Configuration Remediations
            "V-72433": {
                "type": "file_edit",
                "file": "/etc/ssh/sshd_config",
                "changes": [
                    {"regex": "^Protocol.*", "replacement": "Protocol 2"},
                    {"append_if_not_found": "Protocol 2"}
                ],
                "service_restart": "ssh",
                "backup_required": True
            },
            # Service Configuration Remediations
            "V-72435": {
                "type": "service_config",
                "service": "ssh",
                "config_file": "/etc/ssh/sshd_config",
                "changes": [
                    {"regex": "^PermitRootLogin.*", "replacement": "PermitRootLogin no"},
                    {"append_if_not_found": "PermitRootLogin no"}
                ],
                "backup_required": True
            }
        }

        return remediation_map.get(finding["rule_id"])

    async def execute_plan(self, plan_id: str, approved_items: List[str]) -> Dict[str, Any]:
        """Execute approved remediation items"""
        # Get the plan from the database
        plan = await self._get_plan(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")

        execution_results = {
            "plan_id": plan_id,
            "timestamp": datetime.now().isoformat(),
            "items": [],
            "status": "in_progress"
        }

        try:
            for item in plan["items"]:
                if item["finding_id"] in approved_items:
                    result = await self._execute_remediation_item(item)
                    execution_results["items"].append(result)

            execution_results["status"] = "completed"
            
        except Exception as e:
            self.logger.error(f"Error during remediation execution: {str(e)}")
            execution_results["status"] = "failed"
            execution_results["error"] = str(e)

        # Store execution results
        await self.db.store_remediation_execution(execution_results)
        await self.db.update_remediation_status(plan_id, execution_results["status"])

        return execution_results

    async def _execute_remediation_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single remediation item"""
        result = {
            "finding_id": item["finding_id"],
            "title": item["title"],
            "status": "failed",
            "changes_made": [],
            "backup_path": None
        }

        try:
            remediation = item["remediation"]
            
            # Create backup if required
            if remediation.get("backup_required"):
                result["backup_path"] = await self._create_backup(remediation)

            # Execute based on remediation type
            if remediation["type"] == "package_install":
                await self._handle_package_installation(remediation, result)
            
            elif remediation["type"] == "file_edit":
                await self._handle_file_edit(remediation, result)
            
            elif remediation["type"] == "service_config":
                await self._handle_service_config(remediation, result)

            result["status"] = "success"

        except Exception as e:
            result["error"] = str(e)
            # Attempt to restore from backup if available
            if result["backup_path"]:
                await self._restore_from_backup(result["backup_path"], remediation)

        return result

    async def _create_backup(self, remediation: Dict[str, Any]) -> str:
        """Create backup of files before modification"""
        if "config_file" in remediation:
            source = remediation["config_file"]
        elif "file" in remediation:
            source = remediation["file"]
        else:
            return None

        if not os.path.exists(source):
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"{os.path.basename(source)}.{timestamp}.bak"
        
        shutil.copy2(source, backup_path)
        return str(backup_path)

    async def _restore_from_backup(self, backup_path: str, remediation: Dict[str, Any]) -> None:
        """Restore file from backup"""
        if not backup_path or not os.path.exists(backup_path):
            return

        target = remediation.get("config_file") or remediation.get("file")
        if target:
            shutil.copy2(backup_path, target)
            self.logger.info(f"Restored {target} from backup {backup_path}")

    async def _handle_package_installation(self, remediation: Dict[str, Any], result: Dict[str, Any]):
        """Handle package installation remediation"""
        package = remediation["package"]
        
        # Install package
        process = await asyncio.create_subprocess_exec(
            "apt-get", "install", "-y", package,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"Failed to install package {package}: {stderr.decode()}")

        result["changes_made"].append(f"Installed package {package}")

        # Configure if needed
        if "config_file" in remediation and "settings" in remediation:
            await self._update_config_file(
                remediation["config_file"],
                remediation["settings"],
                result
            )

    async def _handle_file_edit(self, remediation: Dict[str, Any], result: Dict[str, Any]):
        """Handle file edit remediation"""
        file_path = remediation["file"]
        
        with open(file_path, 'r') as f:
            content = f.read()

        new_content = content
        for change in remediation["changes"]:
            if "regex" in change:
                import re
                pattern = re.compile(change["regex"], re.MULTILINE)
                new_content = pattern.sub(change["replacement"], new_content)
                
            if "append_if_not_found" in change and change["append_if_not_found"] not in new_content:
                new_content = f"{new_content}\n{change['append_if_not_found']}"

        if new_content != content:
            with open(file_path, 'w') as f:
                f.write(new_content)
            result["changes_made"].append(f"Updated {file_path}")

        # Restart service if required
        if "service_restart" in remediation:
            await self._restart_service(remediation["service_restart"])
            result["changes_made"].append(f"Restarted service {remediation['service_restart']}")

    async def _handle_service_config(self, remediation: Dict[str, Any], result: Dict[str, Any]):
        """Handle service configuration remediation"""
        await self._handle_file_edit(remediation, result)
        
        # Ensure service is enabled and running
        service = remediation["service"]
        await self._enable_service(service)
        result["changes_made"].append(f"Enabled service {service}")

    async def _update_config_file(self, file_path: str, settings: Dict[str, str], result: Dict[str, Any]):
        """Update configuration file with new settings"""
        with open(file_path, 'r') as f:
            lines = f.readlines()

        # Update existing settings or add new ones
        updated_lines = []
        settings_found = set()

        for line in lines:
            line = line.strip()
            if '=' in line:
                key = line.split('=')[0].strip()
                if key in settings:
                    updated_lines.append(f"{key} = {settings[key]}")
                    settings_found.add(key)
                    result["changes_made"].append(f"Updated {key} in {file_path}")
                else:
                    updated_lines.append(line)
            else:
                updated_lines.append(line)

        # Add missing settings
        for key, value in settings.items():
            if key not in settings_found:
                updated_lines.append(f"{key} = {value}")
                result["changes_made"].append(f"Added {key} to {file_path}")

        with open(file_path, 'w') as f:
            f.write('\n'.join(updated_lines))

    async def _restart_service(self, service: str):
        """Restart a system service"""
        process = await asyncio.create_subprocess_exec(
            "systemctl", "restart", service,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

    async def _enable_service(self, service: str):
        """Enable a system service"""
        process = await asyncio.create_subprocess_exec(
            "systemctl", "enable", service,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await process.communicate()

    async def _get_plan(self, plan_id: str) -> Dict[str, Any]:
        """Get remediation plan from database"""
        # This method would need to be implemented in the DatabaseManager
        # For now, we'll assume it exists
        return await self.db.get_remediation_plan(plan_id) 