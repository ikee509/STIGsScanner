import asyncio
import logging
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

from .scanners import (
    FilePermissionScanner,
    ServiceScanner,
    SecurityConfigScanner,
    UserGroupScanner,
    NetworkScanner,
    SoftwareScanner
)
from .remediation import RemediationManager
from .database import DatabaseManager
from .reporting import ReportGenerator
from .utils import setup_logging, encrypt_data, decrypt_data

class STIGAgent:
    def __init__(self, config_path: str = "/etc/stig-agent/config.json"):
        self.config = self._load_config(config_path)
        self.logger = setup_logging(self.config.get("log_level", "INFO"))
        self.db = DatabaseManager(self.config["database_path"])
        self.remediation_mgr = RemediationManager(self.db)
        
        # Initialize scanners
        self.scanners = {
            "file_permissions": FilePermissionScanner(),
            "services": ServiceScanner(),
            "security_config": SecurityConfigScanner(),
            "users_groups": UserGroupScanner(),
            "network": NetworkScanner(),
            "software": SoftwareScanner()
        }

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load agent configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            sys.exit(f"Failed to load configuration: {str(e)}")

    async def run_scan(self) -> Dict[str, Any]:
        """Run all STIG compliance scans"""
        self.logger.info("Starting STIG compliance scan")
        scan_results = {
            "timestamp": datetime.now().isoformat(),
            "hostname": os.uname()[1],
            "findings": []
        }

        for scanner_name, scanner in self.scanners.items():
            try:
                self.logger.info(f"Running {scanner_name} scan")
                results = await scanner.scan()
                scan_results["findings"].extend(results)
            except Exception as e:
                self.logger.error(f"Error in {scanner_name} scan: {str(e)}")

        # Store results in database
        await self.db.store_scan_results(scan_results)
        return scan_results

    async def generate_remediation_plan(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate remediation plan for scan findings"""
        return await self.remediation_mgr.create_plan(scan_results)

    async def execute_remediation(self, plan_id: str, approved_items: List[str]) -> Dict[str, Any]:
        """Execute approved remediation items"""
        return await self.remediation_mgr.execute_plan(plan_id, approved_items)

    async def generate_report(self, scan_id: str, format: str = "json") -> str:
        """Generate compliance report"""
        report_gen = ReportGenerator()
        scan_data = await self.db.get_scan_results(scan_id)
        return await report_gen.generate(scan_data, format)

    async def start(self):
        """Start the agent service"""
        self.logger.info("Starting STIG Agent service")
        while True:
            try:
                # Run scan based on configured schedule
                if self._should_run_scan():
                    scan_results = await self.run_scan()
                    
                    # Generate remediation plan
                    plan = await self.generate_remediation_plan(scan_results)
                    
                    # Generate and store report
                    report = await self.generate_report(scan_results["scan_id"])
                    
                    # Send results to central server if configured
                    if self.config.get("central_server"):
                        await self._send_results_to_server(scan_results)

                await asyncio.sleep(self.config.get("scan_interval", 3600))
            except Exception as e:
                self.logger.error(f"Error in agent main loop: {str(e)}")
                await asyncio.sleep(60)  # Wait before retry

    def _should_run_scan(self) -> bool:
        """Check if scan should be run based on schedule"""
        # Implement scheduling logic here
        return True

    async def _send_results_to_server(self, results: Dict[str, Any]):
        """Send scan results to central management server"""
        if not self.config.get("central_server"):
            return

        try:
            # Implement secure communication with central server
            encrypted_data = encrypt_data(results, self.config["server_public_key"])
            # Send data to server
            # TODO: Implement server communication
        except Exception as e:
            self.logger.error(f"Failed to send results to server: {str(e)}")

def main():
    """Main entry point for the STIG agent"""
    agent = STIGAgent()
    
    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        print("\nStopping STIG Agent...")
    except Exception as e:
        print(f"Error running STIG Agent: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 