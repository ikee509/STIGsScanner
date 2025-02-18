import sqlite3
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
import aiosqlite
import logging

class DatabaseManager:
    """Manages all database operations for the STIG agent"""
    
    def __init__(self, db_path: str = "/var/lib/stig-agent/stig.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self._ensure_db_directory()
        self._init_database()

    def _ensure_db_directory(self) -> None:
        """Ensure the database directory exists"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

    def _init_database(self) -> None:
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)

            # Create remediation_plans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_plans (
                    plan_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    items TEXT NOT NULL,
                    status TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
                )
            """)

            # Create remediation_history table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_history (
                    execution_id TEXT PRIMARY KEY,
                    plan_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    items TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result TEXT,
                    FOREIGN KEY (plan_id) REFERENCES remediation_plans (plan_id)
                )
            """)

            conn.commit()

    async def store_scan_results(self, scan_results: Dict[str, Any]) -> str:
        """Store scan results in the database"""
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{scan_results['hostname']}"
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO scans (scan_id, timestamp, hostname, findings, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    scan_results["timestamp"],
                    scan_results["hostname"],
                    json.dumps(scan_results["findings"]),
                    "completed"
                )
            )
            await db.commit()

        self.logger.info(f"Stored scan results with ID: {scan_id}")
        return scan_id

    async def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Retrieve scan results from the database"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,)
            ) as cursor:
                row = await cursor.fetchone()
                
                if not row:
                    raise ValueError(f"Scan ID {scan_id} not found")
                
                return {
                    "scan_id": row[0],
                    "timestamp": row[1],
                    "hostname": row[2],
                    "findings": json.loads(row[3]),
                    "status": row[4]
                }

    async def store_remediation_plan(self, plan: Dict[str, Any]) -> str:
        """Store remediation plan in the database"""
        plan_id = f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{plan['scan_id']}"
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO remediation_plans (plan_id, scan_id, timestamp, items, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    plan_id,
                    plan["scan_id"],
                    datetime.now().isoformat(),
                    json.dumps(plan["items"]),
                    "pending"
                )
            )
            await db.commit()

        self.logger.info(f"Stored remediation plan with ID: {plan_id}")
        return plan_id

    async def update_remediation_status(self, plan_id: str, status: str) -> None:
        """Update the status of a remediation plan"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE remediation_plans SET status = ? WHERE plan_id = ?",
                (status, plan_id)
            )
            await db.commit()

    async def store_remediation_execution(self, execution: Dict[str, Any]) -> str:
        """Store remediation execution results"""
        execution_id = f"exec_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{execution['plan_id']}"
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO remediation_history 
                (execution_id, plan_id, timestamp, items, status, result)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    execution_id,
                    execution["plan_id"],
                    datetime.now().isoformat(),
                    json.dumps(execution["items"]),
                    execution["status"],
                    json.dumps(execution.get("result", {}))
                )
            )
            await db.commit()

        self.logger.info(f"Stored remediation execution with ID: {execution_id}")
        return execution_id

    async def get_remediation_history(self, plan_id: str) -> List[Dict[str, Any]]:
        """Retrieve remediation history for a plan"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT * FROM remediation_history WHERE plan_id = ? ORDER BY timestamp DESC",
                (plan_id,)
            ) as cursor:
                rows = await cursor.fetchall()
                
                return [{
                    "execution_id": row[0],
                    "plan_id": row[1],
                    "timestamp": row[2],
                    "items": json.loads(row[3]),
                    "status": row[4],
                    "result": json.loads(row[5]) if row[5] else None
                } for row in rows]

    async def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Retrieve recent scan results"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ) as cursor:
                rows = await cursor.fetchall()
                
                return [{
                    "scan_id": row[0],
                    "timestamp": row[1],
                    "hostname": row[2],
                    "findings": json.loads(row[3]),
                    "status": row[4]
                } for row in rows]

    async def cleanup_old_data(self, days: int = 90) -> None:
        """Clean up old scan and remediation data"""
        cutoff_date = (datetime.now() - datetime.timedelta(days=days)).isoformat()
        
        async with aiosqlite.connect(self.db_path) as db:
            # Delete old remediation history
            await db.execute(
                "DELETE FROM remediation_history WHERE timestamp < ?",
                (cutoff_date,)
            )
            
            # Delete old remediation plans
            await db.execute(
                "DELETE FROM remediation_plans WHERE timestamp < ?",
                (cutoff_date,)
            )
            
            # Delete old scans
            await db.execute(
                "DELETE FROM scans WHERE timestamp < ?",
                (cutoff_date,)
            )
            
            await db.commit()
            
        self.logger.info(f"Cleaned up data older than {days} days") 