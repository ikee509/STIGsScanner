import aiosqlite
import json
from datetime import datetime
from typing import Dict, List, Any
import logging
from pathlib import Path

class DatabaseManager:
    """Database manager for the central server"""
    
    def __init__(self, db_path: str = "/var/lib/stig-central/central.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):
        """Initialize the database schema"""
        with aiosqlite.connect(self.db_path) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    host_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            """)

            db.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    result_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    FOREIGN KEY (host_id) REFERENCES hosts (host_id)
                )
            """)

            db.execute("""
                CREATE TABLE IF NOT EXISTS remediation_plans (
                    plan_id TEXT PRIMARY KEY,
                    host_id TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    items TEXT NOT NULL,
                    FOREIGN KEY (host_id) REFERENCES hosts (host_id),
                    FOREIGN KEY (result_id) REFERENCES scan_results (result_id)
                )
            """)

    async def store_scan_results(self, results: Dict[str, Any]) -> str:
        """Store scan results from an agent"""
        result_id = f"result_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{results['hostname']}"
        
        async with aiosqlite.connect(self.db_path) as db:
            # Update or insert host
            await db.execute("""
                INSERT OR REPLACE INTO hosts (host_id, hostname, last_seen, status)
                VALUES (?, ?, ?, ?)
            """, (
                results['hostname'],
                results['hostname'],
                datetime.now().isoformat(),
                'active'
            ))

            # Store scan results
            await db.execute("""
                INSERT INTO scan_results (result_id, host_id, timestamp, findings)
                VALUES (?, ?, ?, ?)
            """, (
                result_id,
                results['hostname'],
                results['timestamp'],
                json.dumps(results['findings'])
            ))

            await db.commit()

        return result_id

    async def get_host_results(self, hostname: str) -> List[Dict[str, Any]]:
        """Get scan results for a specific host"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT result_id, timestamp, findings
                FROM scan_results
                WHERE host_id = ?
                ORDER BY timestamp DESC
            """, (hostname,)) as cursor:
                results = await cursor.fetchall()
                
                return [{
                    "result_id": row[0],
                    "timestamp": row[1],
                    "findings": json.loads(row[2])
                } for row in results]

    async def get_summary(self) -> Dict[str, Any]:
        """Get summary of all hosts"""
        async with aiosqlite.connect(self.db_path) as db:
            # Get host count
            async with db.execute("SELECT COUNT(*) FROM hosts") as cursor:
                host_count = (await cursor.fetchone())[0]

            # Get recent scans
            async with db.execute("""
                SELECT h.hostname, s.timestamp, s.findings
                FROM hosts h
                JOIN scan_results s ON h.host_id = s.host_id
                ORDER BY s.timestamp DESC
                LIMIT 10
            """) as cursor:
                recent_scans = [{
                    "hostname": row[0],
                    "timestamp": row[1],
                    "findings": json.loads(row[2])
                } for row in await cursor.fetchall()]

            return {
                "total_hosts": host_count,
                "recent_scans": recent_scans
            } 