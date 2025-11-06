import sqlite3
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from .consent_collector import ConsentCollector  # your existing collector


class DetectionPipeline:
    def __init__(
        self,
        consent_collector: ConsentCollector,
        permission_db: str = "permission_analysis.db",
        state_db: str = "detection_state.db",
    ):
        self.collector = consent_collector
        self.permission_db = permission_db
        self.state_db = state_db
        self._init_state_db()

    ## Initialize state database
    def _init_state_db(self):
        conn = sqlite3.connect(self.state_db)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id TEXT UNIQUE,
                display_name TEXT,
                publisher_domain TEXT,
                type TEXT,
                total_risk REAL,
                risk_level TEXT,
                permissions TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS run_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_apps INTEGER,
                new_apps INTEGER,
                changed_apps INTEGER
            )
        """)
        conn.commit()
        conn.close()

    # Look up risk score for a permission
    def _get_permission_risk(self, permission_name: str) -> Optional[int]:
        conn = sqlite3.connect(self.permission_db)
        cur = conn.cursor()
        cur.execute(
            "SELECT risk_score FROM permission_analysis WHERE permission_name = ?",
            (permission_name,),
        )
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None

    # Calculate total risk for an app
    def _calculate_app_risk(self, permissions: List[str]) -> Tuple[float, str]:
        """Compute mean or cumulative risk score."""
        scores = [self._get_permission_risk(p) for p in permissions]
        scores = [s for s in scores if s is not None]
        if not scores:
            return 0, "low"
        avg = sum(scores) / len(scores)
        if avg >= 4.5:
            level = "critical"
        elif avg >= 3.5:
            level = "high"
        elif avg >= 2.0:
            level = "medium"
        else:
            level = "low"
        return avg, level

    # Insert or update app record in state DB
    def _upsert_app(
        self,
        app_id: str,
        display_name: str,
        publisher_domain: str,
        app_type: str,
        total_risk: float,
        risk_level: str,
        permissions: List[str],
    ):
        conn = sqlite3.connect(self.state_db)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO applications (app_id, display_name, publisher_domain, type, total_risk, risk_level, permissions, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_id)
            DO UPDATE SET
                total_risk = excluded.total_risk,
                risk_level = excluded.risk_level,
                permissions = excluded.permissions,
                last_seen = excluded.last_seen
            """,
            (
                app_id,
                display_name,
                publisher_domain,
                app_type,
                total_risk,
                risk_level,
                json.dumps(permissions),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        conn.close()

    def run_detection(self):
        logging.info("Collecting internal and external consents...")

        internal = self.collector.collect_internal_consents()
        external = self.collector.collect_external_consents()

        new_apps, changed_apps = 0, 0
        total = len(internal) + len(external)

        for app in internal:
            permissions = list(
                {
                    ra["value"]
                    for res in app["requiredResourceAccess"]
                    for ra in res.get("resourceAccess", [])
                    if ra.get("value")
                }
            )
            total_risk, risk_level = self._calculate_app_risk(permissions)
            self._upsert_app(
                app["appId"],
                app.get("displayName", ""),
                app.get("publisherDomain", ""),
                "internal",
                total_risk,
                risk_level,
                permissions,
            )

        for app in external:
            total_risk, risk_level = self._calculate_app_risk(app.permissions)
            self._upsert_app(
                app.app_id,
                app.display_name or "",
                "",
                "external",
                total_risk,
                risk_level,
                app.permissions,
            )

        conn = sqlite3.connect(self.state_db)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO run_metadata (total_apps, new_apps, changed_apps) VALUES (?, ?, ?)",
            (total, new_apps, changed_apps),
        )
        conn.commit()
        conn.close()

        logging.info(f"Detection completed for {total} apps.")
