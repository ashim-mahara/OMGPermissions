# detection_pipeline.py
import sqlite3
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
from .consent_collector import ConsentCollector
from .alert_notification import SlackNotifier

LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class DetectionPipeline:
    def __init__(
        self,
        consent_collector: ConsentCollector,
        permission_db: str = "permission_analysis.db",
        state_db: str = "detection_state.db",
        slack_webhook_url: str | None = None,
        alert_threshold_level: str = "high",  # alert at/above this tier
        top_perm_count: int = 3,  # number of perms to show in alert
    ):
        self.collector = consent_collector
        self.permission_db = permission_db
        self.state_db = state_db
        self.top_perm_count = top_perm_count
        self._init_state_db()
        self.slack = SlackNotifier(slack_webhook_url)
        if alert_threshold_level not in LEVEL_ORDER:
            raise ValueError("Invalid alert threshold")
        self.alert_threshold_level = alert_threshold_level

    # Setup database tables
    def _init_state_db(self):
        conn = sqlite3.connect(self.state_db)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id TEXT UNIQUE,
                display_name TEXT,
                publisher_domain TEXT,
                type TEXT, -- internal | external
                total_risk REAL,
                risk_level TEXT,
                permissions TEXT, -- JSON array
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

    # Lookup risk scores for permissions
    def _get_permission_risk_rows(
        self, permission_names: List[str]
    ) -> List[Tuple[str, int, str]]:
        if not permission_names:
            return []
        q_marks = ",".join(["?"] * len(permission_names))
        sql = f"SELECT permission_name, risk_score, COALESCE(reasoning,'') FROM permission_analysis WHERE permission_name IN ({q_marks})"
        conn = sqlite3.connect(self.permission_db)
        cur = conn.cursor()
        cur.execute(sql, permission_names)
        rows = cur.fetchall()
        conn.close()
        return rows  # (name, score, reasoning)

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

    # ------------------- Risk Calculation -------------------
    def _calculate_app_risk(self, permissions: List[str]) -> Tuple[float, str]:
        scores = [self._get_permission_risk(p) for p in permissions]
        scores = [s for s in scores if s is not None]
        if not scores:
            return 0.0, "low"
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

    # DB utilities
    def _get_existing_app(self, app_id: str) -> Optional[dict]:
        conn = sqlite3.connect(self.state_db)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT app_id, display_name, publisher_domain, type, total_risk, risk_level, permissions
            FROM applications WHERE app_id = ?
        """,
            (app_id,),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        perms = []
        try:
            perms = json.loads(row[6]) if row[6] else []
        except Exception:
            perms = []
        return {
            "app_id": row[0],
            "display_name": row[1],
            "publisher_domain": row[2],
            "type": row[3],
            "total_risk": row[4],
            "risk_level": row[5],
            "permissions": perms,
        }

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
                display_name = excluded.display_name,
                publisher_domain = excluded.publisher_domain,
                type = excluded.type,
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
                json.dumps(sorted(set(permissions))),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        conn.close()

    # alerting utilities
    def _level_meets_threshold(self, level: str) -> bool:
        return LEVEL_ORDER.get(level, 0) >= LEVEL_ORDER[self.alert_threshold_level]

    def _top_risky_permissions(
        self, permissions: List[str], k: int
    ) -> List[Tuple[str, int, str]]:
        rows = self._get_permission_risk_rows(permissions)
        rows.sort(key=lambda t: (t[1] if t[1] is not None else -1), reverse=True)
        # ensure only known perms with scores are shown
        filtered = [(n, s, r) for (n, s, r) in rows if s is not None]
        return filtered[:k]

    def _send_slack_alert(
        self,
        event: str,  # "new", "tier_increase", "perm_added"
        app_id: str,
        app_name: str,
        app_type: str,
        publisher_domain: str,
        risk_level: str,
        total_risk: float,
        permissions: List[str],
        delta_info: str = "",
    ):
        if not self.slack.enabled():
            return

        top = self._top_risky_permissions(permissions, self.top_perm_count)
        top_lines = [
            f"• *{name}* (risk {score})" + (f" — {reason}" if reason else "")
            for name, score, reason in top
        ] or ["• No scored permissions found"]

        title_emoji = (
            ":rotating_light:" if risk_level in ("high", "critical") else ":warning:"
        )
        title = f"{title_emoji} {event.replace('_', ' ').title()} — {app_name or 'Unknown App'}"

        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*App ID:*\n`{app_id}`"},
                    {"type": "mrkdwn", "text": f"*Type:*\n{app_type}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Publisher:*\n{publisher_domain or '—'}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk:*\n{risk_level} ({total_risk:.2f})",
                    },
                ],
            },
        ]
        if delta_info:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Change:* {delta_info}"},
                }
            )
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top risky permissions:*\n" + "\n".join(top_lines),
                },
            }
        )
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "_Automated detection pipeline_"}
                ],
            }
        )

        plain = f"{title}\nApp: {app_name} ({app_id})\nRisk: {risk_level} ({total_risk:.2f})\n{delta_info}"
        self.slack.send(text=plain, blocks=blocks)

    # main detection run
    def run_detection(self):
        logging.info("Collecting internal and external consents...")

        internal = self.collector.collect_internal_consents()
        external = self.collector.collect_external_consents()

        total = len(internal) + len(external)
        new_apps = 0
        changed_apps = 0

        # internal application
        for app in internal:
            current_perms = sorted(
                {
                    ra["value"]
                    for res in app.get("requiredResourceAccess", [])
                    for ra in res.get("resourceAccess", [])
                    if ra.get("value")
                }
            )
            total_risk, risk_level = self._calculate_app_risk(current_perms)

            app_id = app["appId"]
            existing = self._get_existing_app(app_id)
            is_new = existing is None
            gained_perms: list[str] = []

            if not is_new:
                prev_perms = set(existing.get("permissions", []))
                gained_perms = sorted(set(current_perms) - prev_perms)

            # Alert decisions
            if is_new and self._level_meets_threshold(risk_level):
                new_apps += 1
                self._send_slack_alert(
                    event="new",
                    app_id=app_id,
                    app_name=app.get("displayName", ""),
                    app_type="internal",
                    publisher_domain=app.get("publisherDomain", ""),
                    risk_level=risk_level,
                    total_risk=total_risk,
                    permissions=current_perms,
                    delta_info="New application observed.",
                )
            elif not is_new:
                prev_level = existing.get("risk_level", "low")
                if LEVEL_ORDER.get(risk_level, 0) > LEVEL_ORDER.get(
                    prev_level, 0
                ) and self._level_meets_threshold(risk_level):
                    changed_apps += 1
                    self._send_slack_alert(
                        event="tier_increase",
                        app_id=app_id,
                        app_name=app.get("displayName", ""),
                        app_type="internal",
                        publisher_domain=app.get("publisherDomain", ""),
                        risk_level=risk_level,
                        total_risk=total_risk,
                        permissions=current_perms,
                        delta_info=f"Risk tier increased: {prev_level} → {risk_level}",
                    )
                elif gained_perms and self._level_meets_threshold(risk_level):
                    changed_apps += 1
                    self._send_slack_alert(
                        event="perm_added",
                        app_id=app_id,
                        app_name=app.get("displayName", ""),
                        app_type="internal",
                        publisher_domain=app.get("publisherDomain", ""),
                        risk_level=risk_level,
                        total_risk=total_risk,
                        permissions=current_perms,
                        delta_info=f"New permissions granted: {', '.join(gained_perms)}",
                    )

            # persist
            self._upsert_app(
                app_id=app_id,
                display_name=app.get("displayName", ""),
                publisher_domain=app.get("publisherDomain", ""),
                app_type="internal",
                total_risk=total_risk,
                risk_level=risk_level,
                permissions=current_perms,
            )

        # External applications
        for app in external:
            current_perms = sorted(set(app.permissions))
            total_risk, risk_level = self._calculate_app_risk(current_perms)

            app_id = app.app_id
            existing = self._get_existing_app(app_id)
            is_new = existing is None
            gained_perms: list[str] = []
            if not is_new:
                prev_perms = set(existing.get("permissions", []))
                gained_perms = sorted(set(current_perms) - prev_perms)

            if is_new and self._level_meets_threshold(risk_level):
                new_apps += 1
                self._send_slack_alert(
                    event="new",
                    app_id=app_id,
                    app_name=app.display_name or "",
                    app_type="external",
                    publisher_domain="",
                    risk_level=risk_level,
                    total_risk=total_risk,
                    permissions=current_perms,
                    delta_info="New external application observed.",
                )
            elif not is_new:
                prev_level = existing.get("risk_level", "low")
                if LEVEL_ORDER.get(risk_level, 0) > LEVEL_ORDER.get(
                    prev_level, 0
                ) and self._level_meets_threshold(risk_level):
                    changed_apps += 1
                    self._send_slack_alert(
                        event="tier_increase",
                        app_id=app_id,
                        app_name=app.display_name or "",
                        app_type="external",
                        publisher_domain="",
                        risk_level=risk_level,
                        total_risk=total_risk,
                        permissions=current_perms,
                        delta_info=f"Risk tier increased: {prev_level} → {risk_level}",
                    )
                elif gained_perms and self._level_meets_threshold(risk_level):
                    changed_apps += 1
                    self._send_slack_alert(
                        event="perm_added",
                        app_id=app_id,
                        app_name=app.display_name or "",
                        app_type="external",
                        publisher_domain="",
                        risk_level=risk_level,
                        total_risk=total_risk,
                        permissions=current_perms,
                        delta_info=f"New permissions granted: {', '.join(gained_perms)}",
                    )

            self._upsert_app(
                app_id=app_id,
                display_name=app.display_name or "",
                publisher_domain="",
                app_type="external",
                total_risk=total_risk,
                risk_level=risk_level,
                permissions=current_perms,
            )

        # run metadata
        conn = sqlite3.connect(self.state_db)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO run_metadata (total_apps, new_apps, changed_apps) VALUES (?, ?, ?)",
            (total, new_apps, changed_apps),
        )
        conn.commit()
        conn.close()

        logging.info(
            f"Detection completed. total={total} new={new_apps} changed={changed_apps}"
        )
