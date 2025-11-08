# detection_pipeline.py
import sqlite3
import json
import logging
from datetime import datetime
from typing import List, Tuple, Optional, Dict, Any

from .consent_collector import ConsentCollector
from .alert_notification import SlackNotifier  # expects a simple webhook-based notifier

LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class DetectionPipeline:
    def __init__(
        self,
        consent_collector: ConsentCollector,
        permission_db: str = "permission_analysis.db",
        state_db: str = "detection_state.db",
        slack_webhook_url: Optional[str] = None,
        alert_threshold_level: str = "medium",
        top_perm_count: int = 3,
        spike_score: int = 5,
        spike_multi_count: int = 2,
        spike_bypass_threshold: bool = True,
        alert_once_per_app: bool = True,
    ):
        self.collector = consent_collector
        self.permission_db = permission_db
        self.state_db = state_db
        self.top_perm_count = top_perm_count

        self.slack = SlackNotifier(slack_webhook_url)
        if alert_threshold_level not in LEVEL_ORDER:
            raise ValueError("Invalid alert_threshold_level")
        self.alert_threshold_level = alert_threshold_level

        self.spike_score = spike_score
        self.spike_multi_count = spike_multi_count
        self.spike_bypass_threshold = spike_bypass_threshold
        self.alert_once_per_app = alert_once_per_app

        self._init_state_db()
        self._risk_cache = self._load_risk_cache()

    # ------------------- DB bootstrap -------------------
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

    # ------------------- Risk cache -------------------
    def _load_risk_cache(self) -> Dict[str, Dict[str, Any]]:
        """
        Load all rows from permission_analysis into an in-memory cache.
        No aggregation, no deduplication — direct mapping of last-seen rows.
        """
        sql = "SELECT permission_name, risk_score, COALESCE(reasoning,'') FROM permission_analysis"
        conn = sqlite3.connect(self.permission_db)
        cur = conn.cursor()
        cur.execute(sql)
        cache = {}
        for name, score, reason in cur.fetchall():
            if name:
                cache[name.strip().lower()] = {
                    "score": int(score),
                    "reason": reason or "",
                }
        conn.close()
        return cache

    # ------------------- Risk lookups (cache-only) -------------------
    def _get_permission_risk_rows(
        self, permission_names: List[str]
    ) -> List[Tuple[str, int, str]]:
        rows = []
        for p in permission_names or []:
            v = self._risk_cache.get(p.strip().lower())
            if v:
                rows.append((p, v["score"], v["reason"]))
        return rows

    def _get_permission_risk(self, permission_name: str) -> Optional[int]:
        v = self._risk_cache.get(permission_name.strip().lower())
        return v["score"] if v else None

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

    # ------------------- State helpers -------------------
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

    # ------------------- Alert helpers -------------------
    def _level_meets_threshold(self, level: str) -> bool:
        return LEVEL_ORDER.get(level, 0) >= LEVEL_ORDER[self.alert_threshold_level]

    def _top_risky_permissions(
        self, permissions: List[str], k: int
    ) -> List[Tuple[str, int, str]]:
        rows = self._get_permission_risk_rows(permissions)
        rows.sort(key=lambda t: t[1], reverse=True)
        return rows[:k]

    def _send_slack_alert(
        self,
        *,
        event: str,
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
            f"• *{n}* (risk {s}) — {r}" if r else f"• *{n}* (risk {s})"
            for (n, s, r) in top
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
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top risky permissions:*\n" + "\n".join(top_lines),
                },
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "_Automated detection pipeline_"}
                ],
            },
        ]

        if delta_info:
            blocks.insert(
                2,
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Change:* {delta_info}"},
                },
            )

        plain = f"{title}\nApp: {app_name} ({app_id})\nRisk: {risk_level} ({total_risk:.2f})\n{delta_info}"
        self.slack.send(text=plain, blocks=blocks)

    # ------------------- Spike logic -------------------
    def _risk_stats(self, permissions: List[str]) -> Dict[str, Any]:
        rows = self._get_permission_risk_rows(permissions)
        scores = {n: s for (n, s, _) in rows}
        max_score = max(scores.values()) if scores else 0
        count_spike = sum(1 for s in scores.values() if s == self.spike_score)
        return {
            "scores": scores,
            "max": max_score,
            "count_spike": count_spike,
            "has_spike": count_spike >= 1,
            "multi_spike": count_spike >= self.spike_multi_count,
            "spike_perms": sorted(
                [n for n, s in scores.items() if s == self.spike_score]
            ),
        }

    def _maybe_send_spike_alerts(
        self,
        *,
        app_id: str,
        app_name: str,
        app_type: str,
        publisher_domain: str,
        current_perms: List[str],
        previous_perms: Optional[List[str]],
        risk_level: str,
        total_risk: float,
    ) -> bool:
        cur = self._risk_stats(current_perms)
        prev = self._risk_stats(previous_perms or [])

        def _gate():
            return (
                True
                if self.spike_bypass_threshold
                else self._level_meets_threshold(risk_level)
            )

        if cur["multi_spike"] and (
            prev["count_spike"] < self.spike_multi_count
            or cur["count_spike"] > prev["count_spike"]
        ):
            if _gate():
                self._send_slack_alert(
                    event="spike_multiple",
                    app_id=app_id,
                    app_name=app_name,
                    app_type=app_type,
                    publisher_domain=publisher_domain,
                    risk_level=risk_level,
                    total_risk=total_risk,
                    permissions=current_perms,
                    delta_info=f"Spike permissions increased: {prev['count_spike']} → {cur['count_spike']}. "
                    f"Spike value={self.spike_score}; perms: {', '.join(cur['spike_perms']) or '—'}",
                )
                return True

        if cur["has_spike"] and not prev["has_spike"]:
            if _gate():
                self._send_slack_alert(
                    event="spike_present",
                    app_id=app_id,
                    app_name=app_name,
                    app_type=app_type,
                    publisher_domain=publisher_domain,
                    risk_level=risk_level,
                    total_risk=total_risk,
                    permissions=current_perms,
                    delta_info=f"Detected ≥1 permission with risk score {self.spike_score}. "
                    f"Perms: {', '.join(cur['spike_perms']) or '—'}",
                )
                return True
        return False

    # ------------------- Main run -------------------
    def run_detection(self):
        logging.info("Collecting internal and external consents...")
        internal = self.collector.collect_internal_consents()
        external = self.collector.collect_external_consents()

        total = len(internal) + len(external)
        new_apps = 0
        changed_apps = 0

        def process_app(app_id, display_name, app_type, publisher_domain, permissions):
            nonlocal new_apps, changed_apps
            total_risk, risk_level = self._calculate_app_risk(permissions)
            existing = self._get_existing_app(app_id)
            is_new = existing is None
            prev_perms = existing.get("permissions", []) if existing else []

            sent = self._maybe_send_spike_alerts(
                app_id=app_id,
                app_name=display_name,
                app_type=app_type,
                publisher_domain=publisher_domain,
                current_perms=permissions,
                previous_perms=prev_perms,
                risk_level=risk_level,
                total_risk=total_risk,
            )

            if not (self.alert_once_per_app and sent):
                if is_new and self._level_meets_threshold(risk_level):
                    new_apps += 1
                    self._send_slack_alert(
                        event="new",
                        app_id=app_id,
                        app_name=display_name,
                        app_type=app_type,
                        publisher_domain=publisher_domain,
                        risk_level=risk_level,
                        total_risk=total_risk,
                        permissions=permissions,
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
                            app_name=display_name,
                            app_type=app_type,
                            publisher_domain=publisher_domain,
                            risk_level=risk_level,
                            total_risk=total_risk,
                            permissions=permissions,
                            delta_info=f"Risk tier increased: {prev_level} → {risk_level}",
                        )
                    else:
                        gained = sorted(set(permissions) - set(prev_perms))
                        if gained and self._level_meets_threshold(risk_level):
                            changed_apps += 1
                            self._send_slack_alert(
                                event="perm_added",
                                app_id=app_id,
                                app_name=display_name,
                                app_type=app_type,
                                publisher_domain=publisher_domain,
                                risk_level=risk_level,
                                total_risk=total_risk,
                                permissions=permissions,
                                delta_info=f"New permissions granted: {', '.join(gained)}",
                            )

            self._upsert_app(
                app_id,
                display_name,
                publisher_domain,
                app_type,
                total_risk,
                risk_level,
                permissions,
            )

        for app in internal:
            app_id = app["appId"]
            perms = sorted(
                {
                    ra["value"]
                    for res in app.get("requiredResourceAccess", [])
                    for ra in res.get("resourceAccess", [])
                    if ra.get("value")
                }
            )
            process_app(
                app_id,
                app.get("displayName", ""),
                "internal",
                app.get("publisherDomain", ""),
                perms,
            )

        for app in external:
            process_app(
                app.app_id,
                app.display_name or "",
                "external",
                "",
                sorted(set(app.permissions)),
            )

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
