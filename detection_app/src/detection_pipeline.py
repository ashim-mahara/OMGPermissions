# detection_pipeline.py
import sqlite3
import json
import logging
import math
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
        alert_threshold_level: str = "medium",  # fire standard alerts at/above this tier
        top_perm_count: int = 3,  # how many perms to list in alerts
        # ---- spike rule options ----
        spike_score: int = 5,  # which risk score constitutes a "spike"
        spike_multi_count: int = 2,  # how many spikes before "multiple" alert
        spike_bypass_threshold: bool = True,  # allow spike alerts regardless of tier threshold
        alert_once_per_app: bool = True,  # collapse to one alert per app per run
        # ---- aggregation options ----
        gm_order: float = 3.0,  # generalized-mean order (3.0=Cubic). Supports 0 (geometric), +/-inf, negatives.
    ):
        self.collector = consent_collector
        self.permission_db = permission_db
        self.state_db = state_db
        self.top_perm_count = top_perm_count

        # Alerts
        self.slack = SlackNotifier(slack_webhook_url)
        if alert_threshold_level not in LEVEL_ORDER:
            raise ValueError("Invalid alert_threshold_level")
        self.alert_threshold_level = alert_threshold_level

        # Spike policy
        self.spike_score = spike_score
        self.spike_multi_count = spike_multi_count
        self.spike_bypass_threshold = spike_bypass_threshold
        self.alert_once_per_app = alert_once_per_app

        # Aggregation
        self.gm_order = gm_order

        self._init_state_db()
        self._risk_cache = self._load_risk_cache()  # in-memory cache for all lookups

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

    # ------------------- Risk cache -------------------
    def _load_risk_cache(self) -> Dict[str, Dict[str, Any]]:
        """
        Load all rows from permission_analysis into an in-memory cache.
        No aggregation/dedup: last-seen row for a given key wins.
        """
        sql = "SELECT permission_name, risk_score, COALESCE(reasoning,'') FROM permission_analysis"
        conn = sqlite3.connect(self.permission_db)
        cur = conn.cursor()
        cur.execute(sql)
        cache: Dict[str, Dict[str, Any]] = {}
        for name, score, reason in cur.fetchall():
            if not name:
                continue
            try:
                sc = int(score)
            except Exception:
                continue
            cache[name.strip().lower()] = {"score": sc, "reason": reason or ""}
        conn.close()
        return cache

    # ------------------- Risk lookups (cache-only) -------------------
    def _get_permission_risk_rows(
        self, permission_names: List[str]
    ) -> List[Tuple[str, int, str]]:
        """
        Return (permission_name, risk_score, reasoning) using ONLY the in-memory cache.
        Any names not found in cache are omitted.
        """
        if not permission_names:
            return []
        rows: List[Tuple[str, int, str]] = []
        for p in permission_names:
            v = self._risk_cache.get(p.strip().lower())
            if v and v.get("score") is not None:
                rows.append((p, int(v["score"]), v.get("reason", "")))
        return rows

    def _get_permission_risk(self, permission_name: str) -> Optional[int]:
        v = self._risk_cache.get(permission_name.strip().lower())
        return int(v["score"]) if v and v.get("score") is not None else None

    # ------------------- Aggregation -------------------
    def _generalized_mean(self, values: List[float], p: float) -> float:
        """
        Generalized mean (power mean) of positive values.
          p = 1   -> arithmetic
          p = 2   -> quadratic / RMS
          p = 0   -> geometric
          p = -1  -> harmonic
          p -> +inf -> max
          p -> -inf -> min
        """
        n = len(values)
        if n == 0:
            return 0.0

        # Defensive: ensure positivity for geometric/log; risk scores are 1..5, but clamp anyway.
        eps = 1e-12
        vals = [max(float(v), eps) for v in values]

        if math.isinf(p):
            return max(vals) if p > 0 else min(vals)
        if p == 0.0:
            # geometric mean
            return math.exp(sum(math.log(v) for v in vals) / n)
        # general case
        try:
            return (sum(v**p for v in vals) / n) ** (1.0 / p)
        except OverflowError:
            # Fall back gracefully on extreme p by approximating with max/min
            return max(vals) if p > 0 else min(vals)

    def _calculate_app_risk(self, permissions: List[str]) -> Tuple[float, str]:
        """
        Aggregate permission risks via generalized mean with order `self.gm_order`,
        then map to tiers.
        """
        scores = [self._get_permission_risk(p) for p in permissions]
        scores = [float(s) for s in scores if s is not None]
        if not scores:
            return 0.0, "low"

        agg = self._generalized_mean(scores, self.gm_order)

        # Tier mapping (unchanged thresholds; adjust if you tune gm_order)
        if agg >= 4.5:
            level = "critical"
        elif agg >= 3.5:
            level = "high"
        elif agg >= 2.0:
            level = "medium"
        else:
            level = "low"
        return float(agg), level

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
        perms: List[str] = []
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
        """
        Top-k by score using cache only.
        Returns list of (name, score, reason).
        """
        rows = self._get_permission_risk_rows(permissions)
        rows.sort(key=lambda t: (t[1] if t[1] is not None else -1), reverse=True)
        return [(n, s, r) for (n, s, r) in rows if s is not None][:k]

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
            f"• *{name}* (risk {score})" + (f" — {reason}" if reason else "")
            for (name, score, reason) in top
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

    # ------------------- Spike logic (cache-backed) -------------------
    def _risk_stats(self, permissions: List[str]) -> Dict[str, Any]:
        """
        Compute spike-related stats from the in-memory cache for a set of permissions.
        Returns:
          - scores: dict[name] -> score
          - max: max score
          - count_spike: how many perms equal self.spike_score
          - has_spike: bool
          - multi_spike: bool (count >= spike_multi_count)
          - spike_perms: sorted list of permission names at spike score
        """
        rows = self._get_permission_risk_rows(permissions)  # (name, score, reasoning)
        scores = {name: score for (name, score, _) in rows if score is not None}
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
        app_type: str,  # "internal" | "external"
        publisher_domain: str,
        current_perms: List[str],
        previous_perms: Optional[List[str]],
        risk_level: str,
        total_risk: float,
    ) -> bool:
        """
        Evaluate and send spike alerts based on self.spike_score & self.spike_multi_count.
        Returns True if an alert was sent.
        """
        cur = self._risk_stats(current_perms)
        prev = self._risk_stats(previous_perms or [])

        def _gate() -> bool:
            return (
                True
                if self.spike_bypass_threshold
                else self._level_meets_threshold(risk_level)
            )

        # Most severe: reaching multiple spikes or spike count increased
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

        # First time any spike appears
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
        """
        Detection run with Slack alerts:
          - Spike alerts (spike_present / spike_multiple) via reusable method
          - Standard alerts (new / tier_increase / perm_added) honoring alert_threshold_level
          - Persists current app state and run metadata

        All permission risk lookups are served from the in-memory cache loaded at init.
        """
        logging.info("Collecting internal and external consents...")

        internal = self.collector.collect_internal_consents()
        external = (
            self.collector.collect_external_consents()
        )  # already your fixed resolver

        total = len(internal) + len(external)
        new_apps = 0
        changed_apps = 0

        # ---- INTERNAL APPS ----
        for app in internal:
            app_id = app["appId"]
            display_name = app.get("displayName", "")
            publisher_domain = app.get("publisherDomain", "")
            app_type = "internal"

            # Declared/requested perms (your current model)
            current_perms = sorted(
                {
                    ra["value"]
                    for res in app.get("requiredResourceAccess", [])
                    for ra in res.get("resourceAccess", [])
                    if ra.get("value")
                }
            )

            total_risk, risk_level = self._calculate_app_risk(current_perms)

            existing = self._get_existing_app(app_id)
            is_new = existing is None
            prev_perms = existing.get("permissions", []) if existing else []

            # Spike alerts (reusable)
            sent_alert = self._maybe_send_spike_alerts(
                app_id=app_id,
                app_name=display_name,
                app_type=app_type,
                publisher_domain=publisher_domain,
                current_perms=current_perms,
                previous_perms=prev_perms,
                risk_level=risk_level,
                total_risk=total_risk,
            )

            # Threshold-based alerts
            if not (self.alert_once_per_app and sent_alert):
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
                        permissions=current_perms,
                        delta_info="New application observed.",
                    )
                    sent_alert = True
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
                            permissions=current_perms,
                            delta_info=f"Risk tier increased: {prev_level} → {risk_level}",
                        )
                        sent_alert = True
                    else:
                        gained = sorted(set(current_perms) - set(prev_perms))
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
                                permissions=current_perms,
                                delta_info=f"New permissions granted: {', '.join(gained)}",
                            )
                            sent_alert = True

            # persist
            self._upsert_app(
                app_id=app_id,
                display_name=display_name,
                publisher_domain=publisher_domain,
                app_type=app_type,
                total_risk=total_risk,
                risk_level=risk_level,
                permissions=current_perms,
            )

        # ---- EXTERNAL APPS ----
        for app in external:
            app_id = app.app_id
            display_name = app.display_name or ""
            publisher_domain = ""
            app_type = "external"

            current_perms = sorted(set(app.permissions))
            total_risk, risk_level = self._calculate_app_risk(current_perms)

            existing = self._get_existing_app(app_id)
            is_new = existing is None
            prev_perms = existing.get("permissions", []) if existing else []

            sent_alert = self._maybe_send_spike_alerts(
                app_id=app_id,
                app_name=display_name,
                app_type=app_type,
                publisher_domain=publisher_domain,
                current_perms=current_perms,
                previous_perms=prev_perms,
                risk_level=risk_level,
                total_risk=total_risk,
            )

            if not (self.alert_once_per_app and sent_alert):
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
                        permissions=current_perms,
                        delta_info="New external application observed.",
                    )
                    sent_alert = True
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
                            permissions=current_perms,
                            delta_info=f"Risk tier increased: {prev_level} → {risk_level}",
                        )
                        sent_alert = True
                    else:
                        gained = sorted(set(current_perms) - set(prev_perms))
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
                                permissions=current_perms,
                                delta_info=f"New permissions granted: {', '.join(gained)}",
                            )
                            sent_alert = True

            self._upsert_app(
                app_id=app_id,
                display_name=display_name,
                publisher_domain=publisher_domain,
                app_type=app_type,
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
