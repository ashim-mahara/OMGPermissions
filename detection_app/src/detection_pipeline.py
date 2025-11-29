# detection_pipeline.py  — hardened with floors, caps, synergy, and improved spike logic
import sqlite3
import json
import logging
import math
import re
from datetime import datetime, timedelta
from typing import List, Tuple, Optional, Dict, Any

from .consent_collector import ConsentCollector
from .alert_notification import SlackNotifier  # expects a simple webhook-based notifier

LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# ---------- Regex rules for floors/caps ----------
_RX = {
    "rw_all": re.compile(r"\.readwrite\.all$", re.I),
    "r_all": re.compile(r"\.read\.all$", re.I),
    "send": re.compile(r"(mail|smtp|channelmessage|chatmessage)\.send$", re.I),
    "role": re.compile(r"^rolemanagement\.readwrite\.", re.I),
    "app": re.compile(r"^application\.readwrite\.all$", re.I),
    "sp": re.compile(r"^serviceprincipal\.readwrite\.all$", re.I),
    "approle": re.compile(r"^approleassignment\.readwrite\.all$", re.I),
    "secact": re.compile(r"^securityactions\.readwrite\.all$", re.I),
    "policy": re.compile(r"(conditionalaccess|policy).*readwrite", re.I),
    "appfolder": re.compile(r"files\.readwrite\.appfolder$", re.I),
    "createdbyapp": re.compile(r"createdbyapp$", re.I),
}


def _tier_from_score(x: float) -> str:
    if x >= 4.5:
        return "critical"
    if x >= 3.5:
        return "high"
    if x >= 2.0:
        return "medium"
    return "low"


def _tier_bump(tier: str) -> str:
    return {
        "low": "medium",
        "medium": "high",
        "high": "critical",
        "critical": "critical",
    }[tier]


class DetectionPipeline:
    def __init__(
        self,
        consent_collector: ConsentCollector,
        permission_db_path: str = "permission_analysis.db",
        state_db_path: str = "detection_state.db",
        slack_webhook_url: Optional[str] = None,
        alert_threshold_level: str = "medium",  # fire standard alerts at/above this tier
        top_perm_count: int = 3,  # how many perms to list in alerts
        # ---- spike rule options ----
        spike_score: int = 5,  # which risk score constitutes a "spike"
        spike_multi_count: int = 2,  # how many spikes before "multiple" alert
        spike_bypass_threshold: bool = True,  # allow spike alerts regardless of tier threshold
        alert_once_per_app: bool = True,  # collapse to one alert per app per run
        spike_cooldown_hours: int = 24,  # cool-down for spike alerts per app
        # ---- aggregation options ----
        gm_order: float = 3.0,  # generalized-mean order (3.0=Cubic). Supports 0 (geo), +/-inf, negatives.
    ):
        self.collector = consent_collector
        self.permission_db = permission_db_path
        self.state_db = state_db_path
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
        self.spike_cooldown_hours = spike_cooldown_hours

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
        # spike alert cool-down state
        cur.execute("""
            CREATE TABLE IF NOT EXISTS last_alerts (
                app_id TEXT PRIMARY KEY,
                last_spike_ts TEXT,
                last_spike_sig TEXT
            )
        """)
        # helpful indices
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_apps_last_seen ON applications(last_seen)"
        )
        cur.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_apps_appid ON applications(app_id)"
        )
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

    # ------------------- Floors / Caps helpers -------------------
    def _permission_floor(self, perm: str) -> int:
        s = (perm or "").lower().strip()
        if _RX["rw_all"].search(s):
            return 5
        if any(
            rx.search(s)
            for rx in (
                _RX["role"],
                _RX["app"],
                _RX["sp"],
                _RX["approle"],
                _RX["secact"],
                _RX["policy"],
            )
        ):
            return 5
        if _RX["r_all"].search(s):
            return 4
        if _RX["send"].search(s):
            return 4
        if s == "offline_access":
            return 1
        return 0

    def _permission_cap(self, perm: str) -> Optional[int]:
        s = (perm or "").lower().strip()
        if _RX["appfolder"].search(s) or _RX["createdbyapp"].search(s):
            return 2
        # offline_access by itself is handled via synergy/cap logic in aggregator
        return None

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

        eps = 1e-12
        vals = [max(float(v), eps) for v in values]

        if math.isinf(p):
            return max(vals) if p > 0 else min(vals)
        if p == 0.0:
            return math.exp(sum(math.log(v) for v in vals) / n)
        try:
            return (sum(v**p for v in vals) / n) ** (1.0 / p)
        except OverflowError:
            return max(vals) if p > 0 else min(vals)

    def _aggregate_app_risk(
        self, permissions: List[str]
    ) -> Tuple[float, str, Dict[str, Any]]:
        """
        Ordinal-safe, attacker-aware aggregation:
        - compute known scores
        - compute floor and cap impacts
        - base = max(median, max_score, generalized_mean(gm_order), floor_val)
        - synergy: offline_access + any >=3 -> bump tier by +1
        - respect caps (for constrained scopes)
        """
        perms = permissions or []
        rows = self._get_permission_risk_rows(perms)  # (name, score, reason)
        known_scores = [float(s) for (_, s, _) in rows if s is not None]
        max_score = max(known_scores) if known_scores else 0.0
        median_score = (
            float(sorted(known_scores)[len(known_scores) // 2]) if known_scores else 0.0
        )
        gm_score = (
            self._generalized_mean(known_scores, self.gm_order) if known_scores else 0.0
        )

        # Floors & caps
        floor_val = 0
        floors: Dict[str, int] = {}
        max_cap = None
        caps: Dict[str, int] = {}

        for p in perms:
            f = self._permission_floor(p)
            if f:
                floors[p] = f
                floor_val = max(floor_val, f)
            cap = self._permission_cap(p)
            if cap is not None:
                caps[p] = cap
                max_cap = cap if max_cap is None else min(max_cap, cap)

        # Base score before synergy
        base_score = max(median_score, max_score, gm_score, float(floor_val))
        base_tier = _tier_from_score(base_score)

        # Synergy: persistence bump
        synergy_bump = False
        if any(p.lower() == "offline_access" for p in perms) and any(
            s >= 3 for s in known_scores
        ):
            base_tier = _tier_bump(base_tier)
            synergy_bump = True

        # Respect caps ONLY if base came from constrained scopes without high floors
        # (i.e., don't cap if a floor forced High/Critical).
        if (
            max_cap is not None
            and LEVEL_ORDER[base_tier] > LEVEL_ORDER["medium"]
            and floor_val < 4
        ):
            # If all permissions are capped scopes and no high floor, reduce to cap-ish tier.
            base_tier = (
                "low" if max_cap <= 2 else base_tier
            )  # current caps only set to 2

        # Return numeric as the higher of base_score and tier midpoint (keeps dashboards consistent)
        tier_mid = {"low": 1.5, "medium": 2.5, "high": 4.0, "critical": 5.0}[base_tier]
        final_numeric = max(base_score, tier_mid)

        meta = {
            "median": median_score,
            "max_score": max_score,
            "gm_score": gm_score,
            "floors": floors,
            "caps": caps,
            "synergy_bump": synergy_bump,
        }
        return final_numeric, base_tier, meta

    def _calculate_app_risk(
        self, permissions: List[str]
    ) -> Tuple[float, str, Dict[str, Any]]:
        score, tier, meta = self._aggregate_app_risk(permissions)
        return score, tier, meta

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

    def _format_risk_modifiers(
        self, risk_meta: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        """
        Build a short human string describing floors/caps/synergy that influenced risk.
        Example: "floor=5: AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory; cap≤2: Files.ReadWrite.AppFolder; synergy: offline_access+persistence"
        """
        if not risk_meta:
            return None

        parts = []

        # Floors
        floors = risk_meta.get("floors") or {}
        if floors:
            # collect names by floor value for readability
            by_val = {}
            for name, val in floors.items():
                by_val.setdefault(val, []).append(name)
            floor_bits = []
            for val in sorted(by_val.keys(), reverse=True):
                names = sorted(by_val[val])
                shown = ", ".join(names[:5])
                if len(names) > 5:
                    shown += f" +{len(names) - 5} more"
                floor_bits.append(f"floor={val}: {shown}")
            parts.append("; ".join(floor_bits))

        # Caps
        caps = risk_meta.get("caps") or {}
        if caps:
            # most caps you use are 2 (appfolder/createdbyapp)
            by_cap = {}
            for name, val in caps.items():
                by_cap.setdefault(val, []).append(name)
            cap_bits = []
            for val in sorted(by_cap.keys()):
                names = sorted(by_cap[val])
                shown = ", ".join(names[:5])
                if len(names) > 5:
                    shown += f" +{len(names) - 5} more"
                cap_bits.append(f"cap≤{val}: {shown}")
            parts.append("; ".join(cap_bits))

        # Synergy
        if risk_meta.get("synergy_bump"):
            parts.append("synergy: offline_access + ≥3-risk permission")

        if not parts:
            return None
        return "; ".join(parts)

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
        risk_meta: Optional[Dict[str, Any]] = None,  # <— NEW
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

        modifiers_text = self._format_risk_modifiers(risk_meta)
        if modifiers_text:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Risk modifiers applied:*\n" + modifiers_text,
                    },
                }
            )
            # Also append to the plain text for parity
            delta_info = (
                delta_info
                + (" | " if delta_info else "")
                + f"Modifiers: {modifiers_text}"
            ).strip()

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

    # ------------------- Spike state helpers -------------------
    def _get_last_spike_state(self, app_id: str):
        conn = sqlite3.connect(self.state_db)
        cur = conn.cursor()
        cur.execute(
            "SELECT last_spike_ts, last_spike_sig FROM last_alerts WHERE app_id=?",
            (app_id,),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            return set(), None
        sig = row[1] or ""
        return set(sig.split(",")) if sig else set(), row[0]

    def _set_last_spike_state(self, app_id: str, spike_perms: List[str]):
        sig = ",".join(spike_perms)
        conn = sqlite3.connect(self.state_db)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO last_alerts (app_id, last_spike_ts, last_spike_sig)
            VALUES (?, ?, ?)
            ON CONFLICT(app_id) DO UPDATE SET
              last_spike_ts=excluded.last_spike_ts,
              last_spike_sig=excluded.last_spike_sig
        """,
            (app_id, datetime.utcnow().isoformat(), sig),
        )
        conn.commit()
        conn.close()

    def _cooldown_ok(self, last_ts: Optional[str]) -> bool:
        if not last_ts:
            return True
        try:
            dt = datetime.fromisoformat(last_ts.replace("Z", ""))
        except Exception:
            return True
        return (datetime.utcnow() - dt) >= timedelta(hours=self.spike_cooldown_hours)

    # ------------------- Spike logic (cache-backed) -------------------
    def _is_floor5(self, perm: str) -> bool:
        s = (perm or "").lower().strip()
        return any(
            rx.search(s)
            for rx in (
                _RX["rw_all"],
                _RX["role"],
                _RX["app"],
                _RX["sp"],
                _RX["approle"],
                _RX["secact"],
                _RX["policy"],
            )
        )

    def _risk_stats(self, permissions: List[str]) -> Dict[str, Any]:
        """
        Compute spike-related stats from the in-memory cache for a set of permissions.
        Returns:
          - scores: dict[name] -> score (includes floor 5 for unknown but floor-5-shaped perms)
          - max: max score
          - count_spike: count of perms >= self.spike_score
          - has_spike: bool
          - multi_spike: bool (count >= spike_multi_count)
          - spike_perms: sorted list of permission names at/above spike score
          - spike_ratio: spike_count / total_perms
        """
        rows = self._get_permission_risk_rows(permissions)  # (name, score, reasoning)
        scored = {name: score for (name, score, _) in rows if score is not None}

        # include floor-5 for unknown / missing DB scores that match floor-5 families
        for p in permissions or []:
            if p not in scored and self._is_floor5(p):
                scored[p] = 5

        total = len(permissions or [])
        spike_perms = sorted(
            [n for n, s in scored.items() if s is not None and s >= self.spike_score]
        )
        count_spike = len(spike_perms)
        max_score = max(scored.values()) if scored else 0
        ratio = (count_spike / total) if total else 0.0

        return {
            "scores": scored,
            "max": max_score,
            "count_spike": count_spike,
            "has_spike": count_spike >= 1,
            "multi_spike": count_spike >= self.spike_multi_count,
            "spike_perms": spike_perms,
            "spike_ratio": ratio,
            "total_perms": total,
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
        risk_meta: Optional[Dict[str, Any]] = None,  # <— NEW
    ) -> bool:
        """
        Evaluate and send spike alerts based on self.spike_score & self.spike_multi_count.
        - Uses >= threshold
        - Floor-aware for unknown perms
        - Includes set-delta (new/removed spike perms)
        - Enforces cool-down per app
        Returns True if an alert was sent.
        """
        cur = self._risk_stats(current_perms)
        prev = self._risk_stats(previous_perms or [])

        last_set, last_ts = self._get_last_spike_state(app_id)
        cur_set, prev_set = set(cur["spike_perms"]), set(prev["spike_perms"])
        new_spikes = sorted(cur_set - prev_set)
        removed_spikes = sorted(prev_set - cur_set)

        def _gate() -> bool:
            return (
                True
                if self.spike_bypass_threshold
                else self._level_meets_threshold(risk_level)
            )

        # Most severe: reaching multiple spikes or high ratio
        if (cur["multi_spike"] or cur["spike_ratio"] >= 0.25) and (
            len(cur_set) > len(prev_set)
        ):
            if _gate() and self._cooldown_ok(last_ts):
                event = "p5_multiple" if self.spike_score == 5 else "spike_multiple"
                self._send_slack_alert(
                    event=event,
                    app_id=app_id,
                    app_name=app_name,
                    app_type=app_type,
                    publisher_domain=publisher_domain,
                    risk_level=risk_level,
                    total_risk=total_risk,
                    permissions=current_perms,
                    delta_info=f"Spike perms +{len(new_spikes)}: {', '.join(new_spikes) or '—'}"
                    + (
                        f" | removed: {', '.join(removed_spikes)}"
                        if removed_spikes
                        else ""
                    )
                    + f" | spike_ratio={cur['spike_ratio']:.2f}",
                    risk_meta=risk_meta,
                )
                self._set_last_spike_state(app_id, cur["spike_perms"])
                return True

        # First time any spike appears
        if cur["has_spike"] and not prev["has_spike"]:
            if _gate() and self._cooldown_ok(last_ts):
                event = "p5_present" if self.spike_score == 5 else "spike_present"
                self._send_slack_alert(
                    event=event,
                    app_id=app_id,
                    app_name=app_name,
                    app_type=app_type,
                    publisher_domain=publisher_domain,
                    risk_level=risk_level,
                    total_risk=total_risk,
                    permissions=current_perms,
                    delta_info=f"New spike perms: {', '.join(new_spikes) or ', '.join(cur['spike_perms']) or '—'}",
                    risk_meta=risk_meta,
                )
                self._set_last_spike_state(app_id, cur["spike_perms"])
                return True

        return False

    # ------------------- Main run -------------------
    def run_detection(self):
        """
        Detection run with Slack alerts:
          - Spike alerts (p5_present / p5_multiple or generic) via reusable method
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

            total_risk, risk_level, risk_meta = self._calculate_app_risk(current_perms)

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
                risk_meta=risk_meta,
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
                        risk_meta=risk_meta,
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
                            risk_meta=risk_meta,
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
                                risk_meta=risk_meta,
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
            total_risk, risk_level, risk_meta = self._calculate_app_risk(current_perms)

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
                risk_meta=risk_meta,
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
                        risk_meta=risk_meta,
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
                            risk_meta=risk_meta,
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
                                risk_meta=risk_meta,
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
